//! FWMonitor GUI: ventana de escritorio (egui/eframe) sobre el mismo núcleo
//! que la TUI. El escaneo corre en un hilo aparte para no congelar la interfaz.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::thread;
use std::time::{Duration, Instant};

use clap::Parser;
use eframe::egui::{self, Color32, RichText};
use egui_extras::{Column, TableBuilder};

use fwmonitor::connect;
use fwmonitor::history::{ClientHistory, Presence, TrackedHost};
use fwmonitor::model::{self, Snapshot};
use fwmonitor::oui::OuiDb;

const GREEN: Color32 = Color32::from_rgb(110, 200, 120);
const YELLOW: Color32 = Color32::from_rgb(220, 200, 100);
const ORANGE: Color32 = Color32::from_rgb(225, 150, 80);
const RED: Color32 = Color32::from_rgb(230, 105, 105);
const MUTED: Color32 = Color32::from_gray(130);

/// Muestras de señal guardadas por BSSID (~20 min con refresco de 5 s).
const MAX_SAMPLES: usize = 240;
/// TTL de las series de BSSIDs que dejan de verse.
const SERIES_TTL: Duration = Duration::from_secs(1800);

/// Monitor de dispositivos en tu red WiFi, en una ventana de escritorio.
#[derive(Parser, Debug)]
#[command(
    name = "fwmonitor-gui",
    version,
    about = "Monitor de red WiFi con interfaz de escritorio"
)]
struct Args {
    /// Segundos entre escaneos automáticos
    #[arg(short, long, default_value_t = 5)]
    interval: u64,
    /// Cargar base OUI externa (oui.csv de IEEE o manuf de Wireshark)
    #[arg(long, value_name = "FILE")]
    oui_db: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 720.0])
            .with_min_inner_size([760.0, 480.0])
            .with_title("FWMonitor"),
        ..Default::default()
    };

    eframe::run_native(
        "FWMonitor",
        options,
        Box::new(move |cc| {
            cc.egui_ctx.set_visuals(egui::Visuals::dark());
            Ok(Box::new(App::new(cc, args.interval, args.oui_db)))
        }),
    )?;
    Ok(())
}

/// Un escaneo completo, ya con el estado de presencia resuelto.
struct Scan {
    snap: Snapshot,
    tracked: Vec<TrackedHost>,
}

/// Fila seleccionada en una de las tablas. La clave es estable entre
/// escaneos (BSSID / MAC), así que el detalle no se pierde al refrescar.
#[derive(Clone, PartialEq)]
enum Selection {
    Ap(String),
    Host(String),
}

/// Historia de señal de un BSSID: (instante de la muestra, dBm).
type Series = VecDeque<(Instant, i32)>;

/// Resultado de una operación lanzada en segundo plano (conectar, revelar).
enum OpResult {
    Connected(Result<String, String>),
    Revealed { ssid: String, result: Result<String, String> },
}

/// Diálogo de conexión a una red.
struct ConnectDialog {
    ssid: String,
    password: String,
    show_password: bool,
    /// La red no anuncia cifrado: no hace falta contraseña.
    open: bool,
    busy: bool,
    error: Option<String>,
}

/// Contraseña revelada de la red actual (o el error al intentarlo).
struct Revealed {
    ssid: String,
    result: Result<String, String>,
}

struct App {
    scan_rx: Receiver<Scan>,
    /// Pedir un escaneo inmediato al hilo de fondo.
    cmd_tx: Sender<()>,
    snap: Snapshot,
    tracked: Vec<TrackedHost>,
    interval: u64,
    last_update: Option<Instant>,
    scanning: bool,
    /// Fila seleccionada en las tablas (None = panel de detalle vacío).
    selected: Option<Selection>,
    /// Señal por BSSID, muestreada en cada escaneo.
    series: HashMap<String, Series>,
    ctx: egui::Context,
    dialog: Option<ConnectDialog>,
    revealed: Option<Revealed>,
    notice: Option<String>,
    ops_tx: Sender<OpResult>,
    ops_rx: Receiver<OpResult>,
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>, interval: u64, oui_db: Option<PathBuf>) -> Self {
        let interval = interval.max(1);
        let (scan_tx, scan_rx) = channel();
        let (cmd_tx, cmd_rx) = channel();
        let (ops_tx, ops_rx) = channel();
        let ctx = cc.egui_ctx.clone();

        thread::spawn(move || {
            scanner_loop(
                oui_db,
                Duration::from_secs(interval),
                ctx,
                scan_tx,
                cmd_rx,
            )
        });

        Self {
            scan_rx,
            cmd_tx,
            snap: Snapshot::default(),
            tracked: Vec::new(),
            interval,
            last_update: None,
            scanning: true,
            selected: None,
            series: HashMap::new(),
            ctx: cc.egui_ctx.clone(),
            dialog: None,
            revealed: None,
            notice: None,
            ops_tx,
            ops_rx,
        }
    }

    /// Lanza la conexión a una red en un hilo aparte (D-Bus/WLAN pueden tardar).
    fn start_connect(&mut self, ssid: String, password: Option<String>) {
        let (ctx, tx) = (self.ctx.clone(), self.ops_tx.clone());
        thread::spawn(move || {
            let res = connect::connect(&ssid, password.as_deref()).map_err(|e| e.to_string());
            let _ = tx.send(OpResult::Connected(res.map(|_| ssid)));
            ctx.request_repaint();
        });
    }

    /// Diálogo de conexión y ventana con la contraseña revelada.
    fn windows(&mut self, ctx: &egui::Context) {
        if let Some(mut d) = self.dialog.take() {
            let (mut submit, mut close) = (false, false);

            egui::Window::new("Conectar a red")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                .show(ctx, |ui| {
                    ui.label(RichText::new("Red").color(MUTED));
                    ui.add(
                        egui::TextEdit::singleline(&mut d.ssid).desired_width(240.0),
                    );

                    if d.open {
                        ui.add_space(6.0);
                        ui.label(RichText::new("Red abierta: sin contraseña").color(MUTED));
                    } else {
                        ui.add_space(6.0);
                        ui.label(RichText::new("Contraseña").color(MUTED));
                        ui.add(
                            egui::TextEdit::singleline(&mut d.password)
                                .password(!d.show_password)
                                .desired_width(240.0),
                        );
                        ui.checkbox(&mut d.show_password, "Mostrar contraseña");
                    }

                    if let Some(err) = &d.error {
                        ui.add_space(4.0);
                        ui.label(RichText::new(err).color(RED));
                    }

                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        let can = !d.busy
                            && !d.ssid.trim().is_empty()
                            && (d.open || !d.password.is_empty());
                        if ui
                            .add_enabled(can, egui::Button::new("Conectar"))
                            .clicked()
                        {
                            submit = true;
                        }
                        if d.busy {
                            ui.spinner();
                        }
                        if ui.button("Cancelar").clicked() {
                            close = true;
                        }
                    });
                });

            if submit {
                let ssid = d.ssid.trim().to_string();
                let password = if d.open {
                    None
                } else {
                    Some(d.password.clone())
                };
                d.busy = true;
                d.error = None;
                self.start_connect(ssid, password);
            }
            if close {
                self.dialog = None;
            } else {
                self.dialog = Some(d);
            }
        }

        if let Some(rev) = self.revealed.take() {
            let mut close = false;

            egui::Window::new(format!("Contraseña · {}", rev.ssid))
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| match &rev.result {
                    Ok(psk) => {
                        let mut shown = psk.clone();
                        ui.add(
                            egui::TextEdit::singleline(&mut shown)
                                .font(egui::TextStyle::Monospace)
                                .desired_width(260.0),
                        );
                        ui.horizontal(|ui| {
                            if ui.button("Copiar").clicked() {
                                ui.ctx().copy_text(psk.clone());
                            }
                            if ui.button("Cerrar").clicked() {
                                close = true;
                            }
                        });
                    }
                    Err(e) => {
                        ui.label(RichText::new(e).color(RED));
                        ui.label(
                            RichText::new("Requiere permisos para leer secretos de NetworkManager.")
                                .color(MUTED),
                        );
                        if ui.button("Cerrar").clicked() {
                            close = true;
                        }
                    }
                });

            if !close {
                self.revealed = Some(rev);
            }
        }
    }

    /// Lanza la lectura de la contraseña guardada de la red activa.
    fn start_reveal(&mut self, ssid: String) {
        let (ctx, tx) = (self.ctx.clone(), self.ops_tx.clone());
        thread::spawn(move || {
            let res = connect::reveal_password(&ssid).map_err(|e| e.to_string());
            let _ = tx.send(OpResult::Revealed { ssid, result: res });
            ctx.request_repaint();
        });
    }

    fn header(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.heading(RichText::new("FWMonitor").strong());
            ui.separator();
            let iface = if self.snap.iface.is_empty() {
                "—"
            } else {
                self.snap.iface.as_str()
            };
            ui.label(RichText::new(iface).monospace());
            if let Some(net) = &self.snap.net {
                ui.separator();
                ui.label(RichText::new(net).monospace().color(MUTED));
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .add_enabled(!self.scanning, egui::Button::new("Actualizar"))
                    .clicked()
                {
                    let _ = self.cmd_tx.send(());
                    self.scanning = true;
                }
                ui.label(RichText::new(format!("cada {} s", self.interval)).color(MUTED));
                if self.scanning {
                    ui.spinner();
                    ui.label(RichText::new("Escaneando…").color(MUTED));
                } else if let Some(t) = self.last_update {
                    ui.label(RichText::new(format!("hace {} s", t.elapsed().as_secs())).color(MUTED));
                }
            });
        });

        let mut reveal_request: Option<String> = None;
        ui.horizontal(|ui| {
            match &self.snap.link {
                Some(link) => {
                    ui.label(RichText::new("Conectado:").color(MUTED));
                    ui.label(RichText::new(&link.ssid).strong());
                    ui.label(RichText::new(&link.bssid).monospace().color(MUTED));
                    signal_meter(ui, link.rssi);
                    ui.label(
                        RichText::new(rssi_label(link.rssi))
                            .color(rssi_color(link.rssi))
                            .monospace(),
                    );
                    if link.channel > 0 {
                        ui.label(RichText::new(format!("ch {}", link.channel)).color(MUTED));
                    }
                    if let (Some(tx), Some(rx)) = (link.tx_mbps, link.rx_mbps) {
                        ui.label(
                            RichText::new(format!("{tx:.0}/{rx:.0} Mbps"))
                                .monospace()
                                .color(MUTED),
                        );
                    }
                    if let Some(secs) = link.connected_secs {
                        ui.label(RichText::new(format!("· {}", uptime(secs))).color(MUTED));
                    }
                    if ui.small_button("Ver contraseña").clicked() {
                        reveal_request = Some(link.ssid.clone());
                    }
                }
                None => {
                    ui.label(RichText::new("Sin conexión WiFi").color(MUTED));
                }
            }
        });

        if let Some(ssid) = reveal_request {
            self.start_reveal(ssid);
        }

        if let Some(notice) = &self.notice {
            ui.label(RichText::new(notice).color(GREEN));
        }

        for e in &self.snap.errors {
            ui.label(RichText::new(format!("⚠ {e}")).color(RED));
        }
        ui.add_space(6.0);
    }

    fn wifi_panel(&mut self, ui: &mut egui::Ui) {
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(format!("WiFi — {} BSSIDs", self.snap.aps.len())).strong(),
            );
            ui.label(RichText::new("ordenados por señal").color(MUTED));
        });
        ui.add_space(2.0);

        if self.snap.aps.is_empty() {
            ui.centered_and_justified(|ui| {
                ui.label(RichText::new("Sin redes visibles todavía…").color(MUTED));
            });
            return;
        }

        let aps = &self.snap.aps;
        let selected = &self.selected;
        let series = &self.series;
        let mut clicked: Option<Selection> = None;

        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .sense(egui::Sense::click())
            .column(Column::initial(180.0).at_least(80.0).clip(true))
            .column(Column::initial(145.0).at_least(110.0))
            .column(Column::initial(125.0).at_least(90.0))
            .column(Column::initial(55.0).at_least(45.0))
            .column(Column::initial(100.0).at_least(65.0))
            .column(Column::initial(110.0).at_least(70.0))
            .column(Column::remainder().at_least(120.0).clip(true))
            .header(22.0, |mut header| {
                for title in ["SSID", "BSSID", "Señal", "Canal", "Cifrado", "Histórico", "Fabricante"]
                {
                    header.col(|ui| {
                        ui.strong(title);
                    });
                }
            })
            .body(|body| {
                body.rows(22.0, aps.len(), |mut row| {
                    let ap = &aps[row.index()];
                    let key = Selection::Ap(ap.bssid.clone());
                    row.set_selected(selected.as_ref() == Some(&key));

                    row.col(|ui| {
                        if ap.ssid.is_empty() {
                            ui.label(RichText::new("(oculto)").color(MUTED));
                        } else {
                            ui.label(RichText::new(&ap.ssid));
                        }
                    });
                    row.col(|ui| {
                        ui.label(RichText::new(&ap.bssid).monospace());
                    });
                    row.col(|ui| {
                        ui.horizontal(|ui| {
                            signal_meter(ui, ap.rssi);
                            ui.label(
                                RichText::new(rssi_label(ap.rssi))
                                    .color(rssi_color(ap.rssi))
                                    .monospace(),
                            );
                        });
                    });
                    row.col(|ui| {
                        ui.label(ap.channel.to_string());
                    });
                    row.col(|ui| {
                        let text = if ap.encryption.is_empty() {
                            "—"
                        } else {
                            ap.encryption.as_str()
                        };
                        let rt = RichText::new(text);
                        if ap.is_open() {
                            ui.label(rt.color(RED).strong());
                        } else {
                            ui.label(rt);
                        }
                    });
                    row.col(|ui| match series.get(&ap.bssid) {
                        Some(samples) if samples.len() >= 2 => sparkline(ui, samples),
                        _ => {
                            ui.label(RichText::new("—").color(MUTED));
                        }
                    });
                    row.col(|ui| {
                        ui.label(&ap.vendor);
                    });

                    if row.response().clicked() {
                        clicked = Some(key);
                    }
                });
            });

        if let Some(sel) = clicked {
            self.selected = Some(sel);
        }
    }

    fn lan_panel(&mut self, ui: &mut egui::Ui) {
        let activos = self
            .tracked
            .iter()
            .filter(|t| t.state != Presence::Gone)
            .count();
        let ausentes = self.tracked.len() - activos;

        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(format!("LAN — {activos} activos, {ausentes} ausentes")).strong(),
            );
            if let Some(net) = &self.snap.net {
                ui.label(RichText::new(net).monospace().color(MUTED));
            }
        });
        ui.add_space(2.0);

        if self.tracked.is_empty() {
            ui.centered_and_justified(|ui| {
                ui.label(RichText::new("Sin hosts conocidos todavía…").color(MUTED));
            });
            return;
        }

        let tracked = &self.tracked;
        let selected = &self.selected;
        let mut clicked: Option<Selection> = None;

        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .sense(egui::Sense::click())
            .column(Column::initial(150.0).at_least(110.0))
            .column(Column::initial(160.0).at_least(130.0))
            .column(Column::initial(70.0).at_least(55.0))
            .column(Column::remainder().at_least(140.0).clip(true))
            .column(Column::initial(80.0).at_least(65.0))
            .header(22.0, |mut header| {
                for title in ["IP", "MAC", "Tipo", "Fabricante", "Estado"] {
                    header.col(|ui| {
                        ui.strong(title);
                    });
                }
            })
            .body(|body| {
                body.rows(22.0, tracked.len(), |mut row| {
                    let t = &tracked[row.index()];
                    let gone = t.state == Presence::Gone;
                    let key = Selection::Host(host_key(&t.host));
                    row.set_selected(selected.as_ref() == Some(&key));
                    let text = |s: &str| {
                        let rt = RichText::new(s);
                        if gone { rt.color(MUTED) } else { rt }
                    };

                    row.col(|ui| {
                        ui.label(text(&t.host.ip).monospace());
                    });
                    row.col(|ui| {
                        ui.label(text(&t.host.mac).monospace());
                    });
                    row.col(|ui| {
                        ui.label(text(&t.host.kind));
                    });
                    row.col(|ui| {
                        ui.label(text(&t.host.vendor));
                    });
                    row.col(|ui| {
                        let (txt, color) = match t.state {
                            Presence::New => ("nuevo", GREEN),
                            Presence::Gone => ("ausente", MUTED),
                            Presence::Normal => ("", MUTED),
                        };
                        if !txt.is_empty() {
                            ui.label(RichText::new(txt).color(color).strong());
                        }
                    });

                    if row.response().clicked() {
                        clicked = Some(key);
                    }
                });
            });

        if let Some(sel) = clicked {
            self.selected = Some(sel);
        }
    }

    /// Guarda la señal de cada BSSID visible en este escaneo.
    fn record(&mut self, snap: &Snapshot, now: Instant) {
        for ap in &snap.aps {
            if ap.rssi >= 0 {
                continue; // señal desconocida
            }
            let samples = self.series.entry(ap.bssid.clone()).or_default();
            samples.push_back((now, ap.rssi));
            while samples.len() > MAX_SAMPLES {
                samples.pop_front();
            }
        }

        // Solo poda cuando el mapa crece de más: barato y suficiente.
        if self.series.len() > 128 {
            self.series
                .retain(|_, s| s.back().is_some_and(|(t, _)| now.duration_since(*t) < SERIES_TTL));
        }
    }

    fn detail_panel(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.heading("Detalle");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if self.selected.is_some() && ui.small_button("Cerrar").clicked() {
                    self.selected = None;
                }
            });
        });
        ui.separator();

        let Some(sel) = self.selected.clone() else {
            ui.add_space(6.0);
            ui.label(
                RichText::new("Haz clic en una fila para ver su detalle y su histórico de señal.")
                    .color(MUTED),
            );
            return;
        };

        match sel {
            Selection::Ap(bssid) => self.ap_detail(ui, &bssid),
            Selection::Host(key) => self.host_detail(ui, &key),
        }
    }

    fn ap_detail(&mut self, ui: &mut egui::Ui, bssid: &str) {
        let ap = self.snap.aps.iter().find(|ap| ap.bssid == bssid);

        egui::Grid::new("detalle_ap")
            .num_columns(2)
            .spacing([14.0, 7.0])
            .show(ui, |ui| {
                ui.label(RichText::new("BSSID").color(MUTED));
                ui.label(RichText::new(bssid).monospace());
                ui.end_row();

                let Some(ap) = ap else {
                    ui.label(RichText::new("Estado").color(MUTED));
                    ui.label(RichText::new("ya no visible").color(ORANGE));
                    ui.end_row();
                    return;
                };

                ui.label(RichText::new("SSID").color(MUTED));
                if ap.ssid.is_empty() {
                    ui.label(RichText::new("(oculto)").color(MUTED));
                } else {
                    ui.label(RichText::new(&ap.ssid).strong());
                }
                ui.end_row();

                ui.label(RichText::new("Señal").color(MUTED));
                ui.horizontal(|ui| {
                    signal_meter(ui, ap.rssi);
                    ui.label(
                        RichText::new(rssi_label(ap.rssi))
                            .color(rssi_color(ap.rssi))
                            .monospace(),
                    );
                });
                ui.end_row();

                ui.label(RichText::new("Canal").color(MUTED));
                ui.label(ap.channel.to_string());
                ui.end_row();

                ui.label(RichText::new("Cifrado").color(MUTED));
                if ap.is_open() {
                    ui.label(RichText::new("abierta — sin cifrado").color(RED).strong());
                } else {
                    ui.label(&ap.encryption);
                }
                ui.end_row();

                ui.label(RichText::new("PHY").color(MUTED));
                ui.label(&ap.phy);
                ui.end_row();

                ui.label(RichText::new("Fabricante").color(MUTED));
                ui.label(if ap.vendor.is_empty() {
                    "—"
                } else {
                    ap.vendor.as_str()
                });
                ui.end_row();
            });

        if let Some(ap) = ap {
            ui.add_space(10.0);
            if ui.button("Conectar a esta red…").clicked() {
                self.dialog = Some(ConnectDialog {
                    ssid: ap.ssid.clone(),
                    password: String::new(),
                    show_password: false,
                    open: ap.is_open(),
                    busy: false,
                    error: None,
                });
            }
        }

        ui.add_space(12.0);
        ui.label(RichText::new("Histórico de señal").strong());
        match self.series.get(bssid) {
            Some(samples) => signal_chart(ui, samples),
            None => {
                ui.label(RichText::new("Aún sin muestras.").color(MUTED));
            }
        }
    }

    fn host_detail(&self, ui: &mut egui::Ui, key: &str) {
        let Some(t) = self.tracked.iter().find(|t| host_key(&t.host) == key) else {
            ui.label(RichText::new("Este host ya no está en el historial.").color(ORANGE));
            return;
        };

        let (estado, color) = match t.state {
            Presence::New => ("nuevo", GREEN),
            Presence::Normal => ("presente", GREEN),
            Presence::Gone => ("ausente", MUTED),
        };

        egui::Grid::new("detalle_host")
            .num_columns(2)
            .spacing([14.0, 7.0])
            .show(ui, |ui| {
                ui.label(RichText::new("IP").color(MUTED));
                ui.label(RichText::new(&t.host.ip).monospace());
                ui.end_row();

                ui.label(RichText::new("MAC").color(MUTED));
                ui.label(RichText::new(or_dash(&t.host.mac)).monospace());
                ui.end_row();

                ui.label(RichText::new("Tipo").color(MUTED));
                ui.label(or_dash(&t.host.kind));
                ui.end_row();

                ui.label(RichText::new("Fabricante").color(MUTED));
                ui.label(or_dash(&t.host.vendor));
                ui.end_row();

                ui.label(RichText::new("Estado").color(MUTED));
                ui.label(RichText::new(estado).color(color).strong());
                ui.end_row();
            });
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        while let Ok(scan) = self.scan_rx.try_recv() {
            let now = Instant::now();
            self.record(&scan.snap, now);
            self.snap = scan.snap;
            self.tracked = scan.tracked;
            self.last_update = Some(now);
            self.scanning = false;
        }

        while let Ok(op) = self.ops_rx.try_recv() {
            match op {
                OpResult::Connected(Ok(ssid)) => {
                    self.dialog = None;
                    self.notice = Some(format!("Conectado a {ssid}"));
                    self.scanning = true;
                    let _ = self.cmd_tx.send(()); // refrescar el snapshot
                }
                OpResult::Connected(Err(e)) => {
                    if let Some(d) = &mut self.dialog {
                        d.busy = false;
                        d.error = Some(e);
                    }
                }
                OpResult::Revealed { ssid, result } => {
                    self.revealed = Some(Revealed { ssid, result });
                }
            }
        }

        if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
            self.selected = None;
        }

        // Mantiene vivo el "hace N s" aunque no lleguen escaneos.
        if !self.scanning {
            ui.ctx().request_repaint_after(Duration::from_secs(1));
        }

        egui::Panel::top("cabecera").show(ui, |ui| self.header(ui));

        egui::Panel::right("detalle")
            .resizable(true)
            .default_size(320.0)
            .min_size(220.0)
            .show(ui, |ui| self.detail_panel(ui));

        egui::Panel::top("wifi")
            .resizable(true)
            .default_size(330.0)
            .show(ui, |ui| self.wifi_panel(ui));

        egui::CentralPanel::default().show(ui, |ui| self.lan_panel(ui));

        self.windows(ui.ctx());
    }
}

/// Bucle del hilo de escaneo: captura, envía el resultado y espera al
/// siguiente tick o a una petición de refresco manual.
fn scanner_loop(
    oui_db: Option<PathBuf>,
    interval: Duration,
    ctx: egui::Context,
    tx: Sender<Scan>,
    cmd_rx: Receiver<()>,
) {
    let oui = match oui_db {
        Some(path) => OuiDb::load_external(&path).unwrap_or_else(|e| {
            eprintln!("⚠ OUI: {e}");
            OuiDb::builtin()
        }),
        None => OuiDb::builtin(),
    };
    let mut history = ClientHistory::default();

    loop {
        let snap = model::snapshot(&oui);
        let tracked = history.update(&snap.hosts);

        if tx.send(Scan { snap, tracked }).is_err() {
            return; // la ventana ya se cerró
        }
        ctx.request_repaint();

        match cmd_rx.recv_timeout(interval) {
            Ok(()) | Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

fn rssi_label(rssi: i32) -> String {
    if rssi >= 0 {
        "—".to_string()
    } else {
        format!("{rssi} dBm")
    }
}

fn rssi_color(rssi: i32) -> Color32 {
    match rssi {
        r if r >= 0 => MUTED,
        r if r >= -50 => GREEN,
        r if r >= -65 => YELLOW,
        r if r >= -75 => ORANGE,
        _ => RED,
    }
}

/// Cinco barras cuyo relleno depende de la intensidad de la señal.
fn signal_meter(ui: &mut egui::Ui, rssi: i32) {
    let (filled, color) = match rssi {
        r if r >= 0 => (0, MUTED),
        r if r >= -50 => (5, GREEN),
        r if r >= -65 => (4, YELLOW),
        r if r >= -75 => (3, ORANGE),
        r if r >= -85 => (2, ORANGE),
        _ => (1, RED),
    };

    for i in 0..5 {
        let (rect, _) = ui.allocate_exact_size(egui::vec2(4.0, 11.0), egui::Sense::hover());
        let c = if i < filled {
            color
        } else {
            Color32::from_gray(60)
        };
        ui.painter().rect_filled(rect, 1, c);
    }
}

/// Mini-gráfico del histórico de señal, para una fila de la tabla.
fn sparkline(ui: &mut egui::Ui, samples: &Series) {
    let Some(&(_, latest)) = samples.back() else {
        return;
    };

    let (rect, _) = ui.allocate_exact_size(
        egui::vec2(ui.available_width().max(16.0), 12.0),
        egui::Sense::hover(),
    );
    let painter = ui.painter();
    painter.rect_filled(rect, 2, Color32::from_gray(28));

    let (t0, _) = *samples.front().expect("sparkline necesita 2 muestras");
    let (t1, _) = *samples.back().expect("sparkline necesita 2 muestras");
    let span = t1.duration_since(t0).as_secs_f32().max(0.001);
    let plot = rect.shrink(2.0);

    let y_of = |rssi: i32| {
        let t = (-20.0_f32 - (rssi as f32).clamp(-100.0, -20.0)) / 80.0;
        plot.top() + t * plot.height()
    };
    let points: Vec<egui::Pos2> = samples
        .iter()
        .map(|(at, rssi)| {
            let x = plot.left() + (at.duration_since(t0).as_secs_f32() / span) * plot.width();
            egui::pos2(x, y_of(*rssi))
        })
        .collect();

    painter.add(egui::Shape::line(
        points,
        egui::Stroke::new(1.0, rssi_color(latest)),
    ));
}

/// Segundos conectado -> "2h 14m" / "3m 20s" / "45s".
fn uptime(secs: u32) -> String {
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    if h > 0 {
        format!("{h}h {m:02}m")
    } else if m > 0 {
        format!("{m}m {s:02}s")
    } else {
        format!("{s}s")
    }
}

/// "—" para cadenas vacías.
fn or_dash(s: &str) -> &str {
    if s.is_empty() {
        "—"
    } else {
        s
    }
}

/// Clave estable de un host: la MAC si la hay, si no la IP.
fn host_key(host: &fwmonitor::model::LanHost) -> String {
    if host.mac.is_empty() {
        format!("ip:{}", host.ip)
    } else {
        format!("mac:{}", host.mac.to_lowercase())
    }
}

/// Dibuja el histórico de señal (dBm frente al tiempo) de un BSSID.
fn signal_chart(ui: &mut egui::Ui, samples: &Series) {
    let Some(&(_, latest)) = samples.back() else {
        return;
    };

    let n = samples.len();
    let min = samples.iter().map(|(_, r)| *r).min().unwrap_or(0);
    let max = samples.iter().map(|(_, r)| *r).max().unwrap_or(0);
    let avg = samples.iter().map(|(_, r)| *r).sum::<i32>() as f32 / n as f32;
    ui.label(
        RichText::new(format!("{n} muestras · mín {min} · media {avg:.0} · máx {max} dBm"))
            .color(MUTED)
            .small(),
    );

    if n < 2 {
        ui.label(RichText::new("Recolectando muestras…").color(MUTED).small());
        return;
    }

    let (rect, _) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), 120.0),
        egui::Sense::hover(),
    );
    let painter = ui.painter();
    painter.rect_filled(rect, 4, Color32::from_gray(22));

    // Margen izquierdo para las etiquetas de dBm.
    let inner = rect.shrink2(egui::vec2(30.0, 10.0));
    let (top_dbm, bottom_dbm) = (-20.0_f32, -100.0_f32);
    let y_of = |dbm: f32| {
        let t = (top_dbm - dbm.clamp(bottom_dbm, top_dbm)) / (top_dbm - bottom_dbm);
        inner.top() + t * inner.height()
    };

    for dbm in [-40.0_f32, -60.0, -80.0, -100.0] {
        let y = y_of(dbm);
        painter.line_segment(
            [egui::pos2(inner.left(), y), egui::pos2(inner.right(), y)],
            egui::Stroke::new(1.0, Color32::from_gray(48)),
        );
        painter.text(
            egui::pos2(inner.left() - 5.0, y),
            egui::Align2::RIGHT_CENTER,
            format!("{dbm:.0}"),
            egui::FontId::monospace(9.0),
            MUTED,
        );
    }

    let (t0, _) = *samples.front().expect("n >= 2");
    let (t1, _) = *samples.back().expect("n >= 2");
    let span = t1.duration_since(t0).as_secs_f32().max(0.001);

    let points: Vec<egui::Pos2> = samples
        .iter()
        .map(|(at, rssi)| {
            let x = inner.left() + (at.duration_since(t0).as_secs_f32() / span) * inner.width();
            egui::pos2(x, y_of(*rssi as f32))
        })
        .collect();

    let last = *points.last().expect("n >= 2");
    let color = rssi_color(latest);
    painter.add(egui::Shape::line(
        points,
        egui::Stroke::new(1.6, color),
    ));
    painter.circle_filled(last, 2.5, color);

    painter.text(
        egui::pos2(rect.right() - 4.0, rect.top() + 2.0),
        egui::Align2::RIGHT_TOP,
        format!("{:.0} s", span),
        egui::FontId::monospace(9.0),
        MUTED,
    );
}
