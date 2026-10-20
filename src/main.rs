//! FWMonitor: monitor de red WiFi en la terminal.
//! Windows: escaneo BSSID (Native WiFi API) + descubrimiento ARP.
//! Linux: nl80211 + AF_PACKET, con modo monitor 802.11 opcional (--monitor).

mod csv;
mod history;
mod lan;
#[cfg(target_os = "linux")]
mod monitor;
mod model;
mod oui;
mod ui;
mod wifi;

use std::io::stdout;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use ratatui::{
    crossterm::event::{self, Event, KeyCode},
    crossterm::{execute, terminal},
    Terminal,
};

use crate::oui::OuiDb;

/// Monitor de dispositivos en tu red WiFi, vivo en la terminal.
#[derive(Parser, Debug)]
#[command(name = "fwmonitor", version, about)]
struct Args {
    /// Segundos entre refrescos automáticos
    #[arg(short, long, default_value_t = 5)]
    interval: u64,
    /// Una sola captura (sin TUI) e imprime en texto plano
    #[arg(long, default_value_t = false)]
    once: bool,
    /// Exportar a CSV (sobreescribe el archivo)
    #[arg(long, value_name = "FILE")]
    csv: Option<PathBuf>,
    /// Añadir al CSV en vez de sobreescribir (acumula histórico)
    #[arg(long, value_name = "FILE")]
    csv_append: Option<PathBuf>,
    /// Cargar base OUI externa (oui.csv de IEEE o manuf de Wireshark)
    #[arg(long, value_name = "FILE")]
    oui_db: Option<PathBuf>,
    /// Modo monitor 802.11 (solo Linux): captura pasiva con channel hopping.
    /// Requiere root: toma posesión de la interfaz (no puede estar conectada).
    #[arg(long, default_value_t = false)]
    monitor: bool,
    /// Interfaz para el modo monitor
    #[arg(long, value_name = "IFACE", default_value = "wlan0")]
    monitor_iface: String,
    /// Salir tras N segundos en modo monitor (sin límite si es 0)
    #[arg(long, value_name = "SECS", default_value_t = 0)]
    monitor_secs: u64,
    /// Canales a saltar en modo monitor. Acepta lista y rangos: "1-13", "1,6,11,36-48".
    /// Por defecto 1-13 (todo 2.4 GHz): tu red está donde está, y en 5 GHz sólo se
    /// capturan los canales sin DFS mientras duren los beacons.
    #[arg(long, value_name = "SPEC", default_value = "1-13")]
    monitor_channels: String,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let oui = match &args.oui_db {
        Some(path) => OuiDb::load_external(path)?,
        None => OuiDb::builtin(),
    };

    // --- Modo monitor (solo Linux): captura pasiva 802.11 ---
    if args.monitor {
        monitor_mode(&args, &oui)?;
        return Ok(());
    }

    if args.once || args.csv.is_some() || args.csv_append.is_some() {
        let snap = model::snapshot(&oui);
        if args.once {
            print_once(&snap);
        }
        if let Some(path) = &args.csv {
            csv::export(path, &snap, false)?;
            println!("CSV escrito: {}", path.display());
        }
        if let Some(path) = &args.csv_append {
            csv::export(path, &snap, true)?;
            println!("CSV añadido: {}", path.display());
        }
        return Ok(());
    }

    run_tui(&oui, args.interval)
}

/// Modo monitor: canal hopping + captura de beacons, con impresión periódica
/// (o TUI con Ctrl+C limpio). La interfaz SIEMPRE se restaura al final.
#[cfg(target_os = "linux")]
/// Parsea la especificación de canales: "1,6,11", "1-13", "1-13,36,149".
/// Deduplica y ordena. Ignora tokens no válidos.
#[cfg(target_os = "linux")]
fn parse_channel_spec(spec: &str) -> Vec<u8> {
    let mut channels: Vec<u8> = Vec::new();
    for tok in spec.split(',') {
        let tok = tok.trim();
        if tok.is_empty() {
            continue;
        }
        if let Some((lo, hi)) = tok.split_once('-') {
            if let (Ok(lo), Ok(hi)) = (lo.trim().parse::<u8>(), hi.trim().parse::<u8>()) {
                for ch in lo..=hi {
                    channels.push(ch);
                }
            }
        } else if let Ok(ch) = tok.parse::<u8>() {
            channels.push(ch);
        }
    }
    channels.sort_unstable();
    channels.dedup();
    channels
}

#[cfg(target_os = "linux")]
fn monitor_mode(args: &Args, oui: &OuiDb) -> anyhow::Result<()> {
    use std::time::Instant;

    let channels: Vec<u8> = {
        let mut c = parse_channel_spec(&args.monitor_channels);
        if c.is_empty() {
            c = (1..=13).collect();
        }
        c
    };

    println!(
        "Monitor en {} (canales {:?}) — Ctrl+C para salir y restaurar la interfaz",
        args.monitor_iface, channels
    );
    println!("⚠ La interfaz se desconectará mientras dure la captura (iwlwifi no permite managed+monitor).\n");

    monitor::install_stop_handlers();

    let mut last_print = Instant::now();
    let tick = |live: &monitor::LiveAps, channel: u8| {
        // Impresión de estado en cada salto de canal (≈ cada 400 ms x canales)
        if last_print.elapsed() < Duration::from_secs(5) {
            return;
        }
        last_print = Instant::now();
        println!("--- canal {channel} | {} APs vistos ---", live.len());
        for ap in live.sorted().iter().take(10) {
            println!(
                "  {:<18} {:<24} ch {:<3} {:>4} dBm  {} beacons / {} data",
                ap.bssid,
                if ap.ssid.is_empty() { "(oculto)" } else { ap.ssid.as_str() },
                ap.channel,
                ap.rssi,
                ap.beacons,
                ap.data_frames
            );
        }
    };

    // Temporizador de --monitor-secs: activar el flag de parada al expirar
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_timer = std::sync::Arc::clone(&stop);
    let monitor_secs = args.monitor_secs;
    if monitor_secs > 0 {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(monitor_secs));
            stop_timer.store(true, std::sync::atomic::Ordering::SeqCst);
        });
    }

    let (_iface, live) = monitor::run_monitor(&args.monitor_iface, &channels, &stop, tick)?;

    println!("\n=== Resultado monitor ({} APs) ===", live.len());
    let snap_aps = monitor::to_snapshot_aps(&live, oui);
    println!(
        "{:<24} {:<18} {:>6} {:>4} {:>8}  {}",
        "SSID", "BSSID", "RSSI", "CH", "Beacons", "Visto (UTC)"
    );
    for ap in live.sorted() {
        println!(
            "{:<24} {:<18} {:>6} {:>4} {:>8}  {} {}",
            truncate(&ap.ssid, 24),
            ap.bssid,
            format!("{} dBm", ap.rssi),
            ap.channel,
            ap.beacons,
            hhmmss_utc(ap.first_seen),
            oui.resolve(&ap.bssid)
        );
    }

    // CSV opcional en modo monitor (mismas convenciones que el resto)
    if args.csv.is_some() || args.csv_append.is_some() {
        let snap = model::Snapshot {
            iface: args.monitor_iface.clone(),
            aps: snap_aps,
            hosts: Vec::new(),
            net: None,
            errors: Vec::new(),
        };
        if let Some(path) = &args.csv {
            csv::export(path, &snap, false)?;
            println!("CSV escrito: {}", path.display());
        }
        if let Some(path) = &args.csv_append {
            csv::export(path, &snap, true)?;
            println!("CSV añadido: {}", path.display());
        }
    }
    Ok(())
}

/// Stub no-Linux: el modo monitor requiere nl80211/AF_PACKET.
#[cfg(not(target_os = "linux"))]
fn monitor_mode(_args: &Args, _oui: &OuiDb) -> anyhow::Result<()> {
    anyhow::bail!("--monitor sólo está disponible en Linux")
}

fn print_once(snap: &model::Snapshot) {
    println!("Interfaz: {}", snap.iface);
    if let Some(net) = &snap.net {
        println!("Red local: {net}");
    }
    if !snap.errors.is_empty() {
        for e in &snap.errors {
            eprintln!("⚠ {e}");
        }
    }
    println!("\n=== WiFi ({} BSSIDs) ===", snap.aps.len());
    println!(
        "{:<32} {:<18} {:>6} {:>4}  {:<13} Fabricante",
        "SSID", "BSSID", "RSSI", "CH", "PHY"
    );
    for ap in &snap.aps {
        println!(
            "{:<32} {:<18} {:>6} {:>4}  {:<13} {}",
            truncate(&ap.ssid, 32),
            ap.bssid,
            format!("{} dBm", ap.rssi),
            ap.channel,
            truncate(&ap.phy, 13),
            ap.vendor
        );
    }
    println!("\n=== LAN ({} hosts, tabla ARP) ===", snap.hosts.len());
    println!(
        "{:<16} {:<18} {:<8} Fabricante",
        "IP", "MAC", "Tipo"
    );
    for h in &snap.hosts {
        println!(
            "{:<16} {:<18} {:<8} {}",
            h.ip,
            h.mac,
            h.kind,
            h.vendor
        );
    }
}

/// Unix epoch -> "HH:MM:SS" (hora UTC del día).
#[cfg(target_os = "linux")]
fn hhmmss_utc(secs: u64) -> String {
    let rem = secs % 86400;
    format!("{:02}:{:02}:{:02}", rem / 3600, (rem % 3600) / 60, rem % 60)
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(max - 1).collect::<String>())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn parsea_canales_lista_rangos_y_dedup() {
        assert_eq!(parse_channel_spec("1,6,11"), vec![1, 6, 11]);
        assert_eq!(parse_channel_spec("1-13"), (1..=13).collect::<Vec<_>>());
        assert_eq!(parse_channel_spec("1, 6 ,11"), vec![1, 6, 11]);
        assert_eq!(parse_channel_spec("1-3,2,36-40"), vec![1, 2, 3, 36, 37, 38, 39, 40]);
        // Tokens inválidos ignorados
        assert_eq!(parse_channel_spec("abc,6,xyz"), vec![6]);
        // Vacío -> el llamador aplica el default
        assert!(parse_channel_spec("").is_empty());
        assert!(parse_channel_spec("a-b").is_empty());
    }
}

fn run_tui(oui: &OuiDb, interval: u64) -> anyhow::Result<()> {
    terminal::enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, terminal::EnterAlternateScreen)?;
    let backend = ratatui::backend::CrosstermBackend::new(out);
    let mut terminal = Terminal::new(backend)?;

    let res = tui_loop(&mut terminal, oui, interval);

    // Restaurar la terminal pase lo que pase
    terminal::disable_raw_mode()?;
    execute!(stdout(), terminal::LeaveAlternateScreen)?;

    res
}

fn tui_loop(
    terminal: &mut Terminal<ratatui::backend::CrosstermBackend<std::io::Stdout>>,
    oui: &OuiDb,
    interval: u64,
) -> anyhow::Result<()> {
    let mut snap = model::snapshot(oui);
    let mut history = history::ClientHistory::default();
    let mut tracked = history.update(&snap.hosts);

    loop {
        terminal.draw(|f| ui::draw(f, &snap, &tracked, interval))?;

        // Espera eventos con timeout = intervalo de refresco
        if event::poll(Duration::from_secs(interval))? {
            if let Event::Key(key) = event::read()? {
                // Solo eventos de "pulsación" (en Windows no hay repetición de release)
                if key.kind == ratatui::crossterm::event::KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                        KeyCode::Char('r') => {
                            snap = model::snapshot(oui);
                            tracked = history.update(&snap.hosts);
                        }
                        _ => {}
                    }
                }
            }
        } else {
            // Timeout: refrescar datos
            snap = model::snapshot(oui);
            tracked = history.update(&snap.hosts);
        }
    }
}
