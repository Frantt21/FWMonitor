//! FWMonitor: monitor de red WiFi en la terminal.
//! Windows: escaneo BSSID (Native WiFi API) + descubrimiento ARP.

mod csv;
mod history;
mod lan;
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
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let oui = match &args.oui_db {
        Some(path) => OuiDb::load_external(path)?,
        None => OuiDb::builtin(),
    };

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

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(max - 1).collect::<String>())
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
