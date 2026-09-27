//! FWMonitor: monitor de red WiFi en la terminal.
//! Windows: escaneo BSSID (Native WiFi API) + tabla ARP.

mod lan;
mod model;
mod ui;
mod wifi;

use std::io::stdout;
use std::time::Duration;

use clap::Parser;
use ratatui::{
    crossterm::event::{self, Event, KeyCode},
    crossterm::{execute, terminal},
    Terminal,
};

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
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if args.once {
        let snap = model::snapshot();
        print_once(&snap);
        return Ok(());
    }

    run_tui(args.interval)
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
    println!("{:<32} {:<18} {:>6} {:>5}  PHY", "SSID", "BSSID", "RSSI", "CH");
    for ap in &snap.aps {
        println!(
            "{:<32} {:<18} {:>+4} {:>4}  {}",
            truncate(&ap.ssid, 32),
            ap.bssid,
            format!("{} dBm", ap.rssi),
            ap.channel,
            ap.phy
        );
    }
    println!("\n=== LAN ({} hosts, tabla ARP) ===", snap.hosts.len());
    println!("{:<16} {:<18} Tipo", "IP", "MAC");
    for h in &snap.hosts {
        println!("{:<16} {:<18} {}", h.ip, h.mac, h.kind);
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(max - 1).collect::<String>())
    }
}

fn run_tui(interval: u64) -> anyhow::Result<()> {
    terminal::enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, terminal::EnterAlternateScreen)?;
    let backend = ratatui::backend::CrosstermBackend::new(out);
    let mut terminal = Terminal::new(backend)?;

    let res = tui_loop(&mut terminal, interval);

    // Restaurar la terminal pase lo que pase
    terminal::disable_raw_mode()?;
    execute!(stdout(), terminal::LeaveAlternateScreen)?;

    res
}

fn tui_loop(terminal: &mut Terminal<ratatui::backend::CrosstermBackend<std::io::Stdout>>, interval: u64) -> anyhow::Result<()> {
    let mut snap = model::snapshot();

    loop {
        terminal.draw(|f| ui::draw(f, &snap, interval))?;

        // Espera eventos con timeout = intervalo de refresco
        if event::poll(Duration::from_secs(interval))? {
            if let Event::Key(key) = event::read()? {
                // Solo eventos de "pulsación" (en Windows no hay repetición de release)
                if key.kind == ratatui::crossterm::event::KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                        KeyCode::Char('r') => snap = model::snapshot(),
                        _ => {}
                    }
                }
            }
        } else {
            // Timeout: refrescar datos
            snap = model::snapshot();
        }
    }
}
