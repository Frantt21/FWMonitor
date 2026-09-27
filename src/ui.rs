//! TUI con ratatui: tabla de APs visibles y hosts LAN, con refresco en vivo.

use ratatui::{
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Frame,
};

use crate::model::Snapshot;

/// Dibuja un frame completo con dos paneles: WiFi arriba, LAN abajo.
pub fn draw(f: &mut Frame, snap: &Snapshot, interval: u64) {
    let [top, bottom] = Layout::vertical([
        Constraint::Percentage(60),
        Constraint::Percentage(40),
    ])
    .areas(f.area());

    draw_wifi_panel(f, snap, top);
    draw_lan_panel(f, snap, bottom);
    draw_footer(f, snap, interval);
}

fn draw_wifi_panel(f: &mut Frame, snap: &Snapshot, area: ratatui::layout::Rect) {
    let header = Row::new(["SSID", "BSSID", "Señal", "Canal", "PHY", "Fabricante"])
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD));

    let rows: Vec<Row> = snap
        .aps
        .iter()
        .map(|ap| {
            let signal = if ap.rssi != 0 {
                format!("{} dBm", ap.rssi)
            } else {
                "—".to_string()
            };
            let bars = signal_bars(ap.rssi);
            Row::new([
                Cell::from(ap.ssid.clone()),
                Cell::from(ap.bssid.clone()),
                Cell::from(format!("{bars} {signal}")),
                Cell::from(ap.channel.to_string()),
                Cell::from(ap.phy.clone()),
                Cell::from(ap.vendor.clone()),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(20),
            Constraint::Percentage(19),
            Constraint::Percentage(15),
            Constraint::Length(6),
            Constraint::Percentage(12),
            Constraint::Percentage(28),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" WiFi: {} BSSIDs (interfaz: {}) ", snap.aps.len(), snap.iface)),
    )
    .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    f.render_widget(table, area);
}

fn draw_lan_panel(f: &mut Frame, snap: &Snapshot, area: ratatui::layout::Rect) {
    let header = Row::new(["IP", "MAC", "Tipo", "Fabricante"])
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD));

    let rows: Vec<Row> = snap
        .hosts
        .iter()
        .map(|h| {
            Row::new([
                Cell::from(h.ip.clone()),
                Cell::from(h.mac.clone()),
                Cell::from(h.kind.clone()),
                Cell::from(h.vendor.clone()),
            ])
        })
        .collect();

    let net_info = snap.net.as_deref().unwrap_or("");
    let table = Table::new(
        rows,
        [
            Constraint::Percentage(15),
            Constraint::Percentage(20),
            Constraint::Length(8),
            Constraint::Percentage(57),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" LAN: {} hosts {net_info} ", snap.hosts.len())),
    );

    f.render_widget(table, area);
}

fn draw_footer(f: &mut Frame, snap: &Snapshot, interval: u64) {
    let area = f.area();
    let mut spans = vec![
        Span::styled(
            format!(" FWMonitor v0.1 — refresco cada {interval}s "),
            Style::default().fg(Color::Black).bg(Color::Cyan),
        ),
        Span::raw("  "),
        Span::styled("[r] refrescar", Style::default().fg(Color::Yellow)),
        Span::raw("  "),
        Span::styled("[q] salir", Style::default().fg(Color::Yellow)),
    ];

    if !snap.errors.is_empty() {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(
            format!("⚠ {}", snap.errors.join(" | ")),
            Style::default().fg(Color::Red),
        ));
    }

    let footer = Paragraph::new(Line::from(spans));
    let [_, footer_area] = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).areas(area);
    f.render_widget(footer, footer_area);
}

fn signal_bars(rssi: i32) -> String {
    // Heurística: >-50 excelente, >-65 bueno, >-75 regular, >-85 flojo, resto malo
    match rssi {
        -50..=0 => "█████",
        -65..=-51 => "████░",
        -75..=-66 => "███░░",
        -85..=-76 => "██░░░",
        _ => "█░░░░",
    }
    .to_string()
}
