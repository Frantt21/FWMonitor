//! Export del snapshot a CSV, con timestamp ISO-8601 (UTC) y escape correcto.

use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::model::Snapshot;

const HEADER: &str = "ts,source,ssid,ip,bssid,mac,channel,rssi,phy,kind,vendor,name";

/// Escapa un campo CSV: entrecomilla si contiene coma, comilla o salto de línea.
fn esc(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Unix epoch -> "2026-09-26T18:45:03Z" (UTC, sin dependencias externas).
fn iso_from_unix(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let (h, min, sec) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    // civil_from_days (Howard Hinnant), epoch 1970-01-01
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if month <= 2 { y + 1 } else { y };

    format!("{y:04}-{month:02}-{d:02}T{h:02}:{min:02}:{sec:02}Z")
}

/// Una fila WiFi con las mismas columnas que [`HEADER`].
fn wifi_row(ts: &str, ap: &crate::model::WifiAp) -> String {
    format!(
        "{ts},wifi,{},,{},,{},{},{},,{},\n",
        esc(&ap.ssid),
        esc(&ap.bssid),
        ap.channel,
        ap.rssi,
        esc(&ap.phy),
        esc(&ap.vendor),
    )
}

/// Una fila LAN con las mismas columnas que [`HEADER`].
fn lan_row(ts: &str, h: &crate::model::LanHost) -> String {
    format!(
        "{ts},lan,,{},,{},,,,{},{},{}\n",
        esc(&h.ip),
        esc(&h.mac),
        esc(&h.kind),
        esc(&h.vendor),
        esc(&h.name),
    )
}

fn now_iso() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    iso_from_unix(secs)
}

/// Escribe (o añade) el snapshot al CSV indicado.
/// `append=false` sobreescribe con cabecera; `append=true` añade al final
/// y solo escribe la cabecera si el archivo no existía.
pub fn export(path: &Path, snap: &Snapshot, append: bool) -> anyhow::Result<()> {
    let ts = now_iso();
    let mut rows = String::new();

    let is_new = !path.exists();
    if !append || is_new {
        rows.push_str(HEADER);
        rows.push('\n');
    }

    for ap in &snap.aps {
        rows.push_str(&wifi_row(&ts, ap));
    }

    for h in &snap.hosts {
        rows.push_str(&lan_row(&ts, h));
    }

    if append {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        f.write_all(rows.as_bytes())?;
    } else {
        std::fs::write(path, rows)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_conocido() {
        assert_eq!(iso_from_unix(0), "1970-01-01T00:00:00Z");
        // 2026-09-26T00:00:00Z = 1790380800
        assert_eq!(iso_from_unix(1_790_380_800), "2026-09-26T00:00:00Z");
        // Año bisiesto: 2024-02-29T12:00:00Z = 1709208000
        assert_eq!(iso_from_unix(1_709_208_000), "2024-02-29T12:00:00Z");
    }

    #[test]
    fn filas_con_tantas_columnas_como_la_cabecera() {
        let expected = HEADER.split(',').count();
        let ap = crate::model::WifiAp {
            ssid: "MiRed".into(),
            bssid: "a0:08:6f:9e:8f:68".into(),
            rssi: -41,
            phy: "HT (11n)".into(),
            channel: 7,
            vendor: "AVM".into(),
            encryption: "WPA2".into(),
        };
        let host = crate::model::LanHost {
            ip: "192.168.1.5".into(),
            mac: "aa:bb:cc:dd:ee:ff".into(),
            kind: "ARP".into(),
            vendor: "".into(),
            name: "tv-salon".into(),
        };
        assert_eq!(wifi_row("2026-01-01T00:00:00Z", &ap).trim_end().split(',').count(), expected);
        assert_eq!(lan_row("2026-01-01T00:00:00Z", &host).trim_end().split(',').count(), expected);
    }

    #[test]
    fn escape_csv() {
        assert_eq!(esc("normal"), "normal");
        assert_eq!(esc("con,coma"), "\"con,coma\"");
        assert_eq!(esc("con\"comilla"), "\"con\"\"comilla\"");
    }
}
