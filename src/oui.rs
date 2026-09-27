//! Resolución de fabricante por OUI (primeros 3 bytes de la MAC).
//! Incluye una tabla integrada con los OUIs más comunes y soporta cargar
//! la base completa de IEEE (`oui.csv`) o la `manuf` de Wireshark.

use std::collections::HashMap;
use std::path::Path;

/// Base de datos OUI: clave = primeros 3 octetos de la MAC como u24.
pub struct OuiDb {
    map: HashMap<u32, String>,
}

impl OuiDb {
    /// Base integrada (~140 OUIs de fabricantes comunes).
    pub fn builtin() -> Self {
        let entries: &[(&str, &str)] = &[
            // Routers / redes domésticas
            // AVM FRITZ!Box (muy común en redes domésticas)
            ("00:1C:4A", "AVM (FRITZ!Box)"),
            ("24:65:11", "AVM (FRITZ!Box)"),
            ("34:31:C4", "AVM (FRITZ!Box)"),
            ("38:10:D5", "AVM (FRITZ!Box)"),
            ("7C:FF:4D", "AVM (FRITZ!Box)"),
            ("A0:08:6F", "AVM (FRITZ!Box)"),
            ("B0:F2:08", "AVM (FRITZ!Box)"),
            ("C8:0E:14", "AVM (FRITZ!Box)"),
            ("CC:CE:1E", "AVM (FRITZ!Box)"),
            ("DC:39:6F", "AVM (FRITZ!Box)"),
            ("E0:28:6D", "AVM (FRITZ!Box)"),
            ("F0:30:29", "AVM (FRITZ!Box)"),
            ("00:0D:88", "D-Link"),
            ("00:0F:3D", "D-Link"),
            ("00:11:95", "D-Link"),
            ("00:13:46", "D-Link"),
            ("00:15:E9", "D-Link"),
            ("00:17:9A", "D-Link"),
            ("00:18:E7", "D-Link"),
            ("00:1B:11", "D-Link"),
            ("00:1C:F0", "D-Link"),
            ("00:1E:58", "D-Link"),
            ("00:22:B0", "D-Link"),
            ("00:24:01", "D-Link"),
            ("00:26:5A", "D-Link"),
            ("00:23:CD", "TP-Link"),
            ("14:CC:20", "TP-Link"),
            ("30:B5:C2", "TP-Link"),
            ("44:D9:E7", "TP-Link"),
            ("50:C7:BF", "TP-Link"),
            ("60:32:B1", "TP-Link"),
            ("84:16:F9", "TP-Link"),
            ("98:DA:C4", "TP-Link"),
            ("AC:84:C6", "TP-Link"),
            ("C0:25:E9", "TP-Link"),
            ("D8:0D:17", "TP-Link"),
            ("EC:08:6B", "TP-Link"),
            ("00:09:5B", "Netgear"),
            ("00:0F:B5", "Netgear"),
            ("00:14:6C", "Netgear"),
            ("00:18:4D", "Netgear"),
            ("00:1B:2F", "Netgear"),
            ("00:1F:33", "Netgear"),
            ("00:22:3F", "Netgear"),
            ("00:24:B2", "Netgear"),
            ("00:26:F2", "Netgear"),
            ("20:E5:2A", "Netgear"),
            ("9C:3D:CF", "Netgear"),
            ("A0:40:A0", "Netgear"),
            ("B0:39:56", "Netgear"),
            ("C0:3F:0E", "Netgear"),
            ("C4:04:15", "Netgear"),
            ("44:94:FC", "Netgear"),
            ("6C:B0:CE", "Netgear"),
            ("00:12:17", "Cisco-Linksys"),
            ("00:14:BF", "Cisco-Linksys"),
            ("00:16:B6", "Cisco-Linksys"),
            ("00:18:39", "Cisco-Linksys"),
            ("00:22:6B", "Cisco-Linksys"),
            ("00:1A:A1", "Cisco"),
            ("00:1B:0C", "Cisco"),
            ("00:1C:B3", "Cisco"),
            ("00:1D:70", "Cisco"),
            ("00:1E:49", "Cisco"),
            ("00:25:45", "Cisco"),
            ("00:0B:86", "Aruba Networks"),
            ("00:1A:1E", "Aruba Networks"),
            ("00:24:6C", "Aruba Networks"),
            ("00:0C:42", "MikroTik"),
            ("48:8F:5A", "MikroTik"),
            ("64:D1:54", "MikroTik"),
            ("D4:CA:6D", "MikroTik"),
            ("F0:9F:C2", "Ubiquiti"),
            ("24:5A:4C", "Ubiquiti"),
            ("78:8A:20", "Ubiquiti"),
            ("68:D7:9A", "Ubiquiti"),
            ("74:AC:B9", "Ubiquiti"),
            ("FC:EC:DA", "Ubiquiti"),
            // Intel (WiFi/ethernet en portátiles)
            ("00:1B:21", "Intel"),
            ("00:1C:BF", "Intel"),
            ("00:1C:C0", "Intel"),
            ("00:1D:E0", "Intel"),
            ("00:1E:64", "Intel"),
            ("00:1E:65", "Intel"),
            ("00:1F:3B", "Intel"),
            ("00:1F:3C", "Intel"),
            ("00:21:5C", "Intel"),
            ("00:21:5D", "Intel"),
            ("00:22:FA", "Intel"),
            ("00:22:FB", "Intel"),
            ("00:24:D6", "Intel"),
            ("00:24:D7", "Intel"),
            // Otros chips de red
            ("00:E0:4C", "Realtek"),
            ("00:0B:6B", "Atheros"),
            ("00:13:74", "Atheros"),
            ("00:0C:43", "Ralink"),
            ("00:10:18", "Broadcom"),
            ("00:90:4C", "Broadcom"),
            ("9C:B6:D0", "Rivet Networks (Killer)"),
            // Apple
            ("00:03:93", "Apple"),
            ("00:10:FA", "Apple"),
            ("00:14:51", "Apple"),
            ("00:16:CB", "Apple"),
            ("00:17:F2", "Apple"),
            ("00:19:E3", "Apple"),
            ("00:1B:63", "Apple"),
            ("00:1E:52", "Apple"),
            ("00:21:E9", "Apple"),
            ("00:23:6C", "Apple"),
            ("00:23:DF", "Apple"),
            ("00:25:BC", "Apple"),
            ("F8:1E:DF", "Apple"),
            ("8C:29:37", "Apple"),
            ("F0:B4:79", "Apple"),
            // Samsung / LG / Sony
            ("00:07:AB", "Samsung"),
            ("00:16:32", "Samsung"),
            ("00:1B:98", "Samsung"),
            ("00:23:99", "Samsung"),
            ("00:24:54", "Samsung"),
            ("00:26:37", "Samsung"),
            ("5C:3C:27", "Samsung"),
            ("84:38:35", "Samsung"),
            ("8C:77:12", "Samsung"),
            ("F0:25:B7", "Samsung"),
            ("00:1E:75", "LG Electronics"),
            ("00:01:4A", "Sony"),
            ("00:13:A9", "Sony"),
            ("00:19:63", "Sony"),
            ("00:1A:80", "Sony"),
            ("30:F9:ED", "Sony"),
            // Huawei / Xiaomi
            ("00:18:82", "Huawei"),
            ("00:1E:10", "Huawei"),
            ("00:25:9E", "Huawei"),
            ("00:46:4B", "Huawei"),
            ("28:6E:D4", "Huawei"),
            ("34:6B:D3", "Huawei"),
            ("78:1D:BA", "Huawei"),
            ("18:59:36", "Xiaomi"),
            ("64:09:80", "Xiaomi"),
            ("74:23:44", "Xiaomi"),
            ("78:02:F8", "Xiaomi"),
            ("8C:BE:BE", "Xiaomi"),
            ("F0:B4:29", "Xiaomi"),
            ("AC:C1:EE", "Xiaomi"),
            // PCs y servidores
            ("00:14:22", "Dell"),
            ("B8:CA:3A", "Dell"),
            ("F8:1A:67", "Dell"),
            ("3C:D9:2B", "Hewlett-Packard"),
            ("54:E1:AD", "Lenovo"),
            ("8C:16:45", "Lenovo"),
            ("F0:DE:F1", "Lenovo"),
            ("00:1D:D8", "Supermicro"),
            ("0C:C4:7A", "Supermicro"),
            ("00:05:69", "VMware"),
            ("00:0C:29", "VMware"),
            ("00:1C:14", "VMware"),
            ("00:50:56", "VMware"),
            ("00:15:5D", "Microsoft (Hyper-V)"),
            ("00:0D:3A", "Microsoft"),
            ("52:54:00", "QEMU/KVM"),
            ("00:16:3E", "Xen"),
            ("3C:A9:F4", "ASUSTek"),
            ("04:D9:F5", "ASUSTek"),
            ("AC:9E:17", "ASUSTek"),
            // NAS / almacenamiento
            ("00:11:32", "Synology"),
            ("24:5E:BE", "QNAP"),
            ("00:10:75", "Seagate"),
            ("00:90:A9", "Western Digital"),
            // IoT / domótica / streaming
            ("00:17:88", "Philips (Hue)"),
            ("44:65:0D", "Amazon"),
            ("68:37:E9", "Amazon"),
            ("74:C2:46", "Amazon"),
            ("84:D6:D0", "Amazon"),
            ("00:1A:11", "Google"),
            ("3C:5A:B4", "Google"),
            ("F4:F5:D8", "Google"),
            ("6C:AD:F8", "Google"),
            ("30:FD:38", "Google"),
            ("B0:EE:7B", "Roku"),
            ("CC:6D:A0", "Roku"),
            ("00:0E:58", "Sonos"),
            ("34:7E:5C", "Sonos"),
            ("78:28:CA", "Sonos"),
            ("94:9F:3E", "Sonos"),
            ("94:10:3E", "Belkin"),
            ("EC:1A:59", "Belkin"),
            ("10:D5:61", "Tuya"),
            ("D8:F1:5B", "Tuya"),
            ("18:FE:34", "Espressif (ESP)"),
            ("24:0A:C4", "Espressif (ESP)"),
            ("24:6F:28", "Espressif (ESP)"),
            ("30:AE:A4", "Espressif (ESP)"),
            ("5C:CF:7F", "Espressif (ESP)"),
            ("84:F3:EB", "Espressif (ESP)"),
            ("A4:CF:12", "Espressif (ESP)"),
            ("BC:DD:C2", "Espressif (ESP)"),
            ("DC:4F:22", "Espressif (ESP)"),
            ("EC:FA:BC", "Espressif (ESP)"),
            ("00:1F:1F", "AzureWave"),
            ("00:24:23", "AzureWave"),
            // Raspberry Pi
            ("B8:27:EB", "Raspberry Pi"),
            ("DC:A6:32", "Raspberry Pi"),
            ("E4:5F:01", "Raspberry Pi"),
            ("D8:3A:DD", "Raspberry Pi"),
        ];

        let map = entries
            .iter()
            .filter_map(|(oui, vendor)| {
                mac_prefix_to_u24(oui).map(|k| (k, vendor.to_string()))
            })
            .collect();
        Self { map }
    }

    /// Carga la base externa y la fusiona sobre la integrada.
    /// Formatos soportados: `oui.csv` de IEEE ("002370","Vendor",...) y
    /// `manuf` de Wireshark (00:23:70\tVendor).
    pub fn load_external(path: &Path) -> anyhow::Result<Self> {
        let mut db = Self::builtin();
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("No se pudo leer {}: {e}", path.display()))?;
        let mut added = 0usize;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((oui, vendor)) = parse_oui_line(line) {
                if db.map.insert(oui, vendor).is_none() {
                    added += 1;
                }
            }
        }

        eprintln!(
            "OUI: {} entradas integradas + {added} cargadas desde {}",
            db.map.len() - added,
            path.display()
        );
        Ok(db)
    }

    /// Resuelve el fabricante de una MAC. Vacío si se desconoce.
    /// Si la MAC es localmente administrada (bit 1 del primer octeto),
    /// se informa de que es aleatoria: no tiene OUI real asignado.
    pub fn resolve(&self, mac: &str) -> String {
        let Some(key) = mac_prefix_to_u24(mac) else {
            return String::new();
        };
        if let Some(v) = self.map.get(&key) {
            return v.clone();
        }
        // MAC localmente administrada: el usuario la aleatorizó (móviles modernos)
        if key >> 16 & 0x02 != 0 {
            return "MAC aleatoria (privada)".to_string();
        }
        String::new()
    }
}

/// "a0:08:6f" | "a0-08-6f" | "a0086f" | "0xa0086f" -> u24
fn mac_prefix_to_u24(mac: &str) -> Option<u32> {
    let clean: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_lowercase();

    // Tomamos solo los primeros 6 dígitos hex (3 octetos)
    if clean.len() < 6 {
        return None;
    }
    u32::from_str_radix(&clean[..6], 16).ok()
}

/// Split CSV respetando comillas ("a,""b"",c" -> ["a", "b", "c"]).
fn split_csv_line(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    cur.push('"');
                } else {
                    in_quotes = false;
                }
            } else {
                cur.push(c);
            }
        } else {
            match c {
                '"' => in_quotes = true,
                ',' => out.push(std::mem::take(&mut cur)),
                _ => cur.push(c),
            }
        }
    }
    out.push(cur);
    out
}

/// Detecta el formato de línea (IEEE oui.csv o manuf de Wireshark).
fn parse_oui_line(line: &str) -> Option<(u32, String)> {
    // Formato manuf de Wireshark: "00:23:70\tPhilips Lighting B.V."
    if line.contains('\t') {
        let mut parts = line.splitn(2, '\t');
        let oui = parts.next()?.trim();
        let vendor = parts.next()?.trim().to_string();
        if vendor.is_empty() {
            return None;
        }
        return mac_prefix_to_u24(oui).map(|k| (k, vendor));
    }

    // Formato IEEE oui.csv: 002370,"Philips Lighting B.V.","00-23-70/36",...
    // campo 0 = assignment (hex), campo 1 = nombre de la organización.
    // La cabecera ("Registry,Assignment,...") se filtra sola: no es hex.
    if line.contains(',') {
        let fields = split_csv_line(line);
        if fields.len() >= 2 {
            let oui = fields[0].trim();
            let vendor = fields[1].trim().to_string();
            if !vendor.is_empty() {
                return mac_prefix_to_u24(oui).map(|k| (k, vendor));
            }
        }
        return None;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resuelve_ouis_integrados() {
        let db = OuiDb::builtin();
        assert_eq!(db.resolve("00:50:56:aa:bb:cc"), "VMware");
        assert_eq!(db.resolve("DC-A6-32-11-22-33"), "Raspberry Pi");
        assert_eq!(db.resolve("A0:08:6F:DE:14:5D"), "AVM (FRITZ!Box)");
        assert_eq!(db.resolve("38:70:0c:ca:4c:c0"), ""); // desconocido
        // MAC localmente administrada -> aleatoria (privacidad)
        assert_eq!(db.resolve("fa:e2:d8:5d:96:24"), "MAC aleatoria (privada)");
        assert_eq!(db.resolve("12:8e:f5:d5:36:fe"), "MAC aleatoria (privada)");
    }

    #[test]
    fn carga_formato_ieee() {
        let dir = std::env::temp_dir().join("fwmonitor_oui_test");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("oui.csv");
        std::fs::write(&file, "002370,\"Philips Lighting B.V.\",00-23-70/36\n0C8063,\"Test Vendor\"\n").unwrap();
        let db = OuiDb::load_external(&file).unwrap();
        assert_eq!(db.resolve("00:23:70:aa:bb:cc"), "Philips Lighting B.V.");
        assert_eq!(db.resolve("0c:80:63:00:00:01"), "Test Vendor");
    }

    #[test]
    fn carga_formato_manuf() {
        let dir = std::env::temp_dir().join("fwmonitor_oui_test");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("manuf");
        std::fs::write(&file, "00:23:70\tPhilips Lighting B.V.\n52:54:00\tQEMU virtual NIC\n").unwrap();
        let db = OuiDb::load_external(&file).unwrap();
        assert_eq!(db.resolve("00:23:70:11:22:33"), "Philips Lighting B.V.");
        assert_eq!(db.resolve("52:54:00:aa:bb:cc"), "QEMU virtual NIC");
    }
}
