use crate::{lan, wifi};

/// Un punto de acceso (BSSID) visto por la tarjeta.
#[derive(Clone, Debug)]
pub struct WifiAp {
    pub ssid: String,
    pub bssid: String,
    /// dBm (negativo; más cercano a 0 = mejor señal)
    pub rssi: i32,
    /// Tipo PHY en texto: HT (n), VHT (ac), HE (ax)...
    pub phy: String,
    /// Canal (0 = desconocido)
    pub channel: u8,
}

/// Un host conocido en la red local (tabla ARP del sistema).
#[derive(Clone, Debug)]
pub struct LanHost {
    pub ip: String,
    pub mac: String,
    /// Dynamic / Static / Other
    pub kind: String,
}

/// Fotografía del estado de la red en un instante dado.
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub iface: String,
    pub aps: Vec<WifiAp>,
    pub hosts: Vec<LanHost>,
    /// Resumen de la red local (interfaz/IP/prefijo/puerta de enlace)
    pub net: Option<String>,
    pub errors: Vec<String>,
}

pub fn snapshot() -> Snapshot {
    let mut snap = Snapshot::default();

    match wifi::scan_aps() {
        Ok((iface, aps)) => {
            snap.iface = iface;
            snap.aps = aps;
        }
        Err(e) => snap.errors.push(format!("WiFi: {e}")),
    }

    // Sondeo ARP de la red local + tabla ARP del sistema
    match lan::local_net() {
        Ok(net) => {
            snap.net = Some(format!(
                "{} {} /{} GW {}",
                net.iface,
                net.ip,
                net.prefix_len,
                net.gateway.map(|g| g.to_string()).unwrap_or_else(|| "—".into())
            ));
            match lan::discover(&net) {
                Ok(hosts) => snap.hosts = hosts,
                Err(e) => snap.errors.push(format!("LAN: {e}")),
            }
        }
        Err(e) => snap.errors.push(format!("Red local: {e}")),
    }

    snap.aps.sort_by_key(|ap| std::cmp::Reverse(ap.rssi));
    snap
}
