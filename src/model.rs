//! Modelos de datos y captura del snapshot combinando WiFi + LAN.

use crate::{lan, oui::OuiDb, wifi};

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
    /// Fabricante según OUI del BSSID
    pub vendor: String,
    /// Cifrado anunciado: abierta, WEP, WPA, WPA2, WPA3, WPA2/WPA3...
    pub encryption: String,
}

impl WifiAp {
    /// `true` si el AP no anuncia cifrado (red abierta).
    pub fn is_open(&self) -> bool {
        self.encryption == "abierta"
    }
}

/// Estado del enlace de la interfaz conectada.
#[derive(Clone, Debug)]
pub struct LinkInfo {
    pub ssid: String,
    pub bssid: String,
    /// dBm de la señal actual
    pub rssi: i32,
    pub channel: u8,
    /// Mbps negociados con el AP
    pub tx_mbps: Option<f64>,
    pub rx_mbps: Option<f64>,
    /// Segundos desde que se asoció (solo Linux)
    pub connected_secs: Option<u32>,
    /// Reintentos de TX acumulados (solo Linux)
    pub tx_retries: Option<u32>,
}

/// Un host conocido en la red local.
#[derive(Clone, Debug)]
pub struct LanHost {
    pub ip: String,
    pub mac: String,
    /// GW / Local / Dynamic / Static / ARP
    pub kind: String,
    /// Fabricante según OUI de la MAC
    pub vendor: String,
}

/// Fotografía del estado de la red en un instante dado.
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub iface: String,
    pub aps: Vec<WifiAp>,
    pub hosts: Vec<LanHost>,
    /// Resumen de la red local (interfaz/IP/prefijo/puerta de enlace)
    pub net: Option<String>,
    /// Enlace WiFi actual (None si no hay asociación)
    pub link: Option<LinkInfo>,
    pub errors: Vec<String>,
}

pub fn snapshot(oui: &OuiDb) -> Snapshot {
    let mut snap = Snapshot::default();

    match wifi::scan_aps() {
        Ok((iface, aps)) => {
            snap.iface = iface;
            snap.aps = aps;
        }
        Err(e) => snap.errors.push(format!("WiFi: {e}")),
    }

    match wifi::link_info() {
        Ok(link) => snap.link = link,
        Err(e) => snap.errors.push(format!("Enlace: {e}")),
    }

    // Sondeo ARP de la red local + tabla ARP del sistema
    match lan::local_net() {
        Ok(net) => {
            snap.net = Some(format!(
                "{} {} /{} GW {}",
                net.iface,
                net.ip,
                net.prefix_len,
                net.gateway
                    .map(|g| g.to_string())
                    .unwrap_or_else(|| "—".into())
            ));
            match lan::discover(&net) {
                Ok(hosts) => snap.hosts = hosts,
                Err(e) => snap.errors.push(format!("LAN: {e}")),
            }
        }
        Err(e) => snap.errors.push(format!("Red local: {e}")),
    }

    // Resolver fabricantes por OUI
    for ap in &mut snap.aps {
        ap.vendor = oui.resolve(&ap.bssid);
    }
    for h in &mut snap.hosts {
        h.vendor = oui.resolve(&h.mac);
    }

    snap.aps.sort_by_key(|ap| std::cmp::Reverse(ap.rssi));
    snap
}
