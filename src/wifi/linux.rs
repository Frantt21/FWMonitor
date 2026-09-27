//! Escaneo WiFi vía nl80211 (netlink genérico) para Linux.
//! - `CmdTriggerScan` construido a mano con `neli` (neli-wifi no lo expone).
//! - `CmdGetScan` vía `neli_wifi::Socket::get_bss_info` (dump de la caché BSS).
//! - SSID y PHY extraídos de los Information Elements del beacon/probe.
//!
//! No requiere permisos especiales para escanear; si la interfaz está
//! gestionada por wpa_supplicant/NetworkManager el escaneo se coordina con ellos.

use std::time::Duration;

use neli::consts::nl::{NlmF, NlmFFlags, Nlmsg};
use neli::consts::socket::NlFamily;
use neli::genl::{Genlmsghdr, Nlattr};
use neli::nl::{NlPayload, Nlmsghdr};
use neli::socket::NlSocketHandle;
use neli::types::GenlBuffer;
use neli_wifi::{Nl80211Attr, Nl80211Cmd, NL_80211_GENL_VERSION};

use crate::model::WifiAp;

fn mac_to_string(mac: &[u8]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Extrae el SSID (IE id 0) y la "Supported Rates"/HT info aproximada de los IEs.
/// El PHY real lo deducimos de las capacidades anunciadas: es lo mismo que hace
/// `iw` al mostrar "capability". Nos basta con distinguir b/g/n/ac/ax.
fn parse_ies(ies: &[u8]) -> (Option<String>, Option<&'static str>) {
    let mut ssid = None;
    let mut phy = None;
    let mut i = 0usize;
    while i + 1 < ies.len() {
        let id = ies[i];
        let len = ies[i + 1] as usize;
        if i + 2 + len > ies.len() {
            break;
        }
        let body = &ies[i + 2..i + 2 + len];
        match id {
            0 => ssid = Some(String::from_utf8_lossy(body).to_string()),
            // IE 45 = HT capabilities (802.11n)
            45 => phy = phy.or(Some("HT (11n)")),
            // IE 191 = VHT capabilities (802.11ac)
            191 => phy = phy.or(Some("VHT (11ac)")),
            // IE 255 = extension: body[0]==35 es HE capabilities (802.11ax)
            255 if !body.is_empty() && body[0] == 35 => phy = Some("HE (WiFi 6)"),
            _ => {}
        }
        i += 2 + len;
    }
    (ssid, phy)
}

/// Frecuencia en MHz -> número de canal (2.4 y 5 GHz).
fn freq_to_channel(mhz: u32) -> u8 {
    match mhz {
        2412..=2472 => ((mhz - 2412) / 5 + 1) as u8,
        2484 => 14,
        5160..=5885 => ((mhz - 5000) / 5) as u8,
        _ => 0,
    }
}

/// Lanza `NL80211_CMD_TRIGGER_SCAN` sobre la interfaz indicada.
/// Devuelve error si el kernel lo rechaza (p. ej. EBUSY si ya hay un escaneo).
fn trigger_scan(sock: &mut NlSocketHandle, family_id: u16, ifindex: i32) -> anyhow::Result<()> {
    let msghdr = Genlmsghdr::<Nl80211Cmd, Nl80211Attr>::new(
        Nl80211Cmd::CmdTriggerScan,
        NL_80211_GENL_VERSION,
        {
            let mut attrs = GenlBuffer::new();
            attrs.push(
                Nlattr::new(false, false, Nl80211Attr::AttrIfindex, ifindex)
                    .map_err(|e| anyhow::anyhow!("Nlattr ifindex: {e}"))?,
            );
            attrs
        },
    );

    let nlhdr = Nlmsghdr::new(
        None,
        family_id,
        NlmFFlags::new(&[NlmF::Request, NlmF::Ack]),
        None,
        None,
        NlPayload::Payload(msghdr),
    );
    sock.send(nlhdr)?;

    // Esperar el ACK del kernel (o error)
    let iter = sock.iter::<Nlmsg, Genlmsghdr<Nl80211Cmd, Nl80211Attr>>(false);
    for response in iter {
        let msg = response.map_err(|e| anyhow::anyhow!("netlink recv: {e}"))?;
        match &msg.nl_payload {
            NlPayload::Ack(_) => return Ok(()),
            NlPayload::Err(e) => {
                anyhow::bail!("trigger_scan rechazado (error {})", e.error);
            }
            _ => continue,
        }
    }
    anyhow::bail!("Sin respuesta del kernel al trigger_scan");
}

/// Escanea la interfaz WiFi y devuelve (nombre_interfaz, lista_de_BSSIDs).
pub fn scan_aps() -> anyhow::Result<(String, Vec<WifiAp>)> {
    let mut nlsock = neli_wifi::Socket::connect()
        .map_err(|e| anyhow::anyhow!("No se pudo abrir el socket nl80211: {e}"))?;

    let ifaces = nlsock
        .get_interfaces_info()
        .map_err(|e| anyhow::anyhow!("get_interfaces_info: {e}"))?;
    let iface = ifaces
        .first()
        .ok_or_else(|| anyhow::anyhow!("No hay interfaces WiFi"))?;

    let iface_name = iface
        .name
        .as_ref()
        .map(|n| String::from_utf8_lossy(n).to_string())
        .unwrap_or_else(|| "wlan".to_string());
    let ifindex = iface
        .index
        .ok_or_else(|| anyhow::anyhow!("Interfaz sin índice netlink"))?;

    // Escaneo activo para datos frescos (falla con -EBUSY si ya hay uno en marcha,
    // en cuyo caso usamos la caché existente igualmente)
    let mut raw = NlSocketHandle::connect(NlFamily::Generic, None, &[])
        .map_err(|e| anyhow::anyhow!("socket genérico: {e}"))?;
    let fam_id = raw
        .resolve_genl_family(neli_wifi::NL_80211_GENL_NAME)
        .map_err(|e| anyhow::anyhow!("familia nl80211: {e}"))?;
    if trigger_scan(&mut raw, fam_id, ifindex).is_ok() {
        // Tiempo típico de escaneo completo en 2.4+5 GHz
        std::thread::sleep(Duration::from_millis(3500));
    }

    let bsss = nlsock
        .get_bss_info(ifindex)
        .map_err(|e| anyhow::anyhow!("get_bss_info: {e}"))?;

    let mut aps: Vec<WifiAp> = Vec::new();
    for bss in bsss {
        let bssid = bss
            .bssid
            .as_ref()
            .map(|m| mac_to_string(m))
            .unwrap_or_default();
        if bssid.is_empty() {
            continue;
        }
        let frequency = bss.frequency.unwrap_or(0);
        let rssi = bss.signal.unwrap_or(0) / 100; // mBm -> dBm
        let (ssid, phy_ies) = bss
            .information_elements
            .as_deref()
            .map(parse_ies)
            .unwrap_or((None, None));
        let ssid = ssid.unwrap_or_default();

        // Deducir PHY por frecuencia si no hay IEs con HT/VHT
        let phy = phy_ies
            .map(|s| s.to_string())
            .unwrap_or_else(|| match frequency {
                2412..=2484 => "HT (11n)".to_string(),
                _ => "VHT (11ac)".to_string(),
            });

        aps.push(WifiAp {
            ssid,
            bssid,
            rssi,
            phy,
            channel: freq_to_channel(frequency),
            vendor: String::new(), // se resuelve en model::snapshot()
        });
    }

    // Deduplicar por BSSID (el dump puede traer entradas duplicadas)
    aps.sort_by(|a, b| a.bssid.cmp(&b.bssid));
    aps.dedup_by(|a, b| a.bssid == b.bssid);

    Ok((iface_name, aps))
}
