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

use crate::model::{LinkInfo, WifiAp};

use super::{parse_ies, security_from_ies};

/// Convierte el `AttrIfname` de nl80211 a un String utilizable.
///
/// El kernel entrega el nombre terminado en NUL (p. ej. `b"wlan0\0"`), así que
/// hay que recortar los bytes nulos finales o las comparaciones por nombre fallan.
pub(crate) fn ifname_to_string(name: &[u8]) -> String {
    let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    String::from_utf8_lossy(&name[..end]).to_string()
}

fn mac_to_string(mac: &[u8]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Frecuencia en MHz -> número de canal (2.4 y 5 GHz).
/// (Pública dentro del crate: también la usa `monitor`.)
pub(crate) fn freq_to_channel(mhz: u32) -> u8 {
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
    // `get_interfaces_info` incluye wdevs sin netdev (p. ej. la interfaz
    // virtual P2P-device que crea iwlwifi): esas no tienen `AttrIfindex` y el
    // dump de BSS falla con "Interfaz sin índice netlink". Elegimos la primera
    // que sí sea un netdev (índice + nombre).
    let iface = ifaces
        .iter()
        .find(|i| i.index.is_some() && i.name.is_some())
        .or_else(|| ifaces.iter().find(|i| i.index.is_some()))
        .ok_or_else(|| {
            let vistas: Vec<String> = ifaces
                .iter()
                .map(|i| {
                    i.name
                        .as_ref()
                        .map(|n| ifname_to_string(n))
                        .unwrap_or_else(|| "(sin nombre)".to_string())
                })
                .collect();
            anyhow::anyhow!(
                "No hay interfaces WiFi con ifindex (vistas: {})",
                if vistas.is_empty() {
                    "ninguna".to_string()
                } else {
                    vistas.join(", ")
                }
            )
        })?;

    let iface_name = iface
        .name
        .as_ref()
        .map(|n| ifname_to_string(n))
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

        // nl80211 solo entrega los IEs, no el campo Capability del beacon: sin
        // IE de seguridad no podemos distinguir WEP de red abierta.
        let encryption = security_from_ies(
            bss.information_elements.as_deref().unwrap_or(&[]),
            false,
        );

        aps.push(WifiAp {
            ssid,
            bssid,
            rssi,
            phy,
            channel: freq_to_channel(frequency),
            vendor: String::new(), // se resuelve en model::snapshot()
            encryption: encryption.to_string(),
        });
    }

    // Deduplicar por BSSID (el dump puede traer entradas duplicadas)
    aps.sort_by(|a, b| a.bssid.cmp(&b.bssid));
    aps.dedup_by(|a, b| a.bssid == b.bssid);

    Ok((iface_name, aps))
}

/// Estado del enlace de la interfaz conectada (None si no hay asociación).
pub fn link_info() -> anyhow::Result<Option<LinkInfo>> {
    let mut sock = neli_wifi::Socket::connect()
        .map_err(|e| anyhow::anyhow!("No se pudo abrir el socket nl80211: {e}"))?;
    let ifaces = sock
        .get_interfaces_info()
        .map_err(|e| anyhow::anyhow!("get_interfaces_info: {e}"))?;

    let Some(iface) = ifaces.iter().find(|i| i.index.is_some() && i.name.is_some()) else {
        return Ok(None);
    };

    let ssid = iface
        .ssid
        .as_deref()
        .map(ifname_to_string)
        .unwrap_or_default();
    if ssid.is_empty() {
        return Ok(None); // interfaz sin asociar
    }

    let ifindex = iface.index.unwrap_or_default();
    // En modo managed la única "estación" del dump es el AP al que estamos unidos.
    let sta = sock
        .get_station_info(ifindex)
        .unwrap_or_default()
        .into_iter()
        .next();

    let (bssid, rssi, tx_mbps, rx_mbps, connected_secs, tx_retries) = match sta {
        Some(sta) => (
            sta.bssid.as_deref().map(mac_to_string).unwrap_or_default(),
            sta.average_signal
                .or(sta.signal)
                .map(i32::from)
                .unwrap_or(0),
            // nl80211 expone los bitrates en unidades de 100 kbps
            sta.tx_bitrate.map(|r| r as f64 / 10.0),
            sta.rx_bitrate.map(|r| r as f64 / 10.0),
            sta.connected_time,
            sta.tx_retries,
        ),
        None => (String::new(), 0, None, None, None, None),
    };

    Ok(Some(LinkInfo {
        ssid,
        bssid,
        rssi,
        channel: freq_to_channel(iface.frequency.unwrap_or(0)),
        tx_mbps,
        rx_mbps,
        connected_secs,
        tx_retries,
    }))
}
