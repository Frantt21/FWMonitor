//! Escaneo WiFi multiplataforma.
//! Windows: Native WiFi API (wlanapi.dll). Linux: nl80211 (netlink).

#[cfg(windows)]
pub(crate) mod windows;
#[cfg(windows)]
pub use windows::{link_info, scan_aps};

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use linux::{link_info, scan_aps};

// ---------------------------------------------------------------------------
// Information Elements (compartido por los dos backends)
// ---------------------------------------------------------------------------

/// Extrae el SSID (IE id 0) y la "Supported Rates"/HT info aproximada de los IEs.
/// El PHY real lo deducimos de las capacidades anunciadas: es lo mismo que hace
/// `iw` al mostrar "capability". Nos basta con distinguir b/g/n/ac/ax.
pub(crate) fn parse_ies(ies: &[u8]) -> (Option<String>, Option<&'static str>) {
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

/// Cifrado anunciado por un BSS, deducido de sus Information Elements.
///
/// `privacy` es el bit de privacidad del campo Capability del beacon; solo
/// Windows lo expone (nl80211 no da la cabecera fija), así que en Linux una WEP
/// sin IE de seguridad se ve como "abierta".
pub(crate) fn security_from_ies(ies: &[u8], privacy: bool) -> &'static str {
    let mut rsn: Option<&[u8]> = None;
    let mut wpa = false;

    let mut i = 0usize;
    while i + 1 < ies.len() {
        let id = ies[i];
        let len = ies[i + 1] as usize;
        if i + 2 + len > ies.len() {
            break;
        }
        let body = &ies[i + 2..i + 2 + len];
        match id {
            // IE 48 = RSN (WPA2/WPA3)
            48 => rsn = Some(body),
            // IE 221 con OUI Microsoft = WPA (v1)
            221 if len >= 4 && body[..4] == [0x00, 0x50, 0xf2, 0x01] => wpa = true,
            _ => {}
        }
        i += 2 + len;
    }

    if let Some(body) = rsn {
        let (sae, psk, eap, owe) = rsn_akm_flags(body);
        return match (sae, psk, eap, owe, wpa) {
            // Modo transición: el AP anuncia WPA (v1) y RSN a la vez.
            (true, true, _, _, true) => "WPA/WPA2/WPA3",
            (true, true, _, _, false) => "WPA2/WPA3",
            (true, false, _, _, _) => "WPA3",
            (_, _, true, _, _) => "WPA2 Enterprise",
            (_, _, _, true, _) => "OWE",
            (_, _, _, _, true) => "WPA/WPA2",
            _ => "WPA2",
        };
    }

    if wpa {
        "WPA"
    } else if privacy {
        "WEP"
    } else {
        "abierta"
    }
}

/// Recorre los AKM suites del RSN IE: (SAE, PSK, 802.1X, OWE).
fn rsn_akm_flags(body: &[u8]) -> (bool, bool, bool, bool) {
    let (mut sae, mut psk, mut eap, mut owe) = (false, false, false, false);

    // version(2) + group cipher(4) + pairwise count(2) + pairwise suites
    let mut p = 2 + 4;
    if body.len() < p + 2 {
        return (sae, psk, eap, owe);
    }
    let pairwise = u16::from_le_bytes([body[p], body[p + 1]]) as usize;
    p += 2 + pairwise * 4;
    if body.len() < p + 2 {
        return (sae, psk, eap, owe);
    }
    let akms = u16::from_le_bytes([body[p], body[p + 1]]) as usize;
    p += 2;

    for k in 0..akms {
        let off = p + k * 4;
        if off + 4 > body.len() {
            break;
        }
        if body[off..off + 3] != [0x00, 0x0f, 0xac] {
            continue; // suite de otro OUI
        }
        match body[off + 3] {
            2 => psk = true,
            8 | 9 | 24 => sae = true,  // SAE, FT-SAE, SAE-EXT
            1 | 3 | 5 => eap = true,   // 802.1X, FT-802.1X, SHA256
            18 => owe = true,          // Opportunistic Wireless Encryption
            _ => {}
        }
    }

    (sae, psk, eap, owe)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Construye un RSN IE mínimo (version 1) con los AKM indicados.
    fn rsn_ie(akms: &[u8]) -> Vec<u8> {
        let mut body = vec![1, 0]; // version = 1
        body.extend_from_slice(&[0x00, 0x0f, 0xac, 4]); // group: CCMP
        body.extend_from_slice(&[1, 0]); // 1 pairwise
        body.extend_from_slice(&[0x00, 0x0f, 0xac, 4]); // CCMP
        body.extend_from_slice(&(akms.len() as u16).to_le_bytes());
        for akm in akms {
            body.extend_from_slice(&[0x00, 0x0f, 0xac, *akm]);
        }
        let mut ie = vec![48u8, body.len() as u8];
        ie.extend_from_slice(&body);
        ie
    }

    #[test]
    fn detecta_wpa2_wpa3_y_transicion() {
        assert_eq!(security_from_ies(&rsn_ie(&[2]), false), "WPA2");
        assert_eq!(security_from_ies(&rsn_ie(&[8]), false), "WPA3");
        assert_eq!(security_from_ies(&rsn_ie(&[2, 8]), false), "WPA2/WPA3");
        assert_eq!(security_from_ies(&rsn_ie(&[1]), false), "WPA2 Enterprise");
        assert_eq!(security_from_ies(&rsn_ie(&[18]), false), "OWE");
    }

    #[test]
    fn detecta_abierta_y_wep() {
        assert_eq!(security_from_ies(&[], false), "abierta");
        assert_eq!(security_from_ies(&[], true), "WEP");
        // IE de SSID no implica cifrado
        assert_eq!(security_from_ies(&[0, 4, b't', b'e', b's', b't'], false), "abierta");
    }

    #[test]
    fn detecta_wpa1_por_vendor_ie() {
        let ie = [221u8, 4, 0x00, 0x50, 0xf2, 0x01];
        assert_eq!(security_from_ies(&ie, true), "WPA");
    }

    #[test]
    fn detecta_modo_transicion_wpa_wpa2() {
        // WPA (vendor IE) + RSN con PSK: es lo que anuncia un FRITZ!Box.
        let mut ies = vec![221u8, 4, 0x00, 0x50, 0xf2, 0x01];
        ies.extend_from_slice(&rsn_ie(&[2]));
        assert_eq!(security_from_ies(&ies, true), "WPA/WPA2");
    }
}
