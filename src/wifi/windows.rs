//! Escaneo WiFi vía Native WiFi API (wlanapi.dll): lista de BSSIDs con RSSI y PHY.
//! Solo Windows.

#![cfg(windows)]

use std::ffi::c_void;
use std::time::Duration;

use windows::core::GUID;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WiFi::{
    wlan_intf_opcode_channel_number, wlan_intf_opcode_current_connection,
    wlan_interface_state_connected, WlanCloseHandle, WlanEnumInterfaces, WlanFreeMemory,
    WlanGetNetworkBssList, WlanOpenHandle, WlanQueryInterface, WlanScan, WLAN_BSS_ENTRY,
    WLAN_BSS_LIST, WLAN_CONNECTION_ATTRIBUTES, WLAN_INTERFACE_INFO_LIST,
};

use crate::model::{LinkInfo, WifiAp};
use crate::wifi::security_from_ies;

fn mac_to_string(mac: &[u8]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Convierte un SSID (bytes crudos) en String legible usando su longitud real.
fn ssid_to_string(ssid: &windows::Win32::NetworkManagement::WiFi::DOT11_SSID) -> String {
    let len = ssid.uSSIDLength as usize;
    String::from_utf8_lossy(&ssid.ucSSID[..len.min(32)]).to_string()
}

fn dot11_phy_to_string(phy: i32) -> String {
    // Valores reales de DOT11_PHY_TYPE según el SDK
    let base = match phy {
        1 => "FHSS",
        2 => "DSSS",
        3 => "IR",
        4 => "OFDM (11a)",
        5 => "HR-DSSS (11b)",
        6 => "ERP (11g)",
        7 => "HT (11n)",
        8 => "VHT (11ac)",
        9 => "DMG (60GHz)",
        10 => "HE (WiFi 6)",
        11 => "EHT (WiFi 7)",
        _ => return format!("PHY {phy}"),
    };
    base.to_string()
}

/// Sesión WLAN con los recursos liberados automáticamente en Drop.
struct WlanSession {
    handle: HANDLE,
    guid: GUID,
    iface_name: String,
    iface_list: *mut WLAN_INTERFACE_INFO_LIST,
}

impl Drop for WlanSession {
    fn drop(&mut self) {
        unsafe {
            if !self.iface_list.is_null() {
                WlanFreeMemory(self.iface_list as *const _);
            }
            if !self.handle.is_invalid() {
                WlanCloseHandle(self.handle, None);
            }
        }
    }
}

unsafe fn open_session() -> anyhow::Result<WlanSession> {
    unsafe {
        let mut negotiated = 0u32;
        let mut handle = Default::default();
        // dwClientVersion = 2: API WLAN de Vista+
        let rc = WlanOpenHandle(2, None, &mut negotiated, &mut handle);
        if rc != 0 {
            anyhow::bail!("WlanOpenHandle falló con código {rc}");
        }

        let mut iface_list_ptr: *mut WLAN_INTERFACE_INFO_LIST = std::ptr::null_mut();
        let rc = WlanEnumInterfaces(handle, None, &mut iface_list_ptr);
        if rc != 0 {
            WlanCloseHandle(handle, None);
            anyhow::bail!("WlanEnumInterfaces falló con código {rc}");
        }
        if (*iface_list_ptr).dwNumberOfItems == 0 {
            WlanFreeMemory(iface_list_ptr as *const _);
            WlanCloseHandle(handle, None);
            anyhow::bail!("No hay interfaces WiFi disponibles");
        }

        // Tomamos la primera interfaz (caso usual en portátiles)
        let iface = &*(*iface_list_ptr).InterfaceInfo.as_ptr();
        let iface_name = {
            let desc = &iface.strInterfaceDescription;
            let len = desc.iter().position(|&c| c == 0).unwrap_or(desc.len());
            String::from_utf16_lossy(&desc[..len])
        };

        Ok(WlanSession {
            handle,
            guid: iface.InterfaceGuid,
            iface_name,
            iface_list: iface_list_ptr,
        })
    }
}

/// Lanza un escaneo activo (asíncrono; el driver llena la caché de BSS).
unsafe fn trigger_scan(session: &WlanSession) -> anyhow::Result<()> {
    unsafe {
        let rc = WlanScan(session.handle, &session.guid, None, None, None);
        if rc != 0 {
            anyhow::bail!("WlanScan falló con código {rc}");
        }
        Ok(())
    }
}

/// Lee la caché de BSS del driver tras el escaneo.
unsafe fn collect_aps(session: &WlanSession) -> anyhow::Result<Vec<WifiAp>> {
    unsafe {
        let mut aps: Vec<WifiAp> = Vec::new();
        let mut bss_list_ptr: *mut WLAN_BSS_LIST = std::ptr::null_mut();
        let rc = WlanGetNetworkBssList(
            session.handle,
            &session.guid,
            None,                    // todos los SSIDs
            windows::Win32::NetworkManagement::WiFi::dot11_BSS_type_any,
            false,                   // incluir redes ocultas/inseguras
            None,
            &mut bss_list_ptr,
        );
        if rc != 0 {
            anyhow::bail!("WlanGetNetworkBssList falló con código {rc}");
        }

        let bss_list = &*bss_list_ptr;
        for i in 0..bss_list.dwNumberOfItems as usize {
            let entry: &WLAN_BSS_ENTRY = &*bss_list.wlanBssEntries.as_ptr().add(i);

            // WLAN_BSS_ENTRY guarda un blob de IEs a `ulIeOffset` bytes del
            // comienzo de la propia entrada.
            let ies = std::slice::from_raw_parts(
                (entry as *const WLAN_BSS_ENTRY as *const u8).add(entry.ulIeOffset as usize),
                entry.ulIeSize as usize,
            );
            let privacy = entry.usCapabilityInformation & 0x0010 != 0;

            aps.push(WifiAp {
                ssid: ssid_to_string(&entry.dot11Ssid),
                bssid: mac_to_string(&entry.dot11Bssid),
                rssi: entry.lRssi,
                phy: dot11_phy_to_string(entry.dot11BssPhyType.0),
                channel: freq_to_channel(entry.ulChCenterFrequency),
                vendor: String::new(), // se resuelve en model::snapshot()
                encryption: security_from_ies(ies, privacy).to_string(),
            });
        }
        WlanFreeMemory(bss_list_ptr as *const _);
        Ok(aps)
    }
}

/// Escanea la interfaz WiFi y devuelve (nombre_interfaz, lista_de_BSSIDs).
/// Fuerza un escaneo activo (WlanScan), espera a que el driver llene la caché y lee la lista.
pub fn scan_aps() -> anyhow::Result<(String, Vec<WifiAp>)> {
    unsafe {
        let session = open_session()?;

        // Forzar escaneo activo para datos frescos
        trigger_scan(&session)?;
        std::thread::sleep(Duration::from_millis(2500));

        let aps = collect_aps(&session)?;
        Ok((session.iface_name.clone(), aps))
    }
}

/// Ejecuta un cierre con el handle y el GUID de la interfaz WiFi abierta.
/// Lo usa `connect` para crear perfiles y asociar sin duplicar el setup.
pub(crate) fn with_wlan<T>(f: impl FnOnce(HANDLE, &GUID) -> T) -> anyhow::Result<T> {
    let session = unsafe { open_session()? };
    Ok(f(session.handle, &session.guid))
}

/// Estado del enlace de la interfaz conectada (None si no hay asociación).
pub fn link_info() -> anyhow::Result<Option<LinkInfo>> {
    unsafe {
        let session = open_session()?;

        let mut size = 0u32;
        let mut data: *mut c_void = std::ptr::null_mut();
        let rc = WlanQueryInterface(
            session.handle,
            &session.guid,
            wlan_intf_opcode_current_connection,
            None,
            &mut size,
            &mut data,
            None,
        );
        if rc != 0 || data.is_null() {
            return Ok(None);
        }

        let attrs = &*(data as *const WLAN_CONNECTION_ATTRIBUTES);
        let connected = attrs.isState == wlan_interface_state_connected;
        let ssid = if connected {
            ssid_to_string(&attrs.wlanAssociationAttributes.dot11Ssid)
        } else {
            String::new()
        };
        let assoc = &attrs.wlanAssociationAttributes;
        // Windows da calidad 0-100; aproximamos dBm como en la documentación.
        let rssi = (assoc.wlanSignalQuality as i32) / 2 - 100;
        let bssid = mac_to_string(&assoc.dot11Bssid);
        let tx_mbps = assoc.ulTxRate as f64 / 1000.0;
        let rx_mbps = assoc.ulRxRate as f64 / 1000.0;
        WlanFreeMemory(data);

        if !connected || ssid.is_empty() {
            return Ok(None);
        }

        // Canal actual: consulta aparte (devuelve un ULONG).
        let mut ch_size = 0u32;
        let mut ch_data: *mut c_void = std::ptr::null_mut();
        let mut channel = 0u8;
        if WlanQueryInterface(
            session.handle,
            &session.guid,
            wlan_intf_opcode_channel_number,
            None,
            &mut ch_size,
            &mut ch_data,
            None,
        ) == 0
            && !ch_data.is_null()
        {
            channel = (*(ch_data as *const u32)) as u8;
            WlanFreeMemory(ch_data);
        }

        Ok(Some(LinkInfo {
            ssid,
            bssid,
            rssi,
            channel,
            tx_mbps: Some(tx_mbps),
            rx_mbps: Some(rx_mbps),
            connected_secs: None,
            tx_retries: None,
        }))
    }
}

/// Frecuencia en kHz -> número de canal (2.4 y 5 GHz).
fn freq_to_channel(khz: u32) -> u8 {
    let mhz = khz / 1000;
    match mhz {
        2412..=2472 => ((mhz - 2412) / 5 + 1) as u8,
        2484 => 14,
        5160..=5885 => ((mhz - 5000) / 5) as u8,
        _ => 0,
    }
}
