//! Conexión WiFi y lectura de la clave guardada vía Native WiFi API.
//!
//! Crear el perfil con `WLAN_PROFILE_USER` no exige ejecutar como
//! administrador; sí lo exige leer la contraseña en claro
//! (`WLAN_PROFILE_GET_PLAINTEXT_KEY`).

use std::ffi::c_void;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::BOOL;
use windows::Win32::NetworkManagement::WiFi::{
    dot11_BSS_type_any, wlan_connection_mode_profile, WlanConnect, WlanFreeMemory, WlanGetProfile,
    WlanSetProfile, WLAN_CONNECTION_PARAMETERS, WLAN_PROFILE_GET_PLAINTEXT_KEY, WLAN_PROFILE_USER,
};

/// Conecta a `ssid` creando (o sobreescribiendo) un perfil de usuario.
pub fn connect(ssid: &str, password: Option<&str>) -> anyhow::Result<()> {
    let xml = profile_xml(ssid, password);
    let xml_wide = wide(&xml);
    let profile_wide = wide(ssid);

    crate::wifi::windows::with_wlan(|handle, guid| unsafe {
        let mut reason = 0u32;
        let rc = WlanSetProfile(
            handle,
            guid,
            WLAN_PROFILE_USER,
            PCWSTR(xml_wide.as_ptr()),
            PCWSTR::null(),
            BOOL(1), // sobreescribir si ya existe
            None,
            &mut reason,
        );
        if rc != 0 {
            return Err(anyhow::anyhow!(
                "WlanSetProfile falló con código {rc} (motivo {reason})"
            ));
        }

        let params = WLAN_CONNECTION_PARAMETERS {
            wlanConnectionMode: wlan_connection_mode_profile,
            strProfile: PCWSTR(profile_wide.as_ptr()),
            pDot11Ssid: std::ptr::null_mut(),
            pDesiredBssidList: std::ptr::null_mut(),
            dot11BssType: dot11_BSS_type_any,
            dwFlags: 0,
        };
        let rc = WlanConnect(handle, guid, &params, None);
        if rc != 0 {
            return Err(anyhow::anyhow!("WlanConnect falló con código {rc}"));
        }
        Ok(())
    })?
}

/// Devuelve la contraseña del perfil guardado de `ssid`.
/// Requiere elevación: sin ella Windows devuelve ACCESS_DENIED.
pub fn reveal_password(ssid: &str) -> anyhow::Result<String> {
    let name = wide(ssid);

    crate::wifi::windows::with_wlan(|handle, guid| unsafe {
        let mut xml_ptr = PWSTR(std::ptr::null_mut());
        let mut flags = WLAN_PROFILE_GET_PLAINTEXT_KEY;
        let mut granted = 0u32;

        let rc = WlanGetProfile(
            handle,
            guid,
            PCWSTR(name.as_ptr()),
            None,
            &mut xml_ptr,
            Some(&mut flags),
            Some(&mut granted),
        );
        if rc != 0 {
            return Err(anyhow::anyhow!(
                "WlanGetProfile falló con código {rc} (¿sin permisos de administrador?)"
            ));
        }

        let xml = pwstr_to_string(xml_ptr);
        WlanFreeMemory(xml_ptr.0 as *const c_void);

        extract_key_material(&xml).ok_or_else(|| {
            anyhow::anyhow!(
                "El perfil de {ssid} no guarda contraseña en claro (red abierta o perfil de empresa)"
            )
        })
    })?
}

/// Perfil WLAN en XML (WPA2-PSK/AES, o abierto si no hay contraseña).
fn profile_xml(ssid: &str, password: Option<&str>) -> String {
    let ssid = xml_escape(ssid);
    let security = match password.filter(|p| !p.is_empty()) {
        Some(pw) => format!(
            "<security><authEncryption>\
               <authentication>WPA2PSK</authentication>\
               <encryption>AES</encryption>\
               <useOneX>false</useOneX>\
             </authEncryption>\
             <sharedKey>\
               <keyType>passPhrase</keyType>\
               <protected>false</protected>\
               <keyMaterial>{}</keyMaterial>\
             </sharedKey></security>",
            xml_escape(pw)
        ),
        None => "<security><authEncryption>\
                   <authentication>open</authentication>\
                   <encryption>none</encryption>\
                   <useOneX>false</useOneX>\
                 </authEncryption></security>"
            .to_string(),
    };

    format!(
        r#"<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>{ssid}</name>
  <SSIDConfig><SSID><name>{ssid}</name></SSID></SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>auto</connectionMode>
  <MSM>{security}</MSM>
</WLANProfile>"#
    )
}

/// Extrae `<keyMaterial>` del XML del perfil (viene en claro con el flag).
fn extract_key_material(xml: &str) -> Option<String> {
    const OPEN: &str = "<keyMaterial>";
    const CLOSE: &str = "</keyMaterial>";
    let start = xml.find(OPEN)? + OPEN.len();
    let end = xml[start..].find(CLOSE)? + start;
    let key = xml[start..end].trim();
    if key.is_empty() {
        None
    } else {
        Some(key.to_string())
    }
}

/// PWSTR -> String sin depender de helpers del crate `windows`.
fn pwstr_to_string(p: PWSTR) -> String {
    if p.0.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    unsafe {
        while *p.0.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p.0, len))
    }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// String -> UTF-16 terminado en NUL.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
