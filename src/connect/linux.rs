//! Conexión WiFi vía NetworkManager (D-Bus) y lectura de la PSK guardada.
//!
//! La contraseña viaja dentro de la llamada D-Bus a
//! `AddAndActivateConnection`, así que no aparece en `ps` ni en `/proc/*/cmdline`.

use std::collections::HashMap;
use std::process::Command;

use zbus::blocking::Connection;
use zbus::zvariant::{ObjectPath, Value};

const NM_DEST: &str = "org.freedesktop.NetworkManager";
const NM_PATH: &str = "/org/freedesktop/NetworkManager";
const NM_IFACE: &str = "org.freedesktop.NetworkManager";

/// Conecta a `ssid`. `password` = None para redes abiertas.
pub fn connect(ssid: &str, password: Option<&str>) -> anyhow::Result<()> {
    let mut connection: HashMap<&str, Value> = HashMap::new();
    connection.insert("id", Value::from(format!("fwmonitor {ssid}")));
    connection.insert("type", Value::from("802-11-wireless"));
    connection.insert("uuid", Value::from(random_uuid()?));

    let mut wifi: HashMap<&str, Value> = HashMap::new();
    // El SSID es un array de bytes (`ay`), no una cadena.
    wifi.insert("ssid", Value::from(ssid.as_bytes().to_vec()));
    wifi.insert("mode", Value::from("infrastructure"));

    let mut settings: HashMap<&str, HashMap<&str, Value>> = HashMap::new();
    settings.insert("connection", connection);

    if let Some(password) = password.filter(|p| !p.is_empty()) {
        let mut security: HashMap<&str, Value> = HashMap::new();
        security.insert("key-mgmt", Value::from("wpa-psk"));
        security.insert("psk", Value::from(password));
        // Enlazar la sección de seguridad desde la de la interfaz.
        wifi.insert("security", Value::from("802-11-wireless-security"));
        settings.insert("802-11-wireless-security", security);
    }

    let mut ipv4: HashMap<&str, Value> = HashMap::new();
    ipv4.insert("method", Value::from("auto"));
    settings.insert("ipv4", ipv4);

    let mut ipv6: HashMap<&str, Value> = HashMap::new();
    ipv6.insert("method", Value::from("auto"));
    settings.insert("ipv6", ipv6);

    settings.insert("802-11-wireless", wifi);

    let bus = Connection::system().map_err(|e| anyhow::anyhow!("D-Bus no disponible: {e}"))?;
    bus.call_method(
        Some(NM_DEST),
        NM_PATH,
        Some(NM_IFACE),
        "AddAndActivateConnection",
        &(
            settings,
            ObjectPath::try_from("/").expect("ruta raíz"),
            ObjectPath::try_from("/").expect("ruta raíz"),
        ),
    )
    .map_err(|e| {
        anyhow::anyhow!("NetworkManager rechazó la conexión a {ssid}: {e}")
    })?;

    Ok(())
}

/// Devuelve la contraseña guardada de la red WiFi activa.
/// Requiere que NetworkManager tenga la PSK y que polkit autorice el acceso a
/// secretos: sin privilegios devuelve un error explicativo.
pub fn reveal_password(ssid: &str) -> anyhow::Result<String> {
    let active = Command::new("nmcli")
        .args(["-t", "-f", "UUID,TYPE", "connection", "show", "--active"])
        .output()
        .map_err(|e| anyhow::anyhow!("No se pudo ejecutar nmcli: {e}"))?;

    let uuid = String::from_utf8_lossy(&active.stdout)
        .lines()
        .filter_map(|line| line.rsplit_once(':'))
        .find(|(_, ty)| *ty == "802-11-wireless")
        .map(|(uuid, _)| uuid.to_string())
        .ok_or_else(|| anyhow::anyhow!("No hay una conexión WiFi activa"))?;

    let out = Command::new("nmcli")
        .args([
            "--show-secrets",
            "-g",
            "802-11-wireless-security.psk",
            "connection",
            "show",
            &uuid,
        ])
        .output()
        .map_err(|e| anyhow::anyhow!("No se pudo ejecutar nmcli: {e}"))?;

    let psk = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if !out.status.success() || psk.is_empty() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        anyhow::bail!(
            "No se pudo leer la contraseña de {ssid}: {}",
            if stderr.is_empty() {
                "NetworkManager no la expone sin privilegios".to_string()
            } else {
                stderr
            }
        );
    }

    Ok(psk)
}

/// UUID v4 aleatorio sin dependencias (lo entrega el kernel).
fn random_uuid() -> anyhow::Result<String> {
    let uuid = std::fs::read_to_string("/proc/sys/kernel/random/uuid")
        .map_err(|e| anyhow::anyhow!("No se pudo generar UUID: {e}"))?
        .trim()
        .to_string();
    if uuid.is_empty() {
        anyhow::bail!("UUID vacío");
    }
    Ok(uuid)
}
