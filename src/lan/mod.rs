//! Descubrimiento de vecinos en la LAN, multiplataforma.
//! Windows: SendARP + GetIpNetTable. Linux: sondeo ARP raw + /proc.

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{discover, local_net};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{discover, local_net};

use crate::model::LanHost;

/// Resultado del descubrimiento: hosts vistos y si el barrido activo pudo
/// ejecutarse. Sin `CAP_NET_RAW`/root en Linux solo hay caché ARP.
pub struct Discovery {
    pub hosts: Vec<LanHost>,
    pub sweep_ran: bool,
}

/// Nombre del host según NSS del sistema.
///
/// En Linux tira de `getent hosts`, que usa /etc/hosts, DNS, mDNS (nss-mdns)
/// y WINS si están instalados: no hace falta implementar los protocolos.
#[cfg(target_os = "linux")]
pub fn lookup_name(ip: &str) -> Option<String> {
    let out = std::process::Command::new("getent")
        .args(["hosts", ip])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    parse_getent_hosts(&String::from_utf8_lossy(&out.stdout), ip)
}

#[cfg(not(target_os = "linux"))]
pub fn lookup_name(_ip: &str) -> Option<String> {
    None
}

/// "192.168.1.5  mi-pc.lan" -> "mi-pc.lan" (ignora el eco de la IP).
fn parse_getent_hosts(stdout: &str, ip: &str) -> Option<String> {
    let line = stdout.lines().find(|l| !l.trim().is_empty())?;
    let mut fields = line.split_whitespace();
    let _addr = fields.next()?;
    let name = fields.next()?;
    if name.is_empty() || name == ip {
        None
    } else {
        Some(name.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsea_getent_hosts() {
        assert_eq!(
            parse_getent_hosts("192.168.1.5  mi-pc.lan\n", "192.168.1.5").as_deref(),
            Some("mi-pc.lan")
        );
        assert_eq!(parse_getent_hosts("", "10.0.0.1"), None);
        assert_eq!(
            parse_getent_hosts("10.0.0.1  10.0.0.1\n", "10.0.0.1"),
            None
        );
    }
}
