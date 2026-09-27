//! Descubrimiento de vecinos en la LAN para Linux.
//! - Red local: IP vía `connect()` UDP (sin paquetes), prefijo desde /proc/net/fib_trie
//!   y gateway/interfaz desde /proc/net/route.
//! - Sondeo ARP: sockets raw `AF_PACKET` (requiere CAP_NET_RAW; con sudo basta).
//! - Tabla ARP del sistema: /proc/net/arp.

use std::collections::HashMap;
use std::io::Read;
use std::net::{Ipv4Addr, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::model::LanHost;

/// Red local detectada: interfaz, IP, prefijo y puerta de enlace.
pub struct LocalNet {
    pub iface: String,
    pub ip: Ipv4Addr,
    pub prefix_len: u8,
    pub gateway: Option<Ipv4Addr>,
}

/// Red local: elige la ruta por defecto (la misma que usaría un paquete a Internet).
pub fn local_net() -> anyhow::Result<LocalNet> {
    // connect() UDP no envía nada pero fija la ruta: el kernel elige la interfaz
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.connect("8.8.8.8:80")?;
    let ip = match sock.local_addr()?.ip() {
        std::net::IpAddr::V4(ip) => ip,
        std::net::IpAddr::V6(_) => anyhow::bail!("La ruta por defecto no es IPv4"),
    };

    // Interfaz de la ruta por defecto (la que elegimos con el connect UDP)
    let iface = default_gateway_iface()
        .ok_or_else(|| anyhow::anyhow!("No hay ruta por defecto en /proc/net/route"))?;

    // Prefijo de la red en esa interfaz, desde /proc/net/fib_trie
    let prefix_len = prefix_for(ip).unwrap_or(24);

    Ok(LocalNet {
        iface,
        ip,
        prefix_len,
        gateway: default_gateway(),
    })
}

/// Interfaz de la ruta por defecto desde /proc/net/route.
fn default_gateway_iface() -> Option<String> {
    let content = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() >= 8 && cols[1] == "00000000" {
            return Some(cols[0].to_string());
        }
    }
    None
}

/// Gateway por defecto desde /proc/net/route (hex little-endian en x86).
fn default_gateway() -> Option<Ipv4Addr> {
    let content = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() >= 8 && cols[1] == "00000000" {
            let hex = u32::from_str_radix(cols[2], 16).ok()?;
            return Some(Ipv4Addr::from(u32::from_be(hex)));
        }
    }
    None
}

/// Prefijo de la red que contiene `ip`, según /proc/net/fib_trie.
/// Elige el prefijo más largo entre las rutas que contienen la IP.
fn prefix_for(ip: Ipv4Addr) -> Option<u8> {
    let content = std::fs::read_to_string("/proc/net/fib_trie").ok()?;
    let mut best: Option<u8> = None;

    for line in content.lines() {
        let line = line.trim();
        if !line.starts_with("|--") {
            continue;
        }
        // "|-- 192.168.100.0/24"
        if let Some(slash) = line.rfind('/') {
            let Ok(prefix) = line[slash + 1..].trim().parse::<u8>() else {
                continue;
            };
            let Ok(net) = line[3..slash].trim().parse::<Ipv4Addr>() else {
                continue;
            };
            if ip_in_subnet(ip, net, prefix) && best.is_none_or(|b| prefix > b) {
                best = Some(prefix);
            }
        }
    }
    best
}

fn ip_in_subnet(ip: Ipv4Addr, net: Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 || prefix > 32 {
        return false;
    }
    let mask = if prefix == 32 { u32::MAX } else { u32::MAX << (32 - prefix as u32) };
    (u32::from(ip) & mask) == (u32::from(net) & mask)
}

/// Descubre hosts de la LAN: sondeo ARP del /24 + entradas ya conocidas en /proc.
pub fn discover(net: &LocalNet) -> anyhow::Result<Vec<LanHost>> {
    let mut hosts = probe_sweep(net);
    hosts.extend(read_proc_arp()?);

    hosts.sort_by_key(|h| h.ip.parse::<Ipv4Addr>().ok());
    hosts.dedup_by(|a, b| a.ip == b.ip);

    // Etiquetas útiles: puerta de enlace y este equipo
    for h in &mut hosts {
        if let Ok(ip) = h.ip.parse::<Ipv4Addr>() {
            if Some(ip) == net.gateway {
                h.kind = "GW".to_string();
            } else if ip == net.ip {
                h.kind = "Local".to_string();
            }
        }
    }
    Ok(hosts)
}

/// Sondeo ARP paralelo sobre /24 con sockets AF_PACKET.
pub fn probe_sweep(net: &LocalNet) -> Vec<LanHost> {
    if net.prefix_len < 24 || net.prefix_len >= 32 {
        return Vec::new();
    }

    // MAC de nuestra interfaz para el campo sender del ARP
    let Some(our_mac) = read_iface_mac(&net.iface) else {
        return Vec::new();
    };

    let base = u32::from(net.ip) & (u32::MAX << (32 - net.prefix_len as u32));
    let candidates: Vec<Ipv4Addr> = (1..=254)
        .map(|i| Ipv4Addr::from(base + i))
        .collect();

    let found: Arc<Mutex<HashMap<Ipv4Addr, String>>> = Arc::new(Mutex::new(HashMap::new()));
    let queue = Arc::new(candidates);
    let next = Arc::new(AtomicUsize::new(0));
    let threads = queue.len().min(64);

    let mut handles = Vec::with_capacity(threads);
    for _ in 0..threads {
        let queue = Arc::clone(&queue);
        let found = Arc::clone(&found);
        let next = Arc::clone(&next);
        let our_mac = our_mac.clone();
        let iface = net.iface.clone();
        let our_ip = net.ip;
        handles.push(thread::spawn(move || {
            while let Some(ip) = queue.get(next.fetch_add(1, Ordering::Relaxed)) {
                if let Some(mac) = arp_probe(&iface, our_ip, &our_mac, *ip) {
                    found.lock().unwrap().insert(*ip, mac);
                }
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }

    let result = found.lock().unwrap().clone();
    let mut hosts: Vec<LanHost> = result
        .into_iter()
        .map(|(ip, mac)| LanHost {
            ip: ip.to_string(),
            mac,
            kind: "ARP".to_string(),
            vendor: String::new(), // se resuelve en model::snapshot()
        })
        .collect();
    hosts.sort_by_key(|h| h.ip.parse::<Ipv4Addr>().ok());
    hosts
}

fn read_iface_mac(iface: &str) -> Option<String> {
    let path = format!("/sys/class/net/{iface}/address");
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

/// Envía una petición ARP por AF_PACKET y espera la respuesta.
/// Devuelve la MAC del peer si responde.
fn arp_probe(iface: &str, our_ip: Ipv4Addr, our_mac: &str, target: Ipv4Addr) -> Option<String> {
    let mut mac_bytes = [0u8; 6];
    for (i, part) in our_mac.split(':').enumerate().take(6) {
        mac_bytes[i] = u8::from_str_radix(part, 16).ok()?;
    }

    let iface_index = get_iface_index(iface)?;

    // Trama Ethernet + ARP (RFC 826), destinada a broadcast
    let mut frame = [0u8; 42];
    frame[0..6].copy_from_slice(&[0xff; 6]); // destino: broadcast
    frame[6..12].copy_from_slice(&mac_bytes); // origen: nuestra MAC
    frame[12..14].copy_from_slice(&[0x08, 0x06]); // EtherType: ARP
    frame[14..16].copy_from_slice(&[0x00, 0x01]); // HTYPE: Ethernet
    frame[16..18].copy_from_slice(&[0x00, 0x01]); // PTYPE: IPv4
    frame[18] = 6; // HLEN
    frame[19] = 4; // PLEN
    frame[20..22].copy_from_slice(&[0x00, 0x01]); // OPER: request
    frame[22..28].copy_from_slice(&mac_bytes); // SHA
    frame[28..32].copy_from_slice(&our_ip.octets()); // SPA
    frame[32..38].copy_from_slice(&[0xff; 6]); // THA
    frame[38..42].copy_from_slice(&target.octets()); // TPA

    unsafe {
        // ETH_P_ARP en network byte order
        let fd = libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_ARP as u16).to_be() as i32,
        );
        if fd < 0 {
            return None;
        }
        let _guard = FdGuard(fd);

        let sockaddr = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: (libc::ETH_P_ARP as u16).to_be(),
            sll_ifindex: iface_index,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 6,
            sll_addr: [0; 8],
        };
        let rc = libc::bind(
            fd,
            &sockaddr as *const libc::sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as u32,
        );
        if rc != 0 {
            return None;
        }

        let sent = libc::send(fd, frame.as_ptr() as *const _, frame.len(), 0);
        if sent < 0 {
            return None;
        }

        // Esperar respuesta (poll con timeout de 1s)
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        if libc::poll(&mut pfd, 1, 1000) <= 0 {
            return None;
        }

        let mut buf = [0u8; 128];
        let n = libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0);
        if n < 42 {
            return None;
        }
        // Ethernet(14) + ARP: SHA en offset 22, SPA en offset 28
        let spa = Ipv4Addr::new(buf[14 + 14], buf[14 + 15], buf[14 + 16], buf[14 + 17]);
        if spa == target {
            let reply_sha = &buf[14 + 8..14 + 14];
            return Some(
                reply_sha
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(":"),
            );
        }
        None
    }
}

struct FdGuard(i32);
impl Drop for FdGuard {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

/// Índice de la interfaz vía ioctl SIOCGIFINDEX.
fn get_iface_index(iface: &str) -> Option<i32> {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            return None;
        }
        let _guard = FdGuard(fd);

        let mut ifr: libc::ifreq = std::mem::zeroed();
        let bytes = iface.as_bytes();
        if bytes.len() >= ifr.ifr_name.len() {
            return None;
        }
        for (dst, &b) in ifr.ifr_name.iter_mut().zip(bytes) {
            *dst = b as i8;
        }

        // SIOCGIFINDEX en Linux/x86-64 y aarch64
        const SIOCGIFINDEX: libc::c_ulong = 0x8933;
        if libc::ioctl(fd, SIOCGIFINDEX, &mut ifr) != 0 {
            return None;
        }
        Some(ifr.ifr_ifru.ifru_ifindex)
    }
}

/// Lee /proc/net/arp (tabla ARP del sistema, incluye hosts vistos pasivamente).
fn read_proc_arp() -> anyhow::Result<Vec<LanHost>> {
    let mut content = String::new();
    std::fs::File::open("/proc/net/arp")?.read_to_string(&mut content)?;

    let mut hosts = Vec::new();
    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 6 {
            continue;
        }
        let ip = cols[0];
        let mac = cols[3].to_lowercase();
        let flags = cols[2];
        // 0x2 = ATF_COM: entrada completa con MAC resuelta
        if flags != "0x2" || mac == "00:00:00:00:00:00" {
            continue;
        }
        if let Ok(ip_parsed) = ip.parse::<Ipv4Addr>() {
            if ip_parsed.is_broadcast() || ip_parsed.is_multicast() {
                continue;
            }
        }
        hosts.push(LanHost {
            ip: ip.to_string(),
            mac,
            kind: "Dynamic".to_string(),
            vendor: String::new(), // se resuelve en model::snapshot()
        });
    }

    hosts.sort_by_key(|h| h.ip.parse::<Ipv4Addr>().ok());
    hosts.dedup_by(|a, b| a.ip == b.ip);
    Ok(hosts)
}
