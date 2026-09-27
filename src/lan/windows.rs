//! Descubrimiento de vecinos en la LAN: sondeo ARP paralelo + tabla ARP del sistema.
//! Solo Windows.

#![cfg(windows)]

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GetIpNetTable, SendARP, GAA_FLAG_INCLUDE_GATEWAYS,
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, IP_ADAPTER_ADDRESSES_LH, MIB_IPNETROW_LH,
    MIB_IPNETTABLE,
};
use windows::Win32::Networking::WinSock::AF_INET;

use crate::model::LanHost;

/// Red local detectada: interfaz, IP, prefijo y puerta de enlace.
pub struct LocalNet {
    pub iface: String,
    pub ip: Ipv4Addr,
    pub prefix_len: u8,
    pub gateway: Option<Ipv4Addr>,
}

/// Descubre hosts de la LAN: sondeo ARP del /24 + entradas ya conocidas en la tabla ARP.
pub fn discover(net: &LocalNet) -> anyhow::Result<Vec<LanHost>> {
    let mut hosts = probe_sweep(net);
    hosts.extend(scan_hosts()?);

    // Fusionar por IP: preferimos el tipo de la tabla del sistema (Dynamic/Static)
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

/// Sondeo ARP paralelo sobre /24. Los dispositivos responden ARP aunque tengan
/// firewall ICMP, por lo que descubre más que un ping sweep.
pub fn probe_sweep(net: &LocalNet) -> Vec<LanHost> {
    // Solo barrimos /24 y prefijos mayores (redes típicas domésticas)
    if net.prefix_len < 24 || net.prefix_len >= 32 {
        return Vec::new();
    }

    let base = u32::from(net.ip) & (u32::MAX << (32 - net.prefix_len as u32));
    let candidates: Vec<Ipv4Addr> = (1..=254)
        .map(|i| Ipv4Addr::from(base + i))
        .collect();

    let found: Arc<Mutex<Vec<LanHost>>> = Arc::new(Mutex::new(Vec::new()));
    let queue = Arc::new(candidates);
    let next = Arc::new(AtomicUsize::new(0));
    // Un hilo por IP: SendARP bloquea varios segundos si nadie responde,
    // así que maximizamos el paralelismo para que el barrido tarda ~un timeout.
    let threads = queue.len().min(256);

    let mut handles = Vec::with_capacity(threads);
    for _ in 0..threads {
        let queue = Arc::clone(&queue);
        let found = Arc::clone(&found);
        let next = Arc::clone(&next);
        handles.push(thread::spawn(move || {
            while let Some(ip) = queue.get(next.fetch_add(1, Ordering::Relaxed)) {
                if let Some(mac) = arp_probe(*ip) {
                    found.lock().unwrap().push(LanHost {
                        ip: ip.to_string(),
                        mac,
                        kind: "ARP".to_string(),
                        vendor: String::new(), // se resuelve en model::snapshot()
                    });
                }
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }

    let mut result = found.lock().unwrap().clone();
    result.sort_by_key(|h| h.ip.parse::<Ipv4Addr>().ok());
    result
}

/// Envía una petición ARP directa y devuelve la MAC si hay respuesta.
fn arp_probe(ip: Ipv4Addr) -> Option<String> {
    unsafe {
        let dest = u32::from_le_bytes(ip.octets());
        let mut mac = [0u8; 6];
        let mut mac_len: u32 = 6;

        // SendARP devuelve 0 (NO_ERROR) si el host respondió
        let rc = SendARP(
            dest,
            0,
            mac.as_mut_ptr() as *mut _,
            &mut mac_len,
        );
        if rc == 0 && mac_len == 6 {
            Some(mac.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":"))
        } else {
            None
        }
    }
}

/// Red local: interfaz activa con IPv4, su prefijo y la puerta de enlace.
pub fn local_net() -> anyhow::Result<LocalNet> {
    unsafe {
        let flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_DNS_SERVER;
        let family = AF_INET.0 as u32;

        let mut size: u32 = 32 * 1024;
        let mut buf = vec![0u8; size as usize];
        let mut rc = GetAdaptersAddresses(
            family,
            flags,
            None,
            Some(buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
            &mut size,
        );
        if rc == 111 {
            // ERROR_BUFFER_OVERFLOW: reintentar con el tamaño real
            buf = vec![0u8; size as usize];
            rc = GetAdaptersAddresses(
                family,
                flags,
                None,
                Some(buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                &mut size,
            );
        }
        if rc != ERROR_SUCCESS.0 {
            anyhow::bail!("GetAdaptersAddresses falló con código {rc}");
        }

        let mut adapter = buf.as_mut_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !adapter.is_null() {
            let a = &*adapter;
            let is_up = a.OperStatus.0 == 1; // IfOperStatusUp
            let is_loopback = a.IfType == 24; // IF_TYPE_SOFTWARE_LOOPBACK
            if is_up && !is_loopback {
                // Primera dirección IPv4 unicast
                let mut uni = a.FirstUnicastAddress;
                while !uni.is_null() {
                    let sa = (*uni).Address.lpSockaddr;
                    if !sa.is_null() && (*sa).sa_family.0 == AF_INET.0 {
                        let octets = std::slice::from_raw_parts((sa as *const u8).add(4), 4);
                        let ip = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
                        let prefix_len = (*uni).OnLinkPrefixLength;

                        let iface = {
                            let mut len = 0usize;
                            while !a.FriendlyName.0.is_null()
                                && *a.FriendlyName.0.add(len) != 0
                            {
                                len += 1;
                            }
                            if a.FriendlyName.0.is_null() {
                                "desconocida".to_string()
                            } else {
                                String::from_utf16_lossy(std::slice::from_raw_parts(
                                    a.FriendlyName.0,
                                    len,
                                ))
                            }
                        };

                        // Primera puerta de enlace IPv4
                        let mut gw = None;
                        let mut g = a.FirstGatewayAddress;
                        while !g.is_null() {
                            let sa = (*g).Address.lpSockaddr;
                            if !sa.is_null() && (*sa).sa_family.0 == AF_INET.0 {
                                let octets =
                                    std::slice::from_raw_parts((sa as *const u8).add(4), 4);
                                gw =
                                    Some(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]));
                                break;
                            }
                            g = (*g).Next;
                        }

                        return Ok(LocalNet {
                            iface,
                            ip,
                            prefix_len,
                            gateway: gw,
                        });
                    }
                    uni = (*uni).Next;
                }
            }
            adapter = a.Next;
        }

        anyhow::bail!("No se encontró una interfaz con IPv4 activa")
    }
}

fn mac_to_string(mac: &[u8]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn ipnet_kind_to_string(kind: u32) -> &'static str {
    // MIB_IPNET_TYPE: 1=Other, 2=Invalid, 3=Dynamic, 4=Static
    match kind {
        4 => "Static",
        3 => "Dynamic",
        2 => "Invalid",
        _ => "Other",
    }
}

/// Lee la tabla ARP del sistema (incluye hosts vistos pasivamente).
pub fn scan_hosts() -> anyhow::Result<Vec<LanHost>> {
    let mut hosts: Vec<LanHost> = Vec::new();
    unsafe {
        let mut size: u32 = 15 * 1024;
        let mut buffer = vec![0u8; size as usize];
        let table = buffer.as_mut_ptr() as *mut MIB_IPNETTABLE;

        let rc = GetIpNetTable(Some(table), &mut size, false);
        if rc != ERROR_SUCCESS.0 {
            anyhow::bail!("GetIpNetTable falló con código {rc}");
        }

        let count = (*table).dwNumEntries as usize;
        let first = (*table).table.as_ptr();
        for i in 0..count {
            let row: &MIB_IPNETROW_LH = &*first.add(i);
            if row.dwAddr == 0 || row.dwPhysAddrLen == 0 {
                continue;
            }
            let kind = row.Anonymous.dwType;
            // 2 = Invalid: entradas incompletas (sin MAC real)
            if kind == 2 {
                continue;
            }
            let mac_bytes = &row.bPhysAddr[..row.dwPhysAddrLen as usize];
            // Filtrar broadcast/multicast (primer octeto impar) y MACs nulas
            if mac_bytes.is_empty() || mac_bytes[0] & 1 == 1 || mac_bytes.iter().all(|&b| b == 0) {
                continue;
            }
            hosts.push(LanHost {
                ip: Ipv4Addr::from(u32::from_be(row.dwAddr)).to_string(),
                mac: mac_to_string(mac_bytes),
                kind: ipnet_kind_to_string(kind).to_string(),
                vendor: String::new(), // se resuelve en model::snapshot()
            });
        }
    }

    hosts.sort_by_key(|h| h.ip.parse::<Ipv4Addr>().ok());
    hosts.dedup_by(|a, b| a.ip == b.ip);

    Ok(hosts)
}
