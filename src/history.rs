//! Historial de clientes entre snapshots: marca hosts como nuevos, normales o
//! ausentes (siguen visibles un tiempo por si vuelven a aparecer).

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::model::LanHost;

/// Estado de presencia de un host respecto a los snapshots anteriores.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Presence {
    /// Visto por primera vez, o volvió tras estar ausente
    New,
    /// Ya estaba presente en el snapshot anterior
    Normal,
    /// Estaba antes y no aparece en este snapshot (se mantiene un TTL)
    Gone,
}

/// Un host con su estado de presencia, para mostrar en la TUI.
#[derive(Clone, Debug)]
pub struct TrackedHost {
    pub host: LanHost,
    pub state: Presence,
}

struct Entry {
    host: LanHost,
    last_seen: Instant,
    /// Estaba ausente en el último snapshot procesado
    gone: bool,
}

/// Registro de presencia de los hosts de la LAN.
pub struct ClientHistory {
    /// clave = "mac:<mac>" (identidad estable) o "ip:<ip>" si no hay MAC
    seen: HashMap<String, Entry>,
    /// Cuánto tiempo seguimos listando un host ausente
    ttl: Duration,
    /// El primer snapshot es la línea base: nada se marca como nuevo
    initialized: bool,
}

impl Default for ClientHistory {
    fn default() -> Self {
        Self::new(Duration::from_secs(300))
    }
}

impl ClientHistory {
    pub fn new(ttl: Duration) -> Self {
        Self {
            seen: HashMap::new(),
            ttl,
            initialized: false,
        }
    }

    /// Procesa un snapshot y devuelve la vista para la TUI:
    /// activos ordenados por IP primero, ausentes al final.
    /// `now` se inyecta para poder testear sin esperas reales.
    pub fn update_at(&mut self, hosts: &[LanHost], now: Instant) -> Vec<TrackedHost> {
        let first_run = !std::mem::replace(&mut self.initialized, true);
        let present_keys: HashSet<String> = hosts.iter().map(host_key).collect();

        let mut tracked: Vec<TrackedHost> = Vec::with_capacity(self.seen.len() + hosts.len());

        // 1) Presentes: nuevo si es la primera vez que lo vemos o si venía de
        //    ausente; normal si ya estaba presente en el snapshot anterior.
        for host in hosts {
            let key = host_key(host);
            let state = match self.seen.get_mut(&key) {
                Some(entry) => {
                    let was_gone = entry.gone;
                    entry.host = host.clone();
                    entry.last_seen = now;
                    entry.gone = false;
                    if !first_run && was_gone {
                        Presence::New
                    } else {
                        Presence::Normal
                    }
                }
                None => {
                    self.seen.insert(
                        key,
                        Entry {
                            host: host.clone(),
                            last_seen: now,
                            gone: false,
                        },
                    );
                    if first_run {
                        Presence::Normal
                    } else {
                        Presence::New
                    }
                }
            };
            tracked.push(TrackedHost {
                host: host.clone(),
                state,
            });
        }

        // 2) Ausentes: registrados que no aparecen en este snapshot. Se listan
        //    como Gone hasta que superen el TTL; después se olvidan.
        let ttl = self.ttl;
        let mut expired = Vec::new();
        for (key, entry) in self.seen.iter_mut() {
            if present_keys.contains(key) {
                continue;
            }
            entry.gone = true;
            if now.duration_since(entry.last_seen) > ttl {
                expired.push(key.clone());
            } else {
                tracked.push(TrackedHost {
                    host: entry.host.clone(),
                    state: Presence::Gone,
                });
            }
        }
        for key in expired {
            self.seen.remove(&key);
        }

        // 3) Orden: activos por IP, ausentes al final (también por IP)
        tracked.sort_by_key(|t| (t.state == Presence::Gone, t.ip_key()));
        tracked
    }

    /// Versión de producción que usa el reloj real.
    pub fn update(&mut self, hosts: &[LanHost]) -> Vec<TrackedHost> {
        self.update_at(hosts, Instant::now())
    }
}

fn host_key(host: &LanHost) -> String {
    if host.mac.is_empty() {
        format!("ip:{}", host.ip)
    } else {
        format!("mac:{}", host.mac.to_lowercase())
    }
}

impl TrackedHost {
    fn ip_key(&self) -> Option<Ipv4Addr> {
        self.host.ip.parse::<Ipv4Addr>().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(ip: &str, mac: &str) -> LanHost {
        LanHost {
            ip: ip.to_string(),
            mac: mac.to_string(),
            kind: "ARP".to_string(),
            vendor: String::new(),
        }
    }

    fn state_of<'a>(view: &'a [TrackedHost], mac: &str) -> Presence {
        view.iter()
            .find(|t| t.host.mac == mac)
            .map(|t| t.state)
            .expect("host no encontrado en la vista")
    }

    #[test]
    fn primer_snapshot_es_linea_base() {
        let mut h = ClientHistory::new(Duration::from_secs(60));
        let t0 = Instant::now();
        let view = h.update_at(&[host("192.168.1.1", "aa:aa:aa:aa:aa:aa")], t0);
        assert_eq!(state_of(&view, "aa:aa:aa:aa:aa:aa"), Presence::Normal);
    }

    #[test]
    fn host_nuevo_en_segundo_snapshot() {
        let mut h = ClientHistory::new(Duration::from_secs(60));
        let t0 = Instant::now();
        h.update_at(&[host("192.168.1.1", "aa:aa:aa:aa:aa:aa")], t0);

        let t1 = t0 + Duration::from_secs(5);
        let view = h.update_at(
            &[
                host("192.168.1.1", "aa:aa:aa:aa:aa:aa"),
                host("192.168.1.50", "bb:bb:bb:bb:bb:bb"),
            ],
            t1,
        );
        assert_eq!(state_of(&view, "aa:aa:aa:aa:aa:aa"), Presence::Normal);
        assert_eq!(state_of(&view, "bb:bb:bb:bb:bb:bb"), Presence::New);
    }

    #[test]
    fn host_ausente_y_reaparece_como_nuevo() {
        let mut h = ClientHistory::new(Duration::from_secs(60));
        let t0 = Instant::now();
        h.update_at(&[host("192.168.1.1", "aa:aa:aa:aa:aa:aa")], t0);

        // Desaparece
        let t1 = t0 + Duration::from_secs(5);
        let view = h.update_at(&[], t1);
        assert_eq!(state_of(&view, "aa:aa:aa:aa:aa:aa"), Presence::Gone);

        // Vuelve
        let t2 = t1 + Duration::from_secs(5);
        let view = h.update_at(&[host("192.168.1.1", "aa:aa:aa:aa:aa:aa")], t2);
        assert_eq!(state_of(&view, "aa:aa:aa:aa:aa:aa"), Presence::New);
    }

    #[test]
    fn ausente_se_elimina_tras_ttl() {
        let mut h = ClientHistory::new(Duration::from_millis(100));
        let t0 = Instant::now();
        h.update_at(&[host("192.168.1.1", "aa:aa:aa:aa:aa:aa")], t0);

        let t1 = t0 + Duration::from_millis(50);
        let view = h.update_at(&[], t1);
        assert_eq!(state_of(&view, "aa:aa:aa:aa:aa:aa"), Presence::Gone);

        let t2 = t0 + Duration::from_millis(150);
        let view = h.update_at(&[], t2);
        assert!(view.is_empty(), "el host ausente debería caducar tras el TTL");
    }

    #[test]
    fn cambia_de_ip_misma_mac_mantiene_identidad() {
        let mut h = ClientHistory::new(Duration::from_secs(60));
        let t0 = Instant::now();
        h.update_at(&[host("192.168.1.1", "aa:aa:aa:aa:aa:aa")], t0);

        // Misma MAC, otra IP: mismo host, sin duplicado
        let t1 = t0 + Duration::from_secs(5);
        let view = h.update_at(&[host("192.168.1.2", "aa:aa:aa:aa:aa:aa")], t1);
        assert_eq!(view.len(), 1);
        assert_eq!(state_of(&view, "aa:aa:aa:aa:aa:aa"), Presence::Normal);
        assert_eq!(view[0].host.ip, "192.168.1.2");
    }

    #[test]
    fn ausentes_al_final_y_activos_por_ip() {
        let mut h = ClientHistory::new(Duration::from_secs(60));
        let t0 = Instant::now();
        h.update_at(
            &[
                host("192.168.1.30", "cc:cc:cc:cc:cc:cc"),
                host("192.168.1.20", "bb:bb:bb:bb:bb:bb"),
            ],
            t0,
        );

        let t1 = t0 + Duration::from_secs(5);
        let view = h.update_at(
            &[
                host("192.168.1.10", "aa:aa:aa:aa:aa:aa"),
                host("192.168.1.20", "bb:bb:bb:bb:bb:bb"),
            ],
            t1,
        );

        // Activos (10, 20) primero por IP; ausente (30) al final
        assert_eq!(view[0].host.ip, "192.168.1.10");
        assert_eq!(view[1].host.ip, "192.168.1.20");
        assert_eq!(view[2].host.mac, "cc:cc:cc:cc:cc:cc");
        assert_eq!(view[2].state, Presence::Gone);
    }
}
