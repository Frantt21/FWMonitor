//! Modo monitor 802.11 para Linux: captura pasiva de beacons y tráfico del aire.
//!
//! Flujo (validado en Arch con iwlwifi / Intel AX200):
//! 1. `CmdSetInterface` + `AttrIftype=IftypeMonitor` — convertir la interfaz a monitor.
//! 2. `CmdSetWiphy` + `AttrWiphyFreq` + `AttrWiphyChannelType` — channel hopping.
//! 3. Captura por `AF_PACKET` (ETH_P_ALL) saltando el header radiotap de mac80211.
//! 4. Al salir (normal, error o Ctrl+C) se restaura managed y se reconecta NM.
//!
//! Requiere root (o CAP_NET_ADMIN): en iwlwifi no se puede combinar
//! managed+monitor, así que el modo monitor es una actividad exclusiva.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use neli::consts::nl::{NlmF, NlmFFlags, Nlmsg};
use neli::consts::socket::NlFamily;
use neli::genl::{Genlmsghdr, Nlattr};
use neli::nl::{NlPayload, Nlmsghdr};
use neli::socket::NlSocketHandle;
use neli::types::{Buffer, GenlBuffer};
use neli_wifi::{
    Nl80211Attr, Nl80211ChannelType, Nl80211Cmd, Nl80211Iftype, NL_80211_GENL_VERSION,
};

use crate::model::WifiAp;
use crate::wifi::linux::{ifname_to_string, parse_ies};

// ---------------------------------------------------------------------------
// nl80211: set interface type + set channel
// ---------------------------------------------------------------------------

/// Envía un comando genérico nl80211 con ACK y propaga el error del kernel.
fn nl80211_do(
    sock: &mut NlSocketHandle,
    family_id: u16,
    cmd: Nl80211Cmd,
    attrs: GenlBuffer<Nl80211Attr, Buffer>,
) -> anyhow::Result<()> {
    let msghdr = Genlmsghdr::<Nl80211Cmd, Nl80211Attr>::new(cmd, NL_80211_GENL_VERSION, attrs);
    let nlhdr = Nlmsghdr::new(
        None,
        family_id,
        NlmFFlags::new(&[NlmF::Request, NlmF::Ack]),
        None,
        None,
        NlPayload::Payload(msghdr),
    );
    sock.send(nlhdr)?;

    for response in sock.iter::<Nlmsg, Genlmsghdr<Nl80211Cmd, Nl80211Attr>>(false) {
        let msg = response.map_err(|e| anyhow::anyhow!("netlink recv: {e}"))?;
        match &msg.nl_payload {
            NlPayload::Ack(_) => return Ok(()),
            NlPayload::Err(e) => anyhow::bail!("kernel rechazó {cmd:?}: error {}", e.error),
            _ => continue,
        }
    }
    anyhow::bail!("Sin respuesta del kernel para {cmd:?}");
}

/// Convierte la interfaz a modo monitor (requiere interface DOWN).
fn set_monitor_type(
    sock: &mut NlSocketHandle,
    family_id: u16,
    ifindex: i32,
) -> anyhow::Result<()> {
    // OJO: la policy del kernel define NL80211_ATTR_IFTYPE como NLA_U32.
    // neli serializa los enums neli-wifi como u16 (payload de 2 bytes) y el
    // validador netlink lo rechaza con -ERANGE (errno 34, "Numerical result
    // out of range") antes de llegar al driver. Hay que enviar el valor como u32.
    let mut attrs = GenlBuffer::new();
    attrs.push(
        Nlattr::new(false, false, Nl80211Attr::AttrIfindex, ifindex as u32)
            .map_err(|e| anyhow::anyhow!("Nlattr ifindex: {e}"))?,
    );
    attrs.push(
        Nlattr::new(false, false, Nl80211Attr::AttrIftype, u32::from(u16::from(Nl80211Iftype::IftypeMonitor)))
            .map_err(|e| anyhow::anyhow!("Nlattr iftype: {e}"))?,
    );
    nl80211_do(sock, family_id, Nl80211Cmd::CmdSetInterface, attrs)
}

/// Devuelve la interfaz a modo gestionado (station).
fn set_managed_type(
    sock: &mut NlSocketHandle,
    family_id: u16,
    ifindex: i32,
) -> anyhow::Result<()> {
    let mut attrs = GenlBuffer::new();
    attrs.push(
        Nlattr::new(false, false, Nl80211Attr::AttrIfindex, ifindex as u32)
            .map_err(|e| anyhow::anyhow!("Nlattr ifindex: {e}"))?,
    );
    attrs.push(
        Nlattr::new(false, false, Nl80211Attr::AttrIftype, u32::from(u16::from(Nl80211Iftype::IftypeStation)))
            .map_err(|e| anyhow::anyhow!("Nlattr iftype: {e}"))?,
    );
    nl80211_do(sock, family_id, Nl80211Cmd::CmdSetInterface, attrs)
}

/// Fija la frecuencia/canal del phy (CmdSetWiphy: afecta a toda la tarjeta,
/// igual que `iw dev X set channel` con la interfaz en monitor).
fn set_channel(
    sock: &mut NlSocketHandle,
    family_id: u16,
    ifindex: i32,
    channel: u8,
) -> anyhow::Result<()> {
    let freq = match channel {
        14 => 2484,
        1..=13 => 2412 + (channel as u32 - 1) * 5,
        32..=177 => 5000 + channel as u32 * 5,
        _ => anyhow::bail!("Canal {channel} no soportado"),
    };
    let mut attrs = GenlBuffer::new();
    attrs.push(
        Nlattr::new(false, false, Nl80211Attr::AttrIfindex, ifindex as u32)
            .map_err(|e| anyhow::anyhow!("Nlattr ifindex: {e}"))?,
    );
    attrs.push(
        Nlattr::new(false, false, Nl80211Attr::AttrWiphyFreq, freq)
            .map_err(|e| anyhow::anyhow!("Nlattr freq: {e}"))?,
    );
    attrs.push(
        // Misma razón que AttrIftype: la policy espera NLA_U32.
        Nlattr::new(false, false, Nl80211Attr::AttrWiphyChannelType, u32::from(u16::from(Nl80211ChannelType::ChanHt20)))
            .map_err(|e| anyhow::anyhow!("Nlattr chan type: {e}"))?,
    );
    nl80211_do(sock, family_id, Nl80211Cmd::CmdSetWiphy, attrs)
}

// ---------------------------------------------------------------------------
// Radiotap + parsing de frames 802.11
// ---------------------------------------------------------------------------

/// Info extraída del header radiotap (v0, little endian, sin padding por alineación).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RadiotapInfo {
    /// dBm del campo "antenna signal" (bit 5), si venía
    pub rssi: i8,
    /// Bit 14 del bitmap de flags: frame con FCS incorrecto
    pub bad_fcs: bool,
    /// Bit 11 de flags: frame corto/fallido (bad PLCP)
    pub bad_plcp: bool,
    /// Frecuencia en MHz del campo "channel" (bit 3), si venía
    pub freq_mhz: u16,
}

/// Detecta si el buffer empieza con header radiotap y lo salta.
/// Devuelve (info, offset donde empieza el frame 802.11).
/// Si no parece radiotap, devuelve (default, 0): mac80211 siempre lo antepone,
/// pero así el parser tolera capturas sin radiotap (p. ej. tests).
///
/// Soporta bitmaps extendidos (iwlwifi/AX200 los usa: el RSSI puede ir en el
/// segundo word). El walk es el estándar radiotap: los campos presentes se
/// recorren en orden de bit, cada uno con su alineación y tamaño.
pub fn parse_radiotap(pkt: &[u8]) -> (RadiotapInfo, usize) {
    let default = RadiotapInfo::default();
    if pkt.len() < 8 || pkt[0] != 0 || pkt[1] != 0 {
        return (default, 0);
    }
    let rt_len = u16::from_le_bytes([pkt[2], pkt[3]]) as usize;
    if !(8..=600).contains(&rt_len) || rt_len > pkt.len() {
        return (default, 0);
    }

    // Words del bitmap (el bit 31 marca "hay otro word detrás").
    let mut words: Vec<u32> = Vec::new();
    let mut w_off = 4;
    loop {
        if w_off + 4 > rt_len || words.len() >= 8 {
            break;
        }
        let w = u32::from_le_bytes(pkt[w_off..w_off + 4].try_into().unwrap());
        words.push(w);
        w_off += 4;
        if w & (1 << 31) == 0 {
            break;
        }
    }

    let mut info = RadiotapInfo::default();
    // Los campos empiezan tras el último word del bitmap.
    let mut off = 8 + (words.len() - 1) * 4;
    let take = |off: usize, size: usize| -> Option<&[u8]> {
        if off + size <= rt_len {
            Some(&pkt[off..off + size])
        } else {
            None
        }
    };
    let align_to = |off: &mut usize, a: usize| {
        let r = *off % a;
        if r != 0 {
            *off += a - r;
        }
    };

    'outer: for w in &words {
        for bit in 0..31 {
            if w & (1 << bit) == 0 {
                continue;
            }
            match bit {
                0 => {
                    align_to(&mut off, 8);
                    off += 8; // TSFT u64
                }
                1 => {
                    if let Some(b) = take(off, 1) {
                        info.bad_fcs = b[0] & 0x40 != 0;
                        info.bad_plcp = b[0] & 0x20 != 0;
                    }
                    off += 1; // FLAGS u8
                }
                2 => off += 1, // RATE u8
                3 => {
                    align_to(&mut off, 2);
                    if let Some(b) = take(off, 2) {
                        info.freq_mhz = u16::from_le_bytes([b[0], b[1]]);
                    }
                    off += 4; // CHANNEL u16 freq + u16 flags
                }
                4 => {
                    align_to(&mut off, 2);
                    off += 2; // FHSS (obsoleto)
                }
                5 => {
                    if let Some(b) = take(off, 1) {
                        info.rssi = b[0] as i8;
                    }
                    off += 1; // DBM_ANTSIGNAL s8
                }
                6 => off += 1, // DBM_ANTNOISE s8
                7..=9 => {
                    align_to(&mut off, 2);
                    off += 2; // u16 legacy (calidad/atenuación)
                }
                10 => off += 1, // DBM_TX_POWER s8
                11 => off += 1, // ANTENNA u8
                12 | 13 => off += 1,
                14 | 15 => {
                    align_to(&mut off, 2);
                    off += 2; // RX/TX FLAGS u16
                }
                16 | 17 => off += 1, // retries u8
                19 => off += 3,      // MCS: known + flags + mcs (u8 x3)
                20 => {
                    align_to(&mut off, 4);
                    off += 4; // A-MPDU status u32
                }
                _ => break 'outer, // VHT/HE/…: tamaño variable; ya leímos lo útil
            }
        }
    }

    (info, rt_len)
}

/// Tipo de frame 802.11 tras quitar radiotap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameKind {
    Beacon,
    ProbeResp,
    ProbeReq,
    Data,
    Control,
    Other,
}

/// Datos útiles extraídos de un frame capturado en monitor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameInfo {
    pub kind: FrameKind,
    /// addr3 del MAC header (BSSID en frames de gestión)
    pub bssid: String,
    /// SSID de beacons/probe-responses (IE 0)
    pub ssid: Option<String>,
    /// RSSI del radiotap (0 = no disponible)
    pub rssi: i32,
    pub bad_fcs: bool,
    /// Frecuencia de recepción del radiotap (0 = no disponible)
    pub freq_mhz: u16,
}

/// Clasifica un frame capturado (con o sin radiotap delante).
pub fn classify_frame(pkt: &[u8]) -> FrameInfo {
    let (rt, rt_len) = parse_radiotap(pkt);
    let f = &pkt[rt_len.min(pkt.len())..];
    let mut info = FrameInfo {
        kind: FrameKind::Other,
        bssid: String::new(),
        ssid: None,
        rssi: rt.rssi as i32,
        bad_fcs: rt.bad_fcs,
        freq_mhz: rt.freq_mhz,
    };
    if f.len() < 24 {
        return info;
    }

    // Frame Control (little endian): bits 0-1 versión, 2-3 tipo, 4-7 subtype
    let fc = u16::from_le_bytes([f[0], f[1]]);
    let ftype = (fc >> 2) & 0x3;
    let subtype = (fc >> 4) & 0xF;
    info.bssid = f[16..22]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":");

    match (ftype, subtype) {
        (0, 8) => {
            // Beacon: MAC header (24) + fixed params (12) -> IEs en el byte 36
            info.kind = FrameKind::Beacon;
            if f.len() > 36 {
                let (ssid, _) = parse_ies(&f[36..]);
                info.ssid = ssid;
            }
        }
        (0, 5) => {
            info.kind = FrameKind::ProbeResp;
            if f.len() > 36 {
                let (ssid, _) = parse_ies(&f[36..]);
                info.ssid = ssid;
            }
        }
        (0, 4) => info.kind = FrameKind::ProbeReq,
        (1, _) => info.kind = FrameKind::Control,
        (2, _) => info.kind = FrameKind::Data,
        _ => info.kind = FrameKind::Other,
    }
    info
}

// ---------------------------------------------------------------------------
// Tabla en vivo de APs vistos en monitor
// ---------------------------------------------------------------------------

/// AP visto durante la captura monitor, con métricas agregadas.
#[derive(Clone, Debug)]
pub struct LiveAp {
    pub ssid: String,
    pub bssid: String,
    /// Último RSSI de beacon (radiotap), 0 si no vino en el header
    pub rssi: i32,
    pub channel: u8,
    pub beacons: u32,
    pub data_frames: u32,
    pub first_seen: u64,
    pub last_seen: u64,
}

/// Registro vivo de APs durante la captura monitor.
#[derive(Default)]
pub struct LiveAps {
    aps: HashMap<String, LiveAp>,
}

impl LiveAps {
    /// Registra un beacon o probe-response (ambos anuncian un BSS).
    pub fn record_beacon(&mut self, fi: &FrameInfo, channel: u8, now: u64) {
        let entry = self
            .aps
            .entry(fi.bssid.clone())
            .or_insert_with(|| LiveAp {
                ssid: fi.ssid.clone().unwrap_or_default(),
                bssid: fi.bssid.clone(),
                rssi: fi.rssi,
                channel,
                beacons: 0,
                data_frames: 0,
                first_seen: now,
                last_seen: now,
            });
        if let Some(ssid) = &fi.ssid {
            if !ssid.is_empty() {
                entry.ssid = ssid.clone();
            }
        }
        if fi.rssi != 0 {
            entry.rssi = fi.rssi;
        }
        entry.beacons += 1;
        entry.channel = channel;
        entry.last_seen = now;
    }

    /// Registra un frame de datos (tráfico de clientes de ese BSS).
    pub fn record_data(&mut self, bssid: &str, channel: u8, now: u64) {
        let entry = self
            .aps
            .entry(bssid.to_string())
            .or_insert_with(|| LiveAp {
                ssid: String::new(),
                bssid: bssid.to_string(),
                rssi: 0,
                channel,
                beacons: 0,
                data_frames: 0,
                first_seen: now,
                last_seen: now,
            });
        entry.data_frames += 1;
        entry.last_seen = now;
    }

    pub fn len(&self) -> usize {
        self.aps.len()
    }

    /// Lista ordenada por RSSI (los de señal desconocida, 0, al final).
    pub fn sorted(&self) -> Vec<LiveAp> {
        let mut v: Vec<LiveAp> = self.aps.values().cloned().collect();
        v.sort_by_key(|ap| (std::cmp::Reverse(ap.rssi), ap.bssid.clone()));
        v
    }
}

// ---------------------------------------------------------------------------
// Loop de captura monitor
// ---------------------------------------------------------------------------

/// Duración en cada canal antes de saltar al siguiente.
pub const HOP_INTERVAL_MS: u64 = 400;

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Estadísticas de la sesión monitor (para diagnóstico).
#[derive(Debug, Default)]
pub struct CaptureStats {
    /// Frames leídos del socket AF_PACKET (con o sin radiotap válido)
    pub frames_read: std::sync::atomic::AtomicU64,
    /// Frames descartados por FCS corrupto
    pub bad_fcs: std::sync::atomic::AtomicU64,
}

/// Bucle principal de captura: hopping cada HOP_INTERVAL_MS y lectura
/// no bloqueante del socket AF_PACKET. Corre hasta que `stop` se activa.
/// La conversión a monitor y la restauración las hace el llamador
/// (`run_monitor`), para que la restauración sea infalible (catch_unwind).
fn capture_loop(
    iface: &str,
    ifindex: i32,
    channels: &[u8],
    raw: &mut NlSocketHandle,
    family_id: u16,
    stop: &AtomicBool,
    stats: &CaptureStats,
    mut on_tick: impl FnMut(&LiveAps, u8),
) -> anyhow::Result<LiveAps> {
    let mut live = LiveAps::default();
    let pkt_sock = PacketSocket::bind(iface)?;

    let mut ch_idx = 0usize;
    set_channel(raw, family_id, ifindex, channels[0])?;
    let mut hop_at = Instant::now() + Duration::from_millis(HOP_INTERVAL_MS);

    while !stop.load(Ordering::Relaxed) {
        // --- Channel hopping ---
        if Instant::now() >= hop_at {
            // Avanzar SIEMPRE (reintentar el canal rechazado en el siguiente
            // ciclo), para no quedarnos atascado si un canal falla siempre.
            let mut intentos = 0usize;
            loop {
                ch_idx = (ch_idx + 1) % channels.len();
                intentos += 1;
                if set_channel(raw, family_id, ifindex, channels[ch_idx]).is_ok()
                    || intentos >= channels.len()
                {
                    break;
                }
            }
            on_tick(&live, channels[ch_idx]);
            hop_at = Instant::now() + Duration::from_millis(HOP_INTERVAL_MS);
        }

        // --- Lectura de todos los frames pendientes (no bloqueante) ---
        let mut buf = [0u8; 65535];
        loop {
            match pkt_sock.recv(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    stats.frames_read.fetch_add(1, Ordering::Relaxed);
                    let fi = classify_frame(&buf[..n]);
                    if fi.bad_fcs {
                        stats.bad_fcs.fetch_add(1, Ordering::Relaxed);
                        continue; // frame corrupto: no contar
                    }
                    // El radiotap suele traer la frecuencia real de recepción:
                    // preferirla al canal del salto en curso (frames en el aire
                    // de canales vecinos, o el hop justo a mitad de un beacon).
                    let ch = crate::wifi::linux::freq_to_channel(fi.freq_mhz as u32)
                        .max(channels[ch_idx]);
                    match fi.kind {
                        FrameKind::Beacon | FrameKind::ProbeResp => {
                            live.record_beacon(&fi, ch, now_unix());
                        }
                        FrameKind::Data => {
                            if !fi.bssid.is_empty() {
                                live.record_data(&fi.bssid, ch, now_unix());
                            }
                        }
                        _ => {}
                    }
                }
                Err(e) => {
                    let _ = e;
                    break;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(live)
}

// ---------------------------------------------------------------------------
// Socket AF_PACKET
// ---------------------------------------------------------------------------

/// Socket AF_PACKET (ETH_P_ALL) ligado a una interfaz, no bloqueante.
pub struct PacketSocket {
    fd: i32,
}

impl PacketSocket {
    pub fn bind(iface: &str) -> anyhow::Result<Self> {
        unsafe {
            // ETH_P_ALL en network byte order (el kernel espera big endian)
            let fd = libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                (libc::ETH_P_ALL as u16).to_be() as i32,
            );
            if fd < 0 {
                anyhow::bail!(
                    "AF_PACKET no disponible (¿root/CAP_NET_RAW?): {}",
                    std::io::Error::last_os_error()
                );
            }

            let ifindex = resolve_ifindex(fd, iface)? as i32;
            let sockaddr = libc::sockaddr_ll {
                sll_family: libc::AF_PACKET as u16,
                sll_protocol: (libc::ETH_P_ALL as u16).to_be(),
                sll_ifindex: ifindex,
                sll_hatype: 0,
                sll_pkttype: 0,
                sll_halen: 0,
                sll_addr: [0; 8],
            };
            let rc = libc::bind(
                fd,
                &sockaddr as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as u32,
            );
            if rc != 0 {
                libc::close(fd);
                anyhow::bail!("bind AF_PACKET: {}", std::io::Error::last_os_error());
            }

            // No bloqueante para integrar la lectura en el bucle del hop
            let flags = libc::fcntl(fd, libc::F_GETFL, 0);
            if flags >= 0 {
                libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
            Ok(PacketSocket { fd })
        }
    }

    /// Lee un frame. Devuelve Ok(0) si no hay datos (EAGAIN).
    fn recv(&self, buf: &mut [u8]) -> anyhow::Result<usize> {
        let n = unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EAGAIN) || err.kind() == std::io::ErrorKind::WouldBlock
            {
                return Ok(0);
            }
            return Err(err.into());
        }
        Ok(n as usize)
    }
}

impl Drop for PacketSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

/// Resuelve el índice de la interfaz vía ioctl SIOCGIFINDEX.
fn resolve_ifindex(fd: i32, iface: &str) -> anyhow::Result<u32> {
    unsafe {
        let mut ifr: libc::ifreq = std::mem::zeroed();
        let bytes = iface.as_bytes();
        if bytes.len() >= ifr.ifr_name.len() {
            anyhow::bail!("Nombre de interfaz demasiado largo");
        }
        for (dst, &b) in ifr.ifr_name.iter_mut().zip(bytes) {
            *dst = b as i8;
        }
        const SIOCGIFINDEX: libc::c_ulong = 0x8933;
        if libc::ioctl(fd, SIOCGIFINDEX, &mut ifr) != 0 {
            anyhow::bail!("SIOCGIFINDEX({iface}): {}", std::io::Error::last_os_error());
        }
        Ok(ifr.ifr_ifru.ifru_ifindex as u32)
    }
}

// ---------------------------------------------------------------------------
// Punto de entrada del modo monitor
// ---------------------------------------------------------------------------

/// Flag global de parada: lo activan los handlers de SIGINT/SIGTERM y el
/// temporizador de --monitor-secs. `run_monitor` lo consulta en cada iteración.
pub static STOP_FLAG: AtomicBool = AtomicBool::new(false);

extern "C" fn on_stop_signal(_sig: i32) {
    STOP_FLAG.store(true, Ordering::SeqCst);
}

/// Instala handlers de SIGINT/SIGTERM: al pulsar Ctrl+C el bucle termina de
/// forma ordenada y la restauración de la interfaz corre igualmente.
pub fn install_stop_handlers() {
    unsafe {
        let handler: libc::sighandler_t = on_stop_signal as extern "C" fn(i32) as usize;
        libc::signal(libc::SIGINT, handler);
        libc::signal(libc::SIGTERM, handler);
    }
}

/// Helper: convierte la interfaz a monitor, captura hasta que `stop` se activa
/// y SIEMPRE restaura a managed (con fallback a `iw` del sistema si nl80211 falla).
///
/// Devuelve (iface, tabla de APs vistos). La interfaz queda gestionada de nuevo.
pub fn run_monitor(
    iface: &str,
    channels: &[u8],
    stop: &AtomicBool,
    mut on_tick: impl FnMut(&LiveAps, u8),
) -> anyhow::Result<(String, LiveAps)> {
    let mut channels_owned: Vec<u8> = channels.to_vec();
    if channels_owned.is_empty() {
        channels_owned = vec![1, 6, 11];
    }

    // --- Resolver la interfaz ---
    let mut wifi_sock = neli_wifi::Socket::connect()
        .map_err(|e| anyhow::anyhow!("No se pudo abrir el socket nl80211: {e}"))?;
    let ifaces = wifi_sock
        .get_interfaces_info()
        .map_err(|e| anyhow::anyhow!("get_interfaces_info: {e}"))?;
    // El kernel entrega el nombre terminado en NUL ("wlan0\0"): recortarlo antes
    // de comparar. Además, algunas entradas del dump (p. ej. el P2P-device) no
    // traen nombre ni índice, así que exigimos ambos.
    let iface_info = ifaces
        .iter()
        .find(|i| {
            i.name
                .as_ref()
                .map(|n| ifname_to_string(n).eq_ignore_ascii_case(iface))
                .unwrap_or(false)
        })
        .ok_or_else(|| {
            let disponibles: Vec<String> = ifaces
                .iter()
                .filter_map(|i| i.name.as_ref().map(|n| ifname_to_string(n)))
                .collect();
            anyhow::anyhow!(
                "No se encontró la interfaz WiFi '{iface}'. Interfaces WiFi disponibles: {:?}. \
                 Usa --monitor-iface <nombre> para elegir una.",
                disponibles
            )
        })?;
    let ifindex = iface_info
        .index
        .ok_or_else(|| anyhow::anyhow!("Interfaz sin índice netlink"))?;

    let mut raw = NlSocketHandle::connect(NlFamily::Generic, None, &[])
        .map_err(|e| anyhow::anyhow!("socket genérico: {e}"))?;
    let family_id = raw
        .resolve_genl_family(neli_wifi::NL_80211_GENL_NAME)
        .map_err(|e| anyhow::anyhow!("familia nl80211: {e}"))?;

    // --- Apartar NetworkManager: si no, baja la interfaz/vuelve a managed en
    // mitad de la captura y no entra ningún frame. Misma receta que validó el
    // script Python: disconnect + managed no, y restaurar al final. ---
    let nm_took_over = nm_release_iface(iface);

    // --- DOWN + monitor + UP ---
    iface_up_down(iface, false);
    if let Err(e) = set_monitor_type(&mut raw, family_id, ifindex) {
        // No dejar la interfaz caída: subirla y salir con el error
        let _ = iface_up_down(iface, true);
        if nm_took_over {
            nm_restore_iface(iface);
        }
        return Err(anyhow::anyhow!(
            "No se pudo activar monitor: {e}. ¿Root/CAP_NET_ADMIN y sin NetworkManager en la interfaz?"
        ));
    }
    iface_up_down(iface, true);

    let stats = CaptureStats::default();

    // --- Captura (si paniquea, igual restauramos) ---
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        capture_loop(
            iface,
            ifindex,
            &channels_owned,
            &mut raw,
            family_id,
            stop,
            &stats,
            &mut on_tick,
        )
    }));

    // --- Restauración SIEMPRE ---
    let _ = iface_up_down(iface, false);
    if let Err(e) = set_managed_type(&mut raw, family_id, ifindex) {
        eprintln!("⚠ nl80211 no pudo restaurar managed ({e}); usando iw del sistema");
        let _ = std::process::Command::new("iw")
            .args(["dev", iface, "set", "type", "managed"])
            .status();
    }
    let _ = iface_up_down(iface, true);

    // Devolver la interfaz a NetworkManager (reconecta solo)
    if nm_took_over {
        nm_restore_iface(iface);
    }

    let live = result
        .map_err(|_| anyhow::anyhow!("pánico durante la captura monitor"))??;

    // Diagnóstico: si no cayó ningún frame, la captura no vio el aire.
    let frames = stats.frames_read.load(Ordering::Relaxed);
    if frames == 0 {
        eprintln!(
            "⚠ 0 frames capturados: la interfaz no recibió nada. ¿Sigue en modo monitor? \
             Comprueba con: iw dev {iface} info"
        );
    }

    Ok((iface.to_string(), live))
}

/// Aparta la interfaz del control de NetworkManager. Devuelve true si tocó algo
/// (para saber si hay que devolverla después).
fn nm_release_iface(iface: &str) -> bool {
    let _ = std::process::Command::new("nmcli")
        .args(["device", "disconnect", iface])
        .status();
    std::thread::sleep(Duration::from_millis(800));
    let set = std::process::Command::new("nmcli")
        .args(["device", "set", iface, "managed", "no"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !set {
        eprintln!("⚠ No se pudo poner {iface} fuera del control de NetworkManager");
    }
    set
}

/// Devuelve la interfaz a NetworkManager (managed yes + connect).
/// `connect` falla si NM aún no sabe a qué AP volver (la conexión previa se
/// desactivó con el disconnect); en ese caso `nmcli device wifi connect` no
/// aplica sin contraseña, así que re-activamos la conexión guardada por UUID
/// (la más reciente con autoconnect) o avisamos para reconnectar a mano.
fn nm_restore_iface(iface: &str) {
    let _ = std::process::Command::new("nmcli")
        .args(["device", "set", iface, "managed", "yes"])
        .status();
    std::thread::sleep(Duration::from_millis(500));
    let ok = std::process::Command::new("nmcli")
        .args(["device", "connect", iface])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        // Última opción: reactivar la conexión de autoconexión más reciente
        // (AUTOCONNECT sale como "yes"/"no" independiente del locale).
        let _ = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!(
                "uuid=$(nmcli -g AUTOCONNECT,UUID connection show | grep '^yes:' \
                 | head -1 | cut -d: -f2); [ -n \"$uuid\" ] && nmcli connection up \"$uuid\""
            ))
            .status();
        eprintln!(
            "⚠ {iface} quedó en managed pero sin conectar; ejecuta: nmcli device wifi connect <SSID> si no reconecta"
        );
    }
}

/// up/down de la interfaz vía `ip link` (evita reimplementar RTM_SETLINK).
fn iface_up_down(iface: &str, up: bool) -> bool {
    std::process::Command::new("ip")
        .args(["link", "set", iface, if up { "up" } else { "down" }])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Convierte la tabla live al modelo de FWMonitor (con vendor resuelto).
pub fn to_snapshot_aps(live: &LiveAps, oui: &crate::oui::OuiDb) -> Vec<WifiAp> {
    live.sorted()
        .into_iter()
        .map(|ap| {
            let vendor = oui.resolve(&ap.bssid);
            WifiAp {
                ssid: ap.ssid,
                bssid: ap.bssid,
                rssi: ap.rssi,
                phy: "802.11 (monitor)".to_string(),
                channel: ap.channel,
                vendor,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests de las partes puras (sin hardware)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ifname_recorta_nul_final() {
        // El kernel entrega "wlan0\0": debe compararse como "wlan0".
        assert_eq!(ifname_to_string(b"wlan0\0"), "wlan0");
        assert_eq!(ifname_to_string(b"wlan0"), "wlan0");
        assert!(ifname_to_string(b"WLAN0\0").eq_ignore_ascii_case("wlan0"));
    }

    fn beacon_frame(bssid: [u8; 6], ssid: &str) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&[0x80, 0x00]); // FC: mgmt beacon
        f.extend_from_slice(&[0x00, 0x00]); // duration
        f.extend_from_slice(&bssid); // addr1 (DA)
        f.extend_from_slice(&bssid); // addr2 (SA)
        f.extend_from_slice(&bssid); // addr3 (BSSID)
        f.extend_from_slice(&[0x10, 0x00]); // seq ctrl
        f.extend_from_slice(&[0; 12]); // fixed params (timestamp 8 + interval 2 + cap 2)
        // IE 0 = SSID
        f.push(0);
        f.push(ssid.len() as u8);
        f.extend_from_slice(ssid.as_bytes());
        // IE 45 = HT capabilities -> PHY
        f.push(45);
        f.push(2);
        f.extend_from_slice(&[0xff, 0x1f]);
        f
    }

    fn with_radiotap(frame: &[u8], rssi: i8) -> Vec<u8> {
        let mut rt = Vec::new();
        rt.push(0); // version
        rt.push(0); // pad
        let len = 8u16 + 8 + 1 + 1; // header + tsft + flags + rate... simplificado
        rt.extend_from_slice(&len.to_le_bytes());
        // bitmap: TSFT(0) + FLAGS(1) + RATE(2) + CHANNEL(3) + ANT SIGNAL(5)
        let bitmap: u32 = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 5);
        rt.extend_from_slice(&bitmap.to_le_bytes());
        rt.extend_from_slice(&[0u8; 8]); // tsft
        rt.push(0x00); // flags: sin bad FCS
        rt.push(0x0c); // rate
        rt.extend_from_slice(&[0x6c, 0x09, 0x00, 0x00]); // channel
        rt.push(rssi as u8); // antenna signal
        rt.extend_from_slice(frame);
        // corregir longitud real
        let real_len = rt.len() - frame.len();
        rt[2..4].copy_from_slice(&(real_len as u16).to_le_bytes());
        rt
    }

    #[test]
    fn radiotap_minimo_y_offset() {
        // Header mínimo: version+pad+len+bitmap sin campos
        let mut pkt = vec![0, 0, 8, 0, 0, 0, 0, 0];
        pkt.extend_from_slice(&[0x80, 0x00]);
        let (rt, off) = parse_radiotap(&pkt);
        assert_eq!(off, 8);
        assert_eq!(rt, RadiotapInfo::default());
        // Un frame 802.11 normal no empieza en 0x00 0x00: no se detecta radiotap
        let (_, off2) = parse_radiotap(&[0x80, 0x00, 0x00, 0x00]);
        assert_eq!(off2, 0);
    }

    #[test]
    fn radiotap_extrae_rssi_y_bad_fcs() {
        let frame = beacon_frame([0xa0, 0x08, 0x6f, 0x9e, 0x8f, 0x68], "Test");
        let mut pkt = with_radiotap(&frame, -42);
        // Marcar bad FCS en flags (byte 16 del header: 8 + 8 tsft + flags)
        pkt[8 + 8] = 0x40;
        let (rt, off) = parse_radiotap(&pkt);
        assert!(off > 8);
        assert!(rt.bad_fcs);
        assert_eq!(rt.rssi, -42);
    }

    #[test]
    fn radiotap_bitmap_extendido_estilo_iwlwifi() {
        // Layout típico de iwlwifi/AX200: word1 = TSFT + CHANNEL + bit31(ext),
        // word2 = DBM_ANTSIGNAL + RX FLAGS. El RSSI vive en el segundo word y
        // el parser debe seguir el walk a través del bitmap extendido.
        let frame = beacon_frame([0xa0, 0x08, 0x6f, 0x9e, 0x8f, 0x68], "Ext");
        let mut rt: Vec<u8> = Vec::new();
        rt.push(0);
        rt.push(0);
        rt.extend_from_slice(&[0, 0]); // len (se corrige al final)
        let w1: u32 = (1 << 0) | (1 << 3) | (1 << 31); // TSFT + CHANNEL + ext
        let w2: u32 = (1 << 5) | (1 << 14); // DBM_ANTSIGNAL + RX FLAGS
        rt.extend_from_slice(&w1.to_le_bytes());
        rt.extend_from_slice(&w2.to_le_bytes());
        rt.extend_from_slice(&[0u8; 4]); // padding: TSFT va alineado a 8
                                         // desde el INICIO del header (offset 16)
        rt.extend_from_slice(&[0u8; 8]); // TSFT (offset 16, align 8)
        rt.extend_from_slice(&2432u16.to_le_bytes()); // CHANNEL: freq (offset 24)
        rt.extend_from_slice(&[0x00, 0x00]); // CHANNEL: flags
        rt.push((-58i8) as u8); // DBM_ANTSIGNAL (word2, bit 5)
        rt.push(0); // pad para RX FLAGS (u16, align 2)
        rt.extend_from_slice(&[0x00, 0x00]); // RX FLAGS (word2, bit 14)
        let rt_len = rt.len() as u16;
        rt[2..4].copy_from_slice(&rt_len.to_le_bytes());
        rt.extend_from_slice(&frame);

        let (info, off) = parse_radiotap(&rt);
        assert_eq!(off, rt_len as usize);
        assert_eq!(info.freq_mhz, 2432);
        assert_eq!(info.rssi, -58);
        assert!(!info.bad_fcs);
    }

    #[test]
    fn beacon_se_clasifica_y_extrae_ssid() {
        let bssid = [0xa0u8, 0x08, 0x6f, 0x9e, 0x8f, 0x68];
        let frame = beacon_frame(bssid, "Fam Torres Izaguirre");
        let fi = classify_frame(&frame);
        assert_eq!(fi.kind, FrameKind::Beacon);
        assert_eq!(fi.ssid.as_deref(), Some("Fam Torres Izaguirre"));
        assert_eq!(fi.bssid, "a0:08:6f:9e:8f:68");
        assert!(!fi.bad_fcs);

        // Con radiotap delante (lo que llega de verdad por AF_PACKET)
        let pkt = with_radiotap(&frame, -55);
        let fi2 = classify_frame(&pkt);
        assert_eq!(fi2.kind, FrameKind::Beacon);
        assert_eq!(fi2.ssid.as_deref(), Some("Fam Torres Izaguirre"));
        assert_eq!(fi2.rssi, -55);
    }

    #[test]
    fn data_y_control_se_clasifican() {
        // Data frame: FC 0x08 0x01 (type 2)
        let mut data = vec![0x08, 0x01];
        data.extend_from_slice(&[0u8; 22]);
        assert_eq!(classify_frame(&data).kind, FrameKind::Data);

        // RTS (control): FC 0xB4 0x00 (type 1)
        let mut rts = vec![0xb4, 0x00];
        rts.extend_from_slice(&[0u8; 22]);
        assert_eq!(classify_frame(&rts).kind, FrameKind::Control);

        // Probe request: FC 0x40 (type 0 subtype 4)
        let mut preq = vec![0x40, 0x00];
        preq.extend_from_slice(&[0u8; 22]);
        assert_eq!(classify_frame(&preq).kind, FrameKind::ProbeReq);
    }

    #[test]
    fn live_aps_agrega_y_ordena() {
        let mut live = LiveAps::default();
        let fi = classify_frame(&beacon_frame([0x11u8, 0, 0, 0, 0, 1], "AP_Fuerte"));
        live.record_beacon(&fi, 1, 100);
        let fi2 = classify_frame(&beacon_frame([0x22u8, 0, 0, 0, 0, 2], "AP_Debil"));
        live.record_beacon(&fi2, 6, 110);
        // Ajustar RSSI para el orden
        let fi_debil = FrameInfo { rssi: -80, ..fi2 };
        live.record_beacon(&fi_debil, 6, 120);
        live.record_data("11:00:00:00:00:01", 1, 130);
        live.record_data("11:00:00:00:00:01", 1, 131);

        assert_eq!(live.len(), 2);
        let sorted = live.sorted();
        assert_eq!(sorted[0].ssid, "AP_Fuerte");
        assert_eq!(sorted[0].beacons, 1);
        assert_eq!(sorted[0].data_frames, 2);
        assert_eq!(sorted[1].ssid, "AP_Debil");
        assert_eq!(sorted[1].rssi, -80);
    }

    #[test]
    fn to_snapshot_aps_resuelve_vendor() {
        let mut live = LiveAps::default();
        let fi = classify_frame(&beacon_frame([0xa0u8, 0x08, 0x6f, 0x9e, 0x8f, 0x68], "MiRed"));
        live.record_beacon(&fi, 7, 1);
        let oui = crate::oui::OuiDb::builtin();
        let aps = to_snapshot_aps(&live, &oui);
        assert_eq!(aps.len(), 1);
        assert_eq!(aps[0].ssid, "MiRed");
        assert_eq!(aps[0].channel, 7);
        assert_eq!(aps[0].vendor, "AVM (FRITZ!Box)");
        assert_eq!(aps[0].phy, "802.11 (monitor)");
    }
}
