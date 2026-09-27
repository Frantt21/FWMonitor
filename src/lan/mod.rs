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
