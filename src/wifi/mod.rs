//! Escaneo WiFi multiplataforma.
//! Windows: Native WiFi API (wlanapi.dll). Linux: nl80211 (netlink).

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::scan_aps;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::scan_aps;
