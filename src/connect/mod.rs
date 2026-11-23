//! Conexión a una red WiFi y lectura de la contraseña guardada.
//!
//! Linux: NetworkManager por D-Bus (la contraseña nunca viaja por `argv`).
//! Windows: perfil WLAN con `WlanSetProfile` + `WlanConnect`.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{connect, reveal_password};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{connect, reveal_password};
