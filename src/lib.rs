//! Núcleo de FWMonitor: captura y modelado de datos, sin depender de la
//! interfaz. Lo comparten el binario de terminal (`fwmonitor`) y el de
//! escritorio (`fwmonitor-gui`).

pub mod connect;
pub mod csv;
pub mod history;
pub mod lan;
#[cfg(target_os = "linux")]
pub mod monitor;
pub mod model;
pub mod oui;
pub mod ui;
pub mod wifi;
