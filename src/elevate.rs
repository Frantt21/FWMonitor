//! Solicitud de privilegios para el barrido ARP.
//!
//! En Linux el sondeo ARP necesita `CAP_NET_RAW`. Si no lo tenemos, el proceso
//! se relanza una sola vez: con `pkexec` cuando la UI es gráfica y con `sudo`
//! cuando hay terminal. Si el usuario cancela o no hay mecanismo disponible,
//! se sigue sin privilegios (la app avisa y muestra solo la caché ARP).
//!
//! En Windows no aplica: `SendARP` funciona sin elevación.

use std::process::Command;

/// Marca en el entorno para que el proceso hijo no vuelva a pedir privilegios.
const MARKER: &str = "FWMONITOR_ELEVATED";

/// ¿Podemos abrir sockets `AF_PACKET` sin relanzar?
#[cfg(target_os = "linux")]
pub fn can_sweep() -> bool {
    // root siempre puede
    if unsafe { libc::geteuid() } == 0 {
        return true;
    }
    // CAP_NET_RAW = bit 13 de CapEff (file capabilities sin ser root)
    const CAP_NET_RAW: u64 = 1 << 13;
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find(|line| line.starts_with("CapEff:"))
                .map(str::to_string)
        })
        .and_then(|line| {
            line.split_whitespace()
                .nth(1)
                .and_then(|hex| u64::from_str_radix(hex, 16).ok())
        })
        .is_some_and(|caps| caps & CAP_NET_RAW != 0)
}

#[cfg(not(target_os = "linux"))]
pub fn can_sweep() -> bool {
    true
}

/// Intenta relanzar el proceso con privilegios.
///
/// Devuelve `true` si el hijo elevado ya terminó correctamente y el llamador
/// debe salir; `false` para continuar en el proceso actual (sin privilegios).
pub fn maybe_relaunch(gui: bool) -> bool {
    if std::env::var_os(MARKER).is_some() || can_sweep() {
        return false;
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = gui;
        return false;
    }

    #[cfg(target_os = "linux")]
    {
        let Ok(exe) = std::env::current_exe() else {
            return false;
        };
        let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();

        let mut cmd = if gui {
            Command::new("pkexec")
        } else {
            Command::new("sudo")
        };

        if gui {
            // pkexec resetea el entorno: hay que devolverle la sesión gráfica.
            cmd.arg("env");
            for key in [
                "DISPLAY",
                "WAYLAND_DISPLAY",
                "XAUTHORITY",
                "XDG_RUNTIME_DIR",
                "XDG_SESSION_TYPE",
                "DBUS_SESSION_BUS_ADDRESS",
                "TERM",
            ] {
                if let Some(value) = std::env::var_os(key) {
                    cmd.arg(format!("{key}={}", value.to_string_lossy()));
                }
            }
        }

        cmd.env(MARKER, "1");
        cmd.arg(&exe).args(&args);

        eprintln!("🔒 Se necesitan privilegios para el barrido ARP; relanzando…");

        match cmd.status() {
            Ok(status) if status.success() => true,
            Ok(status) => {
                eprintln!(
                    "⚠ No se concedieron privilegios (código {}): sigo sin barrido ARP.",
                    status.code().unwrap_or(-1)
                );
                false
            }
            Err(err) => {
                eprintln!("⚠ No se pudo relanzar con privilegios: {err}");
                false
            }
        }
    }
}
