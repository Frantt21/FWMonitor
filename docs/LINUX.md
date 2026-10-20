# FWMonitor en Linux (Arch)

Guía completa para compilar, instalar y operar FWMonitor en Arch Linux.
El backend Linux es Rust puro: no necesita libpcap, iw ni headers de sistema.

## Instalación

```sh
# Toolchain (si no la tienes)
sudo pacman -S --needed rust base-devel

# Compilar
git clone <tu-repo> fwmonitor && cd fwmonitor
cargo build --release

# Instalar el binario
sudo install -Dm755 target/release/fwmonitor /usr/local/bin/fwmonitor
```

## Permisos

| Función | Permiso necesario | Sin él… |
|---|---|---|
| Escaneo WiFi (nl80211) | Ninguno | Funciona igual |
| Sondeo ARP activo | `CAP_NET_RAW` | Se omite; solo tabla ARP pasiva |
| TUI / CSV / OUI | Ninguno | Funciona igual |

Dos formas de dar `CAP_NET_RAW`:

```sh
# Opción A: ejecutar como root cada vez
sudo fwmonitor

# Opción B (recomendada): capability permanente, sin root
sudo setcap cap_net_raw=eip /usr/local/bin/fwmonitor
fwmonitor   # ya funciona como usuario normal
```

> Nota: `setcap` hay que reaplicarlo si reinstalas/reescribes el binario.

Verificar la capability: `getcap /usr/local/bin/fwmonitor`

## Modo monitor 802.11 (--monitor)

**Verificado en esta máquina** (Killer AX1650x = Intel AX200, driver `iwlwifi`):
la tarjeta entra en modo monitor, captura beacons reales del aire (~10/s por AP
visible) y el channel hopping retunea correctamente (frames solo en el canal
sintonizado). Es lo que Windows no permitía con estos drivers.

```sh
# Captura continua con hopping por 1-13 (todo 2.4 GHz) hasta Ctrl+C
sudo fwmonitor --monitor

# Sesión de 60 s exportando el resultado a CSV
sudo fwmonitor --monitor --monitor-secs 60 --csv monitor.csv

# Escanear también 5 GHz (los canales DFS 52-144 los rechazará el kernel)
# --monitor-channels acepta listas y rangos
sudo fwmonitor --monitor --monitor-channels 1-13,36,40,44,48,149,153,157,161

# Otra interfaz distinta de wlan0
sudo fwmonitor --monitor --monitor-iface wlp3s0
```

Qué hace exactamente:

1. `NL80211_CMD_SET_INTERFACE` con `NL80211_IFTYPE_MONITOR` (la interfaz debe
   estar DOWN; el programa la baja y la sube solo).
2. Captura por socket raw `AF_PACKET` y parsea el header **radiotap** de
   mac80211: de ahí salen el RSSI y el flag de frames con FCS corrupto
   (se descartan).
3. Clasifica frames 802.11: beacons y probe-responses alimentan la tabla de
   APs (SSID, canal, RSSI, contadores); los frames de datos se cuentan como
   tráfico del BSS.
4. Salta de canal cada 400 ms con `NL80211_CMD_SET_WIPHY` +
   `NL80211_ATTR_WIPHY_FREQ` (+ `CHAN_HT20`).
5. Al terminar **siempre** restaura el modo managed (nl80211, con fallback a
   `iw dev X set type managed` si el kernel se resiste) y NetworkManager
   reconecta en unos segundos.

Opciones: `--monitor-iface` (por defecto `wlan0`), `--monitor-secs N` (0 =
hasta Ctrl+C), `--monitor-channels` (por defecto `1-13`; acepta listas y
rangos, p. ej. `1,6,11` o `1-13,36-48,149`). Combinable con
`--csv`/`--csv-append` y `--oui-db`.

Requiere **root** (o `CAP_NET_ADMIN` en el binario: `sudo setcap
cap_net_admin=eip /usr/local/bin/fwmonitor`). Mientras dura la captura la WiFi
está desconectada: en iwlwifi no coexisten managed+monitor. Si necesitas red
durante la captura, usa la Ethernet.

## Servicio systemd (histórico continuo)

Para dejar un histórico CSV de presencia corriendo de fondo, se combinan un
servicio de una sola pasada con un timer que lo repite:

`~/.config/systemd/user/fwmonitor.service`

```ini
[Unit]
Description=FWMonitor - histórico de presencia en la red
After=network-online.target

[Service]
ExecStart=/usr/local/bin/fwmonitor --once --csv-append %h/.local/share/fwmonitor/hist.csv
NoNewPrivileges=yes
```

> El sondeo ARP necesita `CAP_NET_RAW`: al ser un servicio de usuario, aplícale
> el `setcap` del apartado anterior al binario (los user services no pueden
> elevar capabilities por sí mismos).

`~/.config/systemd/user/fwmonitor.timer`

```ini
[Unit]
Description=FWMonitor cada 5 minutos

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
```

```sh
mkdir -p ~/.local/share/fwmonitor
systemctl --user daemon-reload
systemctl --user enable --now fwmonitor.timer
journalctl --user -u fwmonitor -f     # ver actividad
```

## Hardware: tu Killer AX1650 en Arch

La AX1650 (200NGW) es internamente una **Intel AX200** — en Linux usa el
driver `iwlwifi`, con soporte completo de escaneo nl80211 y **monitor mode
operativo** (verificado con `--monitor`; el modo aparece en `iw phy` bajo
"Supported interface modes", pero **no** en "valid interface combinations":
no se puede combinar con managed, hay que convertir la propia interfaz).

```sh
# Comprobar la tarjeta y el driver
lspci -k | grep -A 3 -i network
iw dev

# Comprobar capacidades (debería listar "monitor" entre los modos)
iw phy | grep -A 8 "Supported interface modes"

# Prueba independiente de monitor mode (sin compilar nada):
sudo python3 scripts/test_monitor.py
```

El firmware se instala con `sudo pacman -S linux-firmware` (viene por defecto
en Arch). Para redes 160 MHz asegúrate de tener `iwlwifi` reciente (kernel
estable actual de Arch lo está siempre).

## Troubleshooting

**No aparece ninguna red WiFi**
- Comprueba que hay una interfaz WiFi: `iw dev`
- Si `rfkill list` la muestra bloqueada: `rfkill unblock wifi`
- Si usas NetworkManager, `nmcli radio wifi on`

**El sondeo ARP no encuentra hosts / error de permisos**
- Sin `CAP_NET_RAW` el sondeo activo se desactiva silenciosamente (ver solo
  `/proc/net/arp`): aplica el `setcap` de arriba o usa sudo.
- Verifica: `getcap /usr/local/bin/fwmonitor`

**El escaneo tarda más de lo esperado**
- Normal en 2.4+5 GHz con muchos canales: puede llevar 3-5 s por ciclo.
- Si un AP concreto no aparece, puede estar en DFS (canal 5GHz 52-144):
  el kernel los escanea pasivamente y tardan más.

**La TUI se ve rota / colores raros**
- FWMonitor usa ratatui sobre crossterm: funciona en cualquier terminal
  moderna (alacritty, kitty, foot, tmux). Con tmux asegúrate de tener
  `set -g default-terminal "tmux-256color"`.

**Error `Address family not supported` en el sondeo**
- Te falta el módulo `af_packet` (rarísimo en Arch). `modprobe af_packet`.

## Diferencias respecto a Windows

- En Arch **sí** hay monitor mode a nivel de driver (`iwlwifi`) y FWMonitor lo
  explota con `--monitor`: captura pasiva de beacons/probes + channel hopping.
  En Windows la API Native 802.11 está deprecada y los drivers Intel/Killer
  lo bloquean (error 50 en WlanHelper).
- El sondeo ARP en Linux usa sockets raw en vez de la API `SendARP` de
  Windows: mismo resultado, distinta vía.
- La detección de la red local es vía /proc en lugar de `GetAdaptersAddresses`.
