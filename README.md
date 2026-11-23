# FWMonitor

Monitor de red WiFi que vive en la terminal: escanea los puntos de acceso a tu
alrededor, descubre los dispositivos conectados a tu red local y sigue su
presencia entre snapshots. Multiplataforma: **Windows** y **Linux (Arch)**.

```
Interfaz: Killer(R) Wi-Fi 6 AX1650x 160MHz Wireless Network Adapter (200NGW)
Red local: Wi-Fi 192.168.100.95 /24 GW 192.168.100.1

=== WiFi (3 BSSIDs) ===
SSID                  BSSID               RSSI    CH  Cifrado          PHY           Fabricante
MiRed                 a0:08:6f:9e:8f:68  -41 dBm    7  WPA/WPA2         HT (11n)      AVM (FRITZ!Box)
RedVecina             a0:08:6f:de:14:5d  -84 dBm    1  WPA2             HT (11n)      AVM (FRITZ!Box)

=== LAN: 2 activos, 1 ausentes ===
IP               MAC                 Tipo     Fabricante              Estado
192.168.100.1    a0:08:6f:9e:8f:62   GW       AVM (FRITZ!Box)
192.168.100.147  fa:e2:d8:5d:96:24   ARP      MAC aleatoria (privada)  nuevo
192.168.100.95   8c:47:be:1d:b7:27   Local                            ausente
```

## Cómo funciona

| | Windows | Linux |
|---|---|---|
| **Escaneo WiFi** | Native WiFi API (`wlanapi.dll`): `WlanScan` + `WlanGetNetworkBssList` | nl80211 vía netlink (`neli`/`neli-wifi`): `CMD_TRIGGER_SCAN` + dump de BSS |
| **Descubrimiento LAN** | `SendARP` paralelo + tabla ARP del sistema | Sockets raw `AF_PACKET` + `/proc/net/arp` |
| **Red local** | `GetAdaptersAddresses` | Ruta por defecto + `/proc/net/route` + `/proc/net/fib_trie` |
| **Monitor mode** | No disponible en drivers modernos (Intel/Killer) | ✅ `--monitor`: captura pasiva 802.11 + channel hopping (verificado en Intel AX200/iwlwifi) |

En ambos casos:

- **Fabricante por OUI**: tabla integrada (~200 fabricantes comunes) + carga
  opcional de la base completa de IEEE/Wireshark. Las MAC localmente
  administradas se muestran como "MAC aleatoria (privada)".
- **Historial de clientes**: en la TUI, cada host se marca como `nuevo`,
  normal o `ausente` (TTL 5 min) comparando snapshots. La identidad es la MAC,
  así que un host que cambia de IP sigue siendo el mismo.
- **Descubrimiento LAN**: barrido ARP del /24 en paralelo más la caché ARP del
  sistema. En Linux el barrido necesita `CAP_NET_RAW`; si no lo hay, la app lo
  **avisa** en vez de fingir una red vacía y solo muestra los vecinos ya
  cacheados (relanza con `sudo` para el inventario completo).
- **Nombres de host**: se resuelven con NSS (`getent hosts`), así que
  funcionan `/etc/hosts`, DNS inverso, mDNS (con `nss-mdns`) y WINS si están
  instalados. Salen en `--once`, en la tabla LAN de la GUI y en el CSV.

## Uso

```sh
fwmonitor                          # TUI interactiva (r: refrescar, q: salir)
fwmonitor --once                   # una captura en texto plano
fwmonitor -i 10                    # refresco cada 10 s

fwmonitor --csv captura.csv        # exporta una captura a CSV (sobreescribe)
fwmonitor --csv-append hist.csv    # añade al CSV (histórico con timestamps)
fwmonitor --once --csv h.csv       # texto + CSV a la vez

fwmonitor --oui-db oui.csv         # base OUI externa (formato IEEE oui.csv
                                   # o manuf de Wireshark), fusionada con la integrada

# Solo Linux: modo monitor 802.11 (requiere root, desconecta la interfaz)
sudo fwmonitor --monitor                            # hopping por 1-13 (2.4 GHz) hasta Ctrl+C
sudo fwmonitor --monitor --monitor-secs 60          # captura de 60 segundos
sudo fwmonitor --monitor --monitor-channels 1-13,36,44,149   # soporta listas y rangos
sudo fwmonitor --monitor --monitor-iface wlan0 --csv mon.csv
```

### Router (FRITZ!Box TR-064)

```sh
# Credenciales por entorno: argv es visible en `ps`
FWMONITOR_ROUTER_USER=usuario FWMONITOR_ROUTER_PASS=clave \
  fwmonitor --router --router-url http://192.168.178.1:49000
```

Muestra modelo y FRITZ!OS, estado WAN (IP pública, tipo de acceso, enlace y
Mbps) y el inventario de hosts del router (nombre, IP, MAC, interfaz y si está
activo), que es más fiable que inferir por ARP. En la GUI, botón **Router…**
con URL/usuario/contraseña; las credenciales solo viven en memoria.

TR-064 tiene que estar activo en el router: *Home Network → Network → Network
Settings → Allow access for applications*. Se habla HTTP plano (es lo que
ofrece TR-064 en LAN), con autenticación digest MD5.

### Interfaz gráfica

```sh
cargo run --release --bin fwmonitor-gui          # ventana (egui/eframe)
cargo run --release --bin fwmonitor-gui -- -i 3  # escaneo cada 3 s
```

Misma captura que la TUI, en una ventana: el escaneo corre en un hilo aparte
(así el sondeo ARP no congela la interfaz), la tabla de APs sale ordenada por
señal y la de LAN mantiene el estado `nuevo`/`ausente` del historial.

### Cifrado, enlace actual y conexión

- Cada AP muestra su **cifrado** deducido de sus Information Elements (RSN,
  WPA y OWE). En la GUI y en `--once`; las redes abiertas salen en rojo con el
  aviso «sin cifrado».
- Con una red asociada, la cabecera de la GUI muestra el **enlace actual**:
  SSID, BSSID, señal, canal, Mbps de TX/RX y tiempo conectado.
- **Conectar** desde el detalle de un AP: en Linux crea la conexión con
  NetworkManager por D-Bus (la contraseña no pasa por `argv`, así que no se ve
  en `ps`); en Windows crea un perfil de usuario con `WlanSetProfile` +
  `WlanConnect`.
- **Ver contraseña** de la red conectada: en Linux `nmcli --show-secrets` (NM
  puede pedir autorización polkit); en Windows `WlanGetProfile` con
  `WLAN_PROFILE_GET_PLAINTEXT_KEY`, que exige administrador. La clave no se
  escribe en disco ni en el CSV: solo se muestra o se copia al portapapeles.

El histórico de señal se muestrea en cada escaneo desde que abres la ventana
(240 muestras por BSSID, ~20 min a 5 s). La columna **Histórico** de la tabla
WiFi dibuja la tendencia de cada red; al hacer clic en una fila se abre el
panel **Detalle** a la derecha con todos los campos del AP o del host y, para
APs, el mismo histórico ampliado con ejes en dBm, mínimo, media y máximo.
`Esc` o el botón `Cerrar` deseleccionan. El modo monitor 802.11 sigue siendo solo de la TUI
(`--monitor`).

En modo monitor la tarjeta se pone en modo pasivo y captura beacons del aire
con hopping de canal: ves **todas** las redes alcanzables (no solo las que
devuelve el escaneo del driver), con contadores de beacons/frames de datos por
BSS. Al salir (Ctrl+C incluido) la interfaz se restaura a managed y se
reconecta sola. En iwlwifi (Intel) no puede haber managed+monitor a la vez,
por eso la captura es exclusiva: usa la Ethernet o planifica el intervalo.

El CSV tiene una fila por dispositivo con columna `ts` (timestamp ISO UTC),
`source` (wifi|lan), `name` y todos los campos. Con `--csv-append` desde una tarea
programada construyes un histórico de quién aparece en tu red y cuándo.

## Compilar

**Windows**: toolchain `x86_64-pc-windows-msvc` (VS Build Tools). Sin
dependencias externas.

**Linux (Arch)**: toolchain estándar. Sin libpcap ni iw: el escaneo nl80211 es
Rust puro.

```sh
cargo build --release
```

Guía completa para Arch (instalación, permisos, servicio systemd,
troubleshooting): **[docs/LINUX.md](docs/LINUX.md)**

## Limitaciones (por diseño, v1)

- **Windows no ofrece monitor mode** en drivers modernos de Intel/Killer: la
  API *Native 802.11* está deprecada y `WlanHelper` falla con error 50 en las
  AX1650/AX2xx. Por eso en Windows se basa en escaneo BSSID + ARP.
- El escaneo de BSSIDs usa la caché del driver; en redes muy saturadas algún
  AP lejano puede tardar un par de ciclos en aparecer.
- El modo monitor en Linux requiere root/CAP_NET_ADMIN y la interfaz queda
  desconectada mientras dura la captura (limitación de iwlwifi, no de la app).
  Los canales DFS (5 GHz 52-144) se saltan si el kernel los rechaza.
- nl80211 solo entrega los IEs del BSS, no el campo Capability del beacon: en
  Linux una red WEP sin IE de seguridad se muestra como «abierta» (Windows sí
  distingue WEP porque tiene ese campo).
- Conectar a una red reemplaza la asociación actual; en la GUI se bloquea el
  escaneo mientras dura el intento. No probado de extremo a extremo en este
  entorno para no cortar la conexión en uso.
- TR-064 solo se implementa sobre HTTP (sin TLS) y con digest MD5, que es lo
  que ofrece el FRITZ!Box en la LAN. Las credenciales del router no se
  persisten: se piden en cada sesión.
- La detección de "dispositivos conectados a TU red" se infiere por ARP: un
  dispositivo con firewall L2 agresivo podría no aparecer en el sondeo activo
  (seguiría apareciendo si habla con tu máquina).

## Roadmap

- [x] Backend Windows (wlanapi + SendARP)
- [x] Backend Linux (nl80211 vía `neli`): escaneo real de BSSIDs + sondeo ARP (AF_PACKET)
- [x] Resolución de fabricante por OUI (tabla integrada + IEEE/Wireshark externa)
- [x] Export a CSV con timestamp (`--csv`, `--csv-append`)
- [x] Historial de clientes: nuevo/ausente entre snapshots en la TUI (TTL 5 min)
- [x] Monitor mode en Linux (`--monitor`): captura pasiva 802.11 + channel hopping
- [x] Cifrado por AP, estado del enlace actual y conexión con contraseña desde la GUI
- [x] Módulo del router (FRITZ!Box TR-064): estado WAN, IP pública e inventario de hosts
- [ ] WiFi de invitados / cambio de canal por TR-064
- [x] Nombres de host vía NSS (DNS/mDNS/WINS) y aviso de barrido degradado
- [ ] Interrogación directa mDNS/SSDP (independiente de los módulos NSS)
- [ ] Fingerprint de servicios por dispositivo (tipo: impresora, NAS, TV…)
