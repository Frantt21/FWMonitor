# FWMonitor

Monitor de red WiFi que vive en la terminal: escanea los puntos de acceso a tu
alrededor y descubre los dispositivos conectados a tu red local.

```
Interfaz: Killer(R) Wi-Fi 6 AX1650x 160MHz Wireless Network Adapter (200NGW)
Red local: Wi-Fi 192.168.100.95 /24 GW 192.168.100.1

=== WiFi (3 BSSIDs) ===
SSID                  BSSID               RSSI    CH  PHY           Fabricante
MiRed                 a0:08:6f:9e:8f:68  -41 dBm    7  HT (11n)      AVM (FRITZ!Box)
RedVecina             a0:08:6f:de:14:5d  -84 dBm    1  HT (11n)      AVM (FRITZ!Box)

=== LAN (3 hosts) ===
IP               MAC                 Tipo     Fabricante
192.168.100.1    a0:08:6f:9e:8f:62   GW       AVM (FRITZ!Box)
192.168.100.95   8c:47:be:1d:b7:27   Local
192.168.100.147  fa:e2:d8:5d:96:24   ARP      MAC aleatoria (privada)
```

## Cómo funciona

- **WiFi**: usa la *Native WiFi API* de Windows (`wlanapi.dll`). Lanza un
  escaneo activo (`WlanScan`) y lee la lista de BSSIDs con RSSI, canal y PHY.
- **LAN**: hace un barrido ARP del /24 (`SendARP`, paralelo con un hilo por IP)
  y lo fusiona con la tabla ARP del sistema. ARP descubre hosts aunque tengan
  firewall que bloquee ping.
- **Fabricante**: resuelve el OUI (primeros 3 bytes de la MAC) contra una tabla
  integrada (~200 fabricantes comunes). Las MAC localmente administradas se
  marcan como "MAC aleatoria (privada)" — típico de móviles con privacidad MAC.

## Uso

```powershell
fwmonitor                          # TUI interactiva (r: refrescar, q: salir)
fwmonitor --once                   # una captura en texto plano
fwmonitor -i 10                    # refresco cada 10 s

fwmonitor --csv captura.csv        # exporta una captura a CSV (sobreescribe)
fwmonitor --csv-append hist.csv    # añade al CSV (histórico con timestamps)
fwmonitor --once --csv h.csv       # texto + CSV a la vez

fwmonitor --oui-db oui.csv         # base OUI externa (formato IEEE oui.csv
                                   # o manuf de Wireshark), fusionada con la integrada
```

El CSV tiene una fila por dispositivo con columna `ts` (timestamp ISO UTC),
`source` (wifi|lan) y todos los campos. Con `--csv-append` desde cron/tarea
programada construyes un histórico de quién aparece en tu red y cuándo.

## Compilar

**Windows**: requiere Rust con toolchain `x86_64-pc-windows-msvc` (VS Build
Tools). No necesita dependencias externas (usa `windows` crate).

**Linux (Arch)**: toolchain estable estándar. No necesita libpcap ni iw: el
escaneo nl80211 es Rust puro vía `neli`/`neli-wifi`.

```sh
cargo build --release
```

## Linux (Arch): permisos

- **Escaneo WiFi (nl80211)**: sin permisos especiales. Funciona junto a
  wpa_supplicant/NetworkManager (el kernel coordina los escaneos).
- **Sondeo ARP**: requiere `CAP_NET_RAW` (sockets `AF_PACKET`). Dos opciones:

```sh
sudo ./fwmonitor --once                 # simple: ejecutar como root
sudo setcap cap_net_raw=eip ./fwmonitor  # o dar la capability una vez
```

Si lo ejecutas sin `CAP_NET_RAW`, el sondeo ARP se omite y solo verás la tabla
ARP pasiva del sistema (los hosts con los que tu máquina ya ha hablado).

## Limitaciones (por diseño, v1)

- **Windows no ofrece monitor mode** en drivers modernos de Intel/Killer: la
  API *Native 802.11* está deprecada y `WlanHelper` falla con error 50 en las
  AX1650/AX2xx. Por eso v1 se basa en escaneo BSSID + ARP, que cubre
  "¿qué hay en mi red?" sin necesitar monitor mode.
- El escaneo de BSSIDs usa la caché del driver; en redes muy saturadas algún
  AP lejano puede tardar un par de ciclos en aparecer.
- La detección de "dispositivos conectados a TU red" se infiere por ARP: un
  dispositivo con firewall L2 agresivo podría no aparecer.

## Roadmap

- [x] Backend Linux (nl80211 vía `neli`): escaneo real de BSSIDs + sondeo ARP (AF_PACKET)
- [x] Resolución de fabricante por OUI (tabla integrada + IEEE/Wireshark externa)
- [x] Export a CSV con timestamp (`--csv`, `--csv-append`)
- [x] Historial de clientes: nuevo/ausente entre snapshots en la TUI (TTL 5 min)
- [ ] Resolución de nombres (mDNS/NBNS/SSDP)
- [ ] Monitor mode opcional en Linux con channel hopping
