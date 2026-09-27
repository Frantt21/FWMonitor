# FWMonitor

Monitor de red WiFi que vive en la terminal: escanea los puntos de acceso a tu
alrededor y descubre los dispositivos conectados a tu red local.

```
Interfaz: Killer(R) Wi-Fi 6 AX1650x 160MHz Wireless Network Adapter (200NGW)
Red local: Wi-Fi 192.168.100.95 /24 GW 192.168.100.1

=== WiFi (2 BSSIDs) ===
SSID                  BSSID               RSSI    CH  PHY
MiRed                 a0:08:6f:9e:8f:68  -41 dBm    7  HT (11n)
RedVecina             a0:08:6f:de:14:5d  -84 dBm    1  HT (11n)

=== LAN (3 hosts) ===
IP               MAC                 Tipo
192.168.100.1    a0:08:6f:9e:8f:62   GW
192.168.100.95   8c:47:be:1d:b7:27   Local
192.168.100.147  ee:d4:7e:28:5d:90   ARP
```

## Cómo funciona

- **WiFi**: usa la *Native WiFi API* de Windows (`wlanapi.dll`). Lanza un
  escaneo activo (`WlanScan`) y lee la lista de BSSIDs con RSSI, canal y PHY.
- **LAN**: hace un barrido ARP del /24 (`SendARP`, paralelo con un hilo por IP)
  y lo fusiona con la tabla ARP del sistema. ARP descubre hosts aunque tengan
  firewall que bloquee ping.

## Uso

```powershell
fwmonitor               # TUI interactiva (r: refrescar, q: salir)
fwmonitor --once        # una captura en texto plano
fwmonitor -i 10         # refresco cada 10 s
```

## Compilar

Requiere Rust con toolchain `x86_64-pc-windows-msvc` (VS Build Tools) en
Windows, y `libpcap`/headers de sistema en Linux.

```sh
cargo build --release
```

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

- [ ] Backend Linux (nl80211 vía `rtnetlink`/`iwlib`): escaneo + monitor mode real
- [ ] Resolución de nombres (mDNS/NBNS/SSDP) y fabricante por OUI
- [ ] Export a CSV/JSON, historial de clientes (nuevo/ausente)
- [ ] Monitor mode opcional en Linux con channel hopping
