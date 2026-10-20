#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Prueba de monitor mode para FWMonitor en Arch (iwlwifi / Intel AX200).

Comprueba, en este orden:
  1. Estado inicial: rfkill, modo de la interfaz, conexión activa.
  2. Que se puede poner la interfaz en modo monitor
     (iw ... set type monitor; reintento con flags otherbss+control si
     no llegara nada, y fallback a wireless extensions SIOCSIWMODE).
  3. Que llegan frames 802.11 reales del aire por un socket AF_PACKET
     (radiotap se detecta y se salta; PACKET_OUTGOING se excluye).
  4. Channel hopping funcional: captura en los canales 1, 6, 7 y 11
     (el 7 es el canal de tu AP, así que debe haber beacons seguro).

Al final SIEMPRE restaura la interfaz a managed y reconecta
NetworkManager (try/finally), pase lo que pase.

Ejecutar con:  sudo python3 scripts/test_monitor.py
"""

import fcntl
import socket
import struct
import subprocess
import sys
import time

IFACE = "wlan0"
CAPTURE_SECONDS = 6          # por canal
CHANNELS = [1, 6, 7, 11]     # 2.4 GHz; el 7 es donde está tu AP

SIOCGIFINDEX = 0x8933
SIOCSIWMODE = 0x8B06         # wireless extensions: fijar modo de operación
IW_MODE_MONITOR = 6

PACKET_HOST = 0
PACKET_BROADCAST = 1
PACKET_MULTICAST = 2
PACKET_OTHERHOST = 3
PACKET_OUTGOING = 4


def run(cmd: str) -> tuple[int, str]:
    """Ejecuta un comando de shell y devuelve (exit_code, salida combinada)."""
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
    return p.returncode, (p.stdout + p.stderr).strip()


def iface_index(name: str) -> int:
    """Índice de la interfaz vía ioctl SIOCGIFINDEX."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifreq = struct.pack("16s i", name.encode(), 0)
        res = fcntl.ioctl(s.fileno(), SIOCGIFINDEX, ifreq)
        return struct.unpack("16s i", res)[1]
    finally:
        s.close()


def set_monitor_via_wext(name: str) -> bool:
    """Fallback clásico: SIOCSIWMODE (lo que hacía iwconfig).

    struct iwreq = ifr_name[16] + union (mode __u32 en offset 16).
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifreq = struct.pack("16s i", name.encode(), IW_MODE_MONITOR)
        fcntl.ioctl(s.fileno(), SIOCSIWMODE, ifreq)
        return True
    except OSError as e:
        print(f"    ioctl SIOCSIWMODE falló: {e}")
        return False
    finally:
        s.close()


def current_mode(name: str) -> str:
    _, out = run(f"iw dev {name} info")
    for line in out.splitlines():
        if "type" in line:
            return line.split("type")[-1].strip()
    return "?"


def strip_radiotap(pkt: bytes) -> bytes:
    """Salta el header radiotap que mac80211 antepone en monitor RX.

    radiotap: version(u8)=0, pad(u8)=0, len(u16 LE), bitmap(u32)...
    El primer byte de un frame 802.11 normal (beacon 0x80, data 0x08/0x88,
    control 0xB4/0xC4/0xD4) nunca es 0x00, así que la heurística es segura
    salvo para frames de asociación (raros).
    """
    if len(pkt) >= 8 and pkt[0] == 0 and pkt[1] == 0:
        rt_len = struct.unpack("<H", pkt[2:4])[0]
        if 8 <= rt_len <= 600 and rt_len <= len(pkt):
            return pkt[rt_len:]
    return pkt


def capture_on_iface(seconds: int) -> dict:
    """Captura frames crudos con AF_PACKET y clasifica frames 802.11."""
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    s.bind((IFACE, 0))
    s.settimeout(0.5)

    counts = {"frames": 0, "beacon": 0, "probe_resp": 0, "probe_req": 0,
              "data": 0, "ctrl": 0, "bad": 0, "outgoing": 0}
    seen_bssids: set[str] = set()
    ssids: dict[str, str] = {}
    deadline = time.time() + seconds

    def mac(b: bytes) -> str:
        return ":".join(f"{x:02x}" for x in b)

    def extract_ssid(body: bytes, bssid: str):
        """IEs del cuerpo de un beacon/probe-response (SSID = IE 0)."""
        i = 0
        while i + 1 < len(body):
            ie_id, ie_len = body[i], body[i + 1]
            if i + 2 + ie_len > len(body):
                break
            if ie_id == 0:
                if ie_len > 0:
                    try:
                        ssids[bssid] = body[i + 2:i + 2 + ie_len].decode("utf-8")
                    except UnicodeDecodeError:
                        ssids[bssid] = repr(body[i + 2:i + 2 + ie_len])
                break
            i += 2 + ie_len

    while time.time() < deadline:
        try:
            pkt, (_ifname, _proto, pkttype, _hatype, _halen) = s.recvfrom(65535)
        except socket.timeout:
            continue
        if pkttype == PACKET_OUTGOING:  # eco nuestro, no tráfico del aire
            counts["outgoing"] += 1
            continue
        counts["frames"] += 1

        f = strip_radiotap(pkt)
        if len(f) < 24:
            counts["bad"] += 1
            continue

        fc = struct.unpack("<H", f[0:2])[0]
        ftype = (fc >> 2) & 0x3
        subtype = (fc >> 4) & 0xF
        bssid = mac(f[16:22])  # addr3: BSSID en frames de gestión

        if ftype == 0:
            if subtype == 8:      # beacon
                counts["beacon"] += 1
                seen_bssids.add(bssid)
                if len(f) > 36:
                    extract_ssid(f[36:], bssid)
            elif subtype == 5:    # probe response
                counts["probe_resp"] += 1
                seen_bssids.add(bssid)
                if len(f) > 36:
                    extract_ssid(f[36:], bssid)
            elif subtype == 4:    # probe request (clientes buscando redes)
                counts["probe_req"] += 1
            else:
                counts["ctrl"] += 0  # gestión variada; la contamos abajo
                counts["bad"] += 0
        elif ftype == 1:
            counts["ctrl"] += 1   # RTS/CTS/ACK
        elif ftype == 2:
            counts["data"] += 1
        else:
            counts["bad"] += 1

    s.close()
    return {"counts": counts, "bssids": seen_bssids, "ssids": ssids}


def hop_and_capture() -> list[tuple[int, dict]]:
    results = []
    for ch in CHANNELS:
        rc, out = run(f"iw dev {IFACE} set channel {ch}")
        if rc != 0:
            print(f"    canal {ch}: FALLO al fijar ({out})")
            results.append((ch, None))
            continue
        print(f"  -- canal {ch} ({2412 + (ch - 1) * 5} MHz) --")
        r = capture_on_iface(CAPTURE_SECONDS)
        c = r["counts"]
        print(f"     frames del aire: {c['frames']:5d}  "
              f"(beacons: {c['beacon']}, probe-resp: {c['probe_resp']}, "
              f"data: {c['data']}, control: {c['ctrl']})")
        for bssid, ssid in list(r["ssids"].items())[:6]:
            print(f"     AP: {bssid}  '{ssid}'")
        if not r["ssids"] and c["beacon"] == 0:
            print("     (sin beacons en este canal)")
        results.append((ch, r))
    return results


def main() -> int:
    print("=" * 70)
    print("PRUEBA DE MONITOR MODE - FWMonitor (Linux/Arch)")
    print("=" * 70)

    if run("id -u")[0] != 0:
        print("ERROR: ejecutar con sudo (root).")
        return 1

    rc, _ = run(f"ip link show {IFACE}")
    if rc != 0:
        print(f"ERROR: no existe la interfaz {IFACE}")
        return 1

    # rfkill
    _, out = run("rfkill list")
    wifi_blocked = False
    for block in out.split("\n"):
        pass
    blocks: dict[str, str] = {}
    current_id = ""
    for line in out.splitlines():
        if line and line[0].isdigit():
            current_id = line.strip()
            blocks[current_id] = ""
        elif current_id:
            blocks[current_id] += line + "\n"
    for _id, body in blocks.items():
        if "Wireless LAN" in body and "yes" in body:
            wifi_blocked = True
    if wifi_blocked:
        print("ERROR: la WiFi está bloqueada por rfkill (rfkill unblock wifi).")
        return 1

    print(f"\n[0] Estado inicial de {IFACE}:")
    print(f"    modo: {current_mode(IFACE)}")
    _, out = run(f"iw dev {IFACE} link")
    if out:
        print(f"    {out.splitlines()[0][:70]}")
    rc, out = run(f"nmcli -g GENERAL.CONNECTION device show {IFACE}")
    nm_conn = out.strip().splitlines()[0] if rc == 0 and out and out.strip() != "--" else ""
    print(f"    conexión NetworkManager: {nm_conn or '(ninguna)'}")

    results: list[tuple[int, dict]] = []
    try:
        # --- 1. Sacar la interfaz del control de NM y desconectar ---
        # Intel/iwlwifi no permite managed+monitor a la vez (no está en las
        # valid interface combinations), y hay que evitar que NM reconecte.
        print("\n[1] Desconectando y poniendo wlan0 fuera del control de NM...")
        if nm_conn:
            run(f"nmcli device disconnect {IFACE}")
            time.sleep(1)
        run(f"nmcli device set {IFACE} managed no")

        # --- 2. Modo monitor ---
        print(f"\n[2] iw dev {IFACE} set type monitor")
        run(f"ip link set {IFACE} down")
        rc, out = run(f"iw dev {IFACE} set type monitor")
        if rc != 0:
            print(f"    nl80211 falló: {out}")
            print("    Probando vía wireless extensions (SIOCSIWMODE)...")
            if not set_monitor_via_wext(IFACE):
                print("    FALLO también por WEXT: el driver no permite monitor.")
                _, dmesg = run("dmesg | grep -i iwlwifi | tail -5")
                if dmesg:
                    print(f"    Últimas líneas de dmesg:\n    {dmesg}")
                return 1
        mode = current_mode(IFACE)
        print(f"    modo ahora: {mode}")
        if "monitor" not in mode:
            print("    FALLO: la interfaz no quedó en modo monitor.")
            return 1
        run(f"ip link set {IFACE} up")
        time.sleep(0.5)
        print("    OK: interfaz en modo monitor")

        # --- 3. Captura + channel hopping ---
        print(f"\n[3] Capturando {CAPTURE_SECONDS}s por canal en {CHANNELS}...")
        results = hop_and_capture()

        total_beacons = sum(r["counts"]["beacon"] for _, r in results if r)
        if total_beacons == 0:
            print("\n    Sin beacons. Reintentando con flags otherbss+control...")
            run(f"ip link set {IFACE} down")
            rc, out = run(f"iw dev {IFACE} set monitor otherbss control")
            if rc == 0:
                run(f"ip link set {IFACE} up")
                time.sleep(0.5)
                results = hop_and_capture()
                total_beacons = sum(r["counts"]["beacon"] for _, r in results if r)
            else:
                print(f"    set monitor otherbss falló: {out}")

        # --- 4. Resumen ---
        print("\n[4] RESUMEN")
        valid = [(ch, r) for ch, r in results if r]
        total_frames = sum(r["counts"]["frames"] for _, r in valid)
        total_data = sum(r["counts"]["data"] for _, r in valid)
        all_bssids: set[str] = set()
        for _, r in valid:
            all_bssids |= r["bssids"]
        print(f"    Canales probados: {[ch for ch, r in valid]}")
        print(f"    Frames del aire: {total_frames}  (beacons: {total_beacons}, data: {total_data})")
        print(f"    APs distintos vistos: {len(all_bssids)}")
        for _, r in valid:
            for b, s in r["ssids"].items():
                print(f"      {b}  '{s}'")

        if total_beacons > 0:
            print("\n    ✔ MONITOR MODE FUNCIONAL: beacons 802.11 capturados del aire")
            print("      y el channel hopping cambió de canal con éxito.")
            print("      Conclusión: FWMonitor puede implementar captura pasiva en")
            print("      Rust (neli CMD_SET_INTERFACE_TYPE + AF_PACKET + set_channel).")
            verdict = 0
        else:
            print("\n    ✘ Se entró en modo monitor pero no llegaron beacons.")
            print("      Causas típicas: APs lejanos / solo 5 GHz en el aire cercano,")
            print("      o firmware que filtra. Prueba de nuevo cerca del router.")
            verdict = 1
        return verdict

    finally:
        # --- Restaurar SIEMPRE ---
        print("\n[Restaurando interfaz...]")
        run(f"ip link set {IFACE} down")
        run(f"iw dev {IFACE} set type managed")
        run(f"ip link set {IFACE} up")
        run(f"nmcli device set {IFACE} managed yes")
        print(f"    modo: {current_mode(IFACE)}")
        if nm_conn:
            run(f"nmcli connection up '{nm_conn}'")
            time.sleep(2)
            _, out = run(f"iw dev {IFACE} link")
            print(f"    reconectada: {out.splitlines()[0][:70] if out else '(NM reconectará solo)'}")
        else:
            run(f"nmcli device connect {IFACE}")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrumpido: restaurando interfaz...")
        run(f"ip link set {IFACE} down")
        run(f"iw dev {IFACE} set type managed")
        run(f"ip link set {IFACE} up")
        run(f"nmcli device set {IFACE} managed yes")
        run(f"nmcli device connect {IFACE}")
        sys.exit(130)
