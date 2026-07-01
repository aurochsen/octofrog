import os
import re
import subprocess
import time
from datetime import datetime
from pathlib import Path

from rich import print as rprint


def _sanitize_essid(essid):
    """Strip special chars from ESSID for use in filenames."""
    essid = re.sub(r"[^\w\-]", "_", essid)
    return essid[:32]


def _pcap_filename(essid, bssid, output_dir):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    bssid_clean = bssid.replace(":", "")
    name = f"{_sanitize_essid(essid)}_{bssid_clean}_{ts}"
    return os.path.join(output_dir, name)


def check_handshake(pcap_path):
    """Return True if pcap contains EAPOL frames (WPA handshake indicator)."""
    # scapy is imported here to avoid slow startup when not needed
    try:
        from scapy.all import rdpcap, EAPOL  # type: ignore
        packets = rdpcap(pcap_path)
        return any(pkt.haslayer(EAPOL) for pkt in packets)
    except Exception:
        return False


def start_capture(monitor_iface, bssid, channel, essid, output_dir="pcaps/", timeout=60):
    """
    Run targeted airodump-ng capture and poll for WPA handshake.
    Returns (success: bool, pcap_path: str).
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    output_prefix = _pcap_filename(essid, bssid, output_dir)
    pcap_path = output_prefix + "-01.cap"

    rprint(f"[cyan][*] Starting capture on {essid} ({bssid}) channel {channel}[/cyan]")

    proc = subprocess.Popen(
        [
            "airodump-ng",
            "-c", str(channel),
            "--bssid", bssid,
            "-w", output_prefix,
            "--output-format", "pcap",
            monitor_iface,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    start_time = time.time()
    elapsed = 0
    success = False

    try:
        while elapsed < timeout:
            time.sleep(5)
            elapsed = int(time.time() - start_time)
            mins, secs = divmod(elapsed, 60)
            rprint(f"[cyan][*] Checking for handshake... ({mins}:{secs:02d})[/cyan]")

            if os.path.exists(pcap_path) and check_handshake(pcap_path):
                success = True
                break
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    if success:
        # Rename to final friendly filename
        final_path = output_prefix + ".pcap"
        try:
            os.rename(pcap_path, final_path)
            pcap_path = final_path
        except OSError:
            pass
        rprint(f"[green][+] Handshake captured! Saved to {pcap_path}[/green]")
    else:
        rprint(f"[red][-] Timeout reached for {essid} — no handshake captured[/red]")

    return success, pcap_path
