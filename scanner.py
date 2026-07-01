import csv
import subprocess
import tempfile
import time
import os
import re
from pathlib import Path

from rich import print as rprint
from rich.table import Table
from rich import box


def enable_monitor_mode(iface):
    """Start monitor mode on iface, return monitor interface name."""
    rprint(f"[cyan][*] Enabling monitor mode on {iface}...[/cyan]")

    # Check if monitor interface already exists
    existing = _find_monitor_iface(iface)
    if existing:
        rprint(f"[yellow][*] Monitor interface {existing} already exists, reusing.[/yellow]")
        return existing

    result = subprocess.run(
        ["airmon-ng", "start", iface],
        capture_output=True, text=True, timeout=20
    )

    # Parse monitor interface name from output
    for line in result.stdout.splitlines():
        m = re.search(r"monitor mode (?:vif )?enabled (?:for|on) \[?\w+\]?\)?.*?(\w+mon\w*)", line, re.IGNORECASE)
        if m:
            return m.group(1)
        m = re.search(r"([\w]+mon[\w]*)", line)
        if m:
            return m.group(1)

    # Fall back to common naming conventions
    candidates = [f"{iface}mon", "wlan0mon", "wlan1mon"]
    for c in candidates:
        check = subprocess.run(["ip", "link", "show", c], capture_output=True)
        if check.returncode == 0:
            return c

    rprint(f"[yellow][*] Could not detect monitor interface name, assuming {iface}mon[/yellow]")
    return f"{iface}mon"


def _find_monitor_iface(base_iface):
    """Look for an existing monitor-mode interface derived from base_iface."""
    try:
        result = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5)
        ifaces = re.findall(r"Interface (\S+)", result.stdout)
        for iface in ifaces:
            if "mon" in iface and base_iface.rstrip("0123456789") in iface:
                return iface
    except Exception:
        pass
    return None


def scan_aps(monitor_iface, duration=15):
    """Run airodump-ng for duration seconds, parse CSV, return list of AP dicts."""
    rprint(f"[cyan][*] Scanning for APs on {monitor_iface}... ({duration}s)[/cyan]")

    with tempfile.TemporaryDirectory(prefix="wifiaudit_scan_") as tmpdir:
        prefix = os.path.join(tmpdir, "scan")
        proc = subprocess.Popen(
            ["airodump-ng", "--write", prefix, "--output-format", "csv", monitor_iface],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(duration)
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

        csv_file = prefix + "-01.csv"
        if not os.path.exists(csv_file):
            rprint("[yellow][-] No scan output found.[/yellow]")
            return []

        return _parse_airodump_csv(csv_file)


def _parse_airodump_csv(csv_path):
    aps = []
    client_map = {}  # bssid -> client count

    with open(csv_path, "r", errors="replace") as f:
        content = f.read()

    # Split into AP section and client section
    sections = re.split(r"\r?\n\s*\r?\n", content)
    ap_section = sections[0] if sections else ""
    client_section = sections[1] if len(sections) > 1 else ""

    # Parse clients to count per BSSID
    client_lines = client_section.strip().splitlines()
    if len(client_lines) > 1:
        for line in client_lines[1:]:
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 6:
                bssid = parts[5].strip().upper()
                if re.match(r"([0-9A-F]{2}:){5}[0-9A-F]{2}", bssid):
                    client_map[bssid] = client_map.get(bssid, 0) + 1

    # Parse APs
    ap_lines = ap_section.strip().splitlines()
    if len(ap_lines) < 2:
        return []

    for line in ap_lines[1:]:
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 14:
            continue
        bssid = parts[0].strip().upper()
        if not re.match(r"([0-9A-F]{2}:){5}[0-9A-F]{2}", bssid):
            continue

        try:
            signal = int(parts[8]) if parts[8].strip().lstrip("-").isdigit() else 0
        except (ValueError, IndexError):
            signal = 0

        try:
            channel = int(parts[3].strip()) if parts[3].strip().lstrip("-").isdigit() else 0
        except (ValueError, IndexError):
            channel = 0

        essid = parts[13].strip() if len(parts) > 13 else "<hidden>"
        if not essid:
            essid = "<hidden>"

        encryption = parts[5].strip() if len(parts) > 5 else "?"

        aps.append({
            "bssid": bssid,
            "essid": essid,
            "channel": channel,
            "signal": signal,
            "encryption": encryption,
            "clients": client_map.get(bssid, 0),
        })

    # Sort by signal strength descending
    aps.sort(key=lambda x: x["signal"])
    return aps


def display_ap_table(ap_list):
    if not ap_list:
        rprint("[yellow][-] No APs found.[/yellow]")
        return

    table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
    table.add_column("#", style="dim", width=4)
    table.add_column("BSSID", style="white")
    table.add_column("ESSID", style="bright_white")
    table.add_column("CH", justify="right")
    table.add_column("Signal", justify="right")
    table.add_column("Encryption", style="yellow")
    table.add_column("Clients", justify="right")

    for i, ap in enumerate(ap_list, 1):
        signal_str = str(ap["signal"]) if ap["signal"] != 0 else "?"
        table.add_row(
            str(i),
            ap["bssid"],
            ap["essid"],
            str(ap["channel"]),
            signal_str,
            ap["encryption"],
            str(ap["clients"]),
        )

    from rich.console import Console
    Console().print(table)
    rprint(f"[green][+] Found {len(ap_list)} APs[/green]")
