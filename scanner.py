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

    # Check if a monitor interface for this specific iface already exists
    existing = _find_monitor_iface(iface)
    if existing:
        rprint(f"[yellow][*] Monitor interface {existing} already exists, reusing.[/yellow]")
        return existing

    subprocess.run(
        ["airmon-ng", "start", iface],
        capture_output=True, text=True, timeout=20
    )

    # Authoritative: ask the kernel what monitor interfaces exist for this iface
    monitor_iface = _find_monitor_iface(iface)
    if monitor_iface:
        return monitor_iface

    # Last resort: assume standard naming
    assumed = f"{iface}mon"
    rprint(f"[yellow][*] Could not detect monitor interface name, assuming {assumed}[/yellow]")
    return assumed


def _find_monitor_iface(base_iface):
    """Return an existing monitor-mode interface created from base_iface, or None."""
    try:
        result = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5)
    except Exception:
        return None

    # Parse blocks: each PHY block lists Interface + type lines
    # We want interfaces in monitor type whose name starts with base_iface
    current_iface = None
    for line in result.stdout.splitlines():
        line = line.strip()
        m = re.match(r"Interface (\S+)", line)
        if m:
            current_iface = m.group(1)
            continue
        if current_iface and re.match(r"type monitor", line, re.IGNORECASE):
            # Only match if this monitor interface belongs to the selected iface.
            # airmon-ng names the monitor iface after the base (wlan1 -> wlan1mon).
            if current_iface.startswith(base_iface):
                return current_iface

    return None


def _iface_exists(iface):
    """Return True if the given network interface currently exists."""
    try:
        result = subprocess.run(
            ["iw", "dev"], capture_output=True, text=True, timeout=5
        )
        return iface in re.findall(r"Interface (\S+)", result.stdout)
    except Exception:
        return False


def scan_aps(monitor_iface, duration=15):
    """Run airodump-ng for duration seconds, parse CSV, return list of AP dicts."""
    rprint(f"[cyan][*] Scanning for APs on {monitor_iface}... ({duration}s)[/cyan]")

    if not _iface_exists(monitor_iface):
        rprint(
            f"[red][-] Interface '{monitor_iface}' does not exist. "
            f"Monitor mode may have failed to start.[/red]"
        )
        rprint("[yellow][*] Current interfaces:[/yellow]")
        try:
            out = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5).stdout
            for m in re.findall(r"Interface (\S+)", out):
                rprint(f"    - {m}")
        except Exception:
            pass
        return []

    with tempfile.TemporaryDirectory(prefix="wifiaudit_scan_") as tmpdir:
        prefix = os.path.join(tmpdir, "scan")
        proc = subprocess.Popen(
            ["airodump-ng", "--write", prefix, "--output-format", "csv", monitor_iface],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

        # Watch for early exit: airodump-ng normally runs until terminated.
        waited = 0.0
        interval = 0.5
        while waited < duration:
            if proc.poll() is not None:
                # Process died on its own — capture and report why.
                output = proc.stdout.read() if proc.stdout else ""
                rprint(
                    f"[red][-] airodump-ng exited early (code {proc.returncode}).[/red]"
                )
                if output.strip():
                    for line in output.strip().splitlines()[-8:]:
                        rprint(f"[yellow]    {line.strip()}[/yellow]")
                _print_interference_hint()
                return []
            time.sleep(interval)
            waited += interval

        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

        csv_file = prefix + "-01.csv"
        if not os.path.exists(csv_file):
            # Check whether other files were written at all.
            written = os.listdir(tmpdir)
            rprint("[red][-] No scan output file was produced by airodump-ng.[/red]")
            if written:
                rprint(f"[yellow][*] Files in scan dir: {', '.join(written)}[/yellow]")
            output = proc.stdout.read() if proc.stdout else ""
            if output.strip():
                for line in output.strip().splitlines()[-8:]:
                    rprint(f"[yellow]    {line.strip()}[/yellow]")
            _print_interference_hint()
            return []

        return _parse_airodump_csv(csv_file)


def _print_interference_hint():
    rprint(
        "[yellow][*] Hint: another process (NetworkManager/wpa_supplicant) may be "
        "interfering. Try 'airmon-ng check kill' before scanning.[/yellow]"
    )


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

    # Strongest signal first (dBm closest to 0); unknown (0) sorts to the end.
    aps.sort(key=lambda x: (x["signal"] == 0, -x["signal"]))
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
