import csv
import shutil
import signal
import subprocess
import time
import os
import re
from pathlib import Path

from rich import print as rprint
from rich.table import Table
from rich import box


def enable_monitor_mode(iface):
    """
    Put iface into monitor mode and return the monitor interface name.

    Tries airmon-ng first, then falls back to the manual iw/ip method. Every
    path is verified against the kernel's actual interface type before being
    accepted, so we never return an interface that isn't really in monitor mode.
    Returns None if monitor mode could not be established.
    """
    rprint(f"[cyan][*] Enabling monitor mode on {iface}...[/cyan]")

    # Already in monitor mode for this specific iface?
    existing = _find_monitor_iface(iface)
    if existing:
        rprint(f"[yellow][*] Monitor interface {existing} already exists, reusing.[/yellow]")
        return existing

    # --- Method 1: airmon-ng ---
    result = subprocess.run(
        ["airmon-ng", "start", iface],
        capture_output=True, text=True, timeout=20
    )
    mon = _find_monitor_iface(iface)
    if mon and _iface_mode(mon) == "monitor":
        rprint(f"[green][+] Monitor mode enabled via airmon-ng: {mon}[/green]")
        return mon

    rprint("[yellow][*] airmon-ng did not produce a monitor interface, trying manual method...[/yellow]")
    if result.stdout.strip():
        for line in result.stdout.strip().splitlines()[-4:]:
            rprint(f"[yellow]    {line.strip()}[/yellow]")

    # --- Method 2: manual iw/ip (keeps the same interface name) ---
    if _manual_monitor(iface):
        rprint(f"[green][+] Monitor mode enabled via iw: {iface}[/green]")
        return iface

    # --- Failed ---
    mode = _iface_mode(iface)
    rprint(f"[red][-] Failed to enable monitor mode on {iface} (current mode: {mode}).[/red]")
    _report_monitor_failure(iface)
    return None


def _driver_name(iface):
    """Return the kernel driver bound to iface (e.g. '88XXau', 'rtl8812au')."""
    try:
        link = os.readlink(f"/sys/class/net/{iface}/device/driver")
        return os.path.basename(link)
    except OSError:
        return None


def _supports_monitor(iface):
    """Return True if the adapter's phy advertises monitor mode in 'iw list'."""
    try:
        out = subprocess.run(["iw", "list"], capture_output=True, text=True, timeout=8).stdout
    except Exception:
        return None
    # Look inside the "Supported interface modes" block for "monitor".
    m = re.search(r"Supported interface modes:(.*?)(?:\n\s*\n|\Z)", out, re.DOTALL)
    if not m:
        return None
    return "monitor" in m.group(1).lower()


def _report_monitor_failure(iface):
    driver = _driver_name(iface)
    supports = _supports_monitor(iface)

    if driver:
        rprint(f"[yellow][*] Driver bound to {iface}: {driver}[/yellow]")

    # RTL8812AU (ALFA AWUS036ACH) is the classic case: needs the out-of-tree
    # driver, and if the loaded driver lacks monitor support nothing can set it.
    is_realtek = driver and re.search(r"88\d\dau|rtl88", driver, re.IGNORECASE)

    if supports is False or (is_realtek and supports is not True):
        rprint(
            "[red][-] This adapter's driver does not advertise monitor mode.[/red]"
        )
        if is_realtek:
            rprint(
                "[yellow][*] RTL8812AU adapters (e.g. ALFA AWUS036ACH) need the "
                "aircrack-ng RTL8812AU driver. On Kali/Debian:[/yellow]"
            )
            rprint("[yellow]    sudo apt update && sudo apt install realtek-rtl88xxau-dkms[/yellow]")
            rprint("[yellow]    then replug the adapter (or reboot) and retry.[/yellow]")
        else:
            rprint(
                "[yellow][*] Install/replace the adapter's driver with one that "
                "supports monitor mode, or use a different adapter.[/yellow]")
    else:
        rprint(
            "[yellow][*] A process may still be holding the interface. Ensure "
            "NetworkManager/wpa_supplicant are stopped and retry. Verify support "
            "with 'iw list' under 'Supported interface modes'.[/yellow]"
        )


def _manual_monitor(iface):
    """Switch iface to monitor mode via iw/ip. Returns True on verified success."""
    cmds = [
        ["ip", "link", "set", iface, "down"],
        ["iw", "dev", iface, "set", "type", "monitor"],
        ["ip", "link", "set", iface, "up"],
    ]
    for cmd in cmds:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if r.returncode != 0 and r.stderr.strip():
                rprint(f"[yellow]    {' '.join(cmd)}: {r.stderr.strip()}[/yellow]")
        except Exception as e:
            rprint(f"[yellow]    {' '.join(cmd)} failed: {e}[/yellow]")
            return False
    return _iface_mode(iface) == "monitor"


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


def _iface_mode(iface):
    """Return the current type/mode of iface (e.g. 'monitor', 'managed') or None."""
    try:
        result = subprocess.run(
            ["iw", "dev", iface, "info"], capture_output=True, text=True, timeout=5
        )
        m = re.search(r"type (\w+)", result.stdout)
        return m.group(1) if m else None
    except Exception:
        return None


def _bring_iface_up(iface):
    """Ensure the interface is administratively UP; airodump-ng needs this."""
    try:
        subprocess.run(["ip", "link", "set", iface, "up"], capture_output=True, timeout=5)
    except Exception:
        pass


def scan_aps(monitor_iface, duration=15, band="abg"):
    """
    Run airodump-ng for duration seconds, parse CSV, return list of AP dicts.

    band selects which frequency bands to scan:
      'bg'  = 2.4 GHz only (airodump-ng default)
      'a'   = 5 GHz only
      'abg' = both 2.4 and 5 GHz (default here — dual-band adapters like the
              AWUS036ACH otherwise miss 5 GHz APs, which airodump does not
              scan unless told to).
    """
    rprint(f"[cyan][*] Scanning for APs on {monitor_iface} (band {band})... ({duration}s)[/cyan]")

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

    # airodump-ng silently captures nothing on a down or non-monitor interface.
    mode = _iface_mode(monitor_iface)
    if mode and mode != "monitor":
        rprint(
            f"[red][-] Interface '{monitor_iface}' is in '{mode}' mode, not monitor. "
            f"Monitor mode setup failed.[/red]"
        )
        return []
    _bring_iface_up(monitor_iface)

    # Use a fixed, persistent directory (not an auto-deleted tempdir) so the
    # CSV and log survive after the scan and can be inspected / compared with a
    # manual run.
    scan_dir = "/tmp/wifiaudit_scan"
    _reset_scan_dir(scan_dir)
    prefix = os.path.join(scan_dir, "scan")
    log_path = os.path.join(scan_dir, "airodump.log")

    cmd = ["airodump-ng", "--write", prefix, "--output-format", "csv"]
    if band:
        cmd += ["--band", band]
    cmd.append(monitor_iface)

    # Show the exact command so it can be compared against a manual run.
    rprint(f"[cyan][*] Running: {' '.join(cmd)}[/cyan]")

    # Let airodump-ng write the CSV itself and just read it. Its live display
    # (stdout) is discarded; only stderr is kept for diagnostics. Redirect to
    # files, never an unread PIPE (a full pipe buffer blocks airodump-ng).
    exited_early = False
    returncode = None
    with open(log_path, "wb") as logf:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=logf)
        waited = 0.0
        while waited < duration:
            if proc.poll() is not None:
                exited_early = True
                break
            time.sleep(0.5)
            waited += 0.5
        if not exited_early:
            # Stop airodump-ng the same way a manual Ctrl-C does: SIGINT makes
            # it flush a complete CSV on exit. SIGTERM (proc.terminate) does
            # not, and can leave an empty file even though capture worked.
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
        returncode = proc.returncode

    # Give the filesystem a moment to settle after exit.
    time.sleep(0.5)
    log_tail = _read_log_tail(log_path)

    if exited_early:
        rprint(f"[red][-] airodump-ng exited early (code {returncode}).[/red]")
        _print_log(log_tail)
        _print_interference_hint()
        return []

    csv_file = prefix + "-01.csv"
    if not os.path.exists(csv_file):
        written = os.listdir(scan_dir) if os.path.isdir(scan_dir) else []
        rprint("[red][-] No scan output file was produced by airodump-ng.[/red]")
        if written:
            rprint(f"[yellow][*] Files in scan dir: {', '.join(written)}[/yellow]")
        _print_log(log_tail)
        _print_interference_hint()
        return []

    csv_size = os.path.getsize(csv_file)
    rprint(f"[cyan][*] Parsing {csv_file} ({csv_size} bytes)[/cyan]")

    aps = _parse_airodump_csv(csv_file)
    if not aps:
        # Monitor mode is confirmed and airodump ran, but caught no beacons.
        rprint("[yellow][-] No APs captured. Most likely causes:[/yellow]")
        rprint(
            f"[yellow]    - APs are on a band not scanned (this run used "
            f"band '{band}'). Try band 'abg' to include 5 GHz.[/yellow]"
        )
        rprint(
            "[yellow]    - A connection manager is still changing the "
            "channel (NetworkManager/wpa_supplicant).[/yellow]"
        )
        rprint(
            "[yellow]    - Scan too short; try a longer duration so every "
            "channel is visited.[/yellow]"
        )
        rprint(f"[yellow][*] Inspect the raw output: cat {csv_file}[/yellow]")
    return aps


def _reset_scan_dir(scan_dir):
    """Clear any previous scan output so we never read a stale CSV."""
    try:
        if os.path.isdir(scan_dir):
            shutil.rmtree(scan_dir)
        os.makedirs(scan_dir, exist_ok=True)
    except Exception:
        pass


def _read_log_tail(log_path, max_lines=10):
    """Read airodump-ng's log, stripping ANSI/curses control sequences."""
    try:
        with open(log_path, "r", errors="replace") as f:
            content = f.read()
    except Exception:
        return []
    # Strip ANSI escape sequences from the live display.
    content = re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", content)
    content = content.replace("\r", "\n")
    lines = [ln.strip() for ln in content.splitlines() if ln.strip()]
    return lines[-max_lines:]


def _print_log(lines):
    for line in lines:
        rprint(f"[yellow]    {line}[/yellow]")


def _print_interference_hint():
    rprint(
        "[yellow][*] Hint: another process (NetworkManager/wpa_supplicant) may be "
        "interfering, or the adapter left monitor mode. The tool runs "
        "'airmon-ng check kill' automatically; if scans stay empty, verify the "
        "adapter supports monitor mode with 'iw dev <iface> info'.[/yellow]"
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
