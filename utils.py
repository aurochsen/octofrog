import os
import sys
import shutil
import subprocess
from pathlib import Path
from datetime import datetime

from rich import print as rprint


def check_root():
    if os.geteuid() != 0:
        rprint("[red][-] This tool must be run as root.[/red]")
        sys.exit(1)


def check_tools():
    required = ["airmon-ng", "airodump-ng", "aireplay-ng"]
    missing = [t for t in required if not shutil.which(t)]
    if missing:
        rprint(f"[red][-] Missing required tools: {', '.join(missing)}[/red]")
        rprint("[red][-] Install aircrack-ng suite and try again.[/red]")
        sys.exit(1)


def list_interfaces():
    """Return list of wireless interface names."""
    interfaces = []
    try:
        result = subprocess.run(
            ["iw", "dev"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("Interface "):
                interfaces.append(line.split()[1])
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    if not interfaces:
        try:
            result = subprocess.run(
                ["iwconfig"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                if line and not line.startswith(" ") and "no wireless" not in line.lower():
                    iface = line.split()[0]
                    if iface:
                        interfaces.append(iface)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    return interfaces


def restore_managed_mode(monitor_iface):
    if not monitor_iface:
        return
    rprint(f"[cyan][*] Restoring managed mode for {monitor_iface}...[/cyan]")
    try:
        subprocess.run(
            ["airmon-ng", "stop", monitor_iface],
            capture_output=True, timeout=15
        )
        rprint(f"[green][+] Managed mode restored.[/green]")
    except Exception as e:
        rprint(f"[yellow][-] Could not restore managed mode: {e}[/yellow]")


def kill_interfering_processes():
    """
    Stop NetworkManager/wpa_supplicant so they don't fight airodump-ng for the
    interface. Returns a list of systemd services that were actually stopped,
    so they can be restarted on exit.
    """
    candidates = ["NetworkManager", "wpa_supplicant"]
    stopped = []
    for svc in candidates:
        try:
            active = subprocess.run(
                ["systemctl", "is-active", "--quiet", svc], timeout=5
            )
            if active.returncode == 0:
                subprocess.run(["systemctl", "stop", svc], capture_output=True, timeout=10)
                stopped.append(svc)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    # airmon-ng check kill also handles processes not managed by systemd
    try:
        subprocess.run(["airmon-ng", "check", "kill"], capture_output=True, timeout=15)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    if stopped:
        rprint(f"[yellow][*] Stopped interfering services: {', '.join(stopped)}[/yellow]")
    else:
        rprint("[cyan][*] Killed interfering processes (airmon-ng check kill)[/cyan]")
    return stopped


def restore_network_services(services):
    """Restart services previously stopped by kill_interfering_processes()."""
    if not services:
        return
    for svc in services:
        try:
            subprocess.run(["systemctl", "start", svc], capture_output=True, timeout=10)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            rprint(f"[yellow][-] Could not restart {svc}[/yellow]")
    rprint(f"[green][+] Restarted network services: {', '.join(services)}[/green]")


def list_pcaps(output_dir="pcaps/"):
    path = Path(output_dir)
    if not path.exists():
        return []
    files = sorted(path.glob("*.pcap"), key=lambda f: f.stat().st_mtime, reverse=True)
    results = []
    for f in files:
        stat = f.stat()
        size_kb = stat.st_size / 1024
        mtime = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        results.append({"name": f.name, "path": str(f), "size_kb": size_kb, "modified": mtime})
    return results


def ensure_output_dir(output_dir="pcaps/"):
    Path(output_dir).mkdir(parents=True, exist_ok=True)
