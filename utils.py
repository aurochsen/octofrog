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
