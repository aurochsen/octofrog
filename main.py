#!/usr/bin/env python3
"""
Wireless Audit Tool — authorized lab environments only.
Run as root. Requires aircrack-ng suite.
"""

import sys

from rich import print as rprint
from rich.table import Table
from rich import box

import utils
import scanner
import deauth as deauth_mod
import capture as capture_mod


OUTPUT_DIR = "pcaps/"


def prompt_interface():
    interfaces = utils.list_interfaces()
    if not interfaces:
        rprint("[red][-] No wireless interfaces found. Ensure wireless hardware is available.[/red]")
        sys.exit(1)

    rprint("\n[cyan]Available wireless interfaces:[/cyan]")
    for i, iface in enumerate(interfaces, 1):
        print(f"  [{i}] {iface}")

    while True:
        try:
            choice = input("\nSelect interface number: ").strip()
            idx = int(choice) - 1
            if 0 <= idx < len(interfaces):
                return interfaces[idx]
        except (ValueError, KeyboardInterrupt):
            pass
        rprint("[yellow]Invalid selection.[/yellow]")


def select_targets(ap_list):
    if not ap_list:
        rprint("[yellow][-] No APs available. Run a scan first.[/yellow]")
        return []

    scanner.display_ap_table(ap_list)
    rprint('\nEnter AP numbers to target (comma-separated) or [bold]all[/bold]:')

    while True:
        try:
            raw = input("Selection: ").strip()
        except KeyboardInterrupt:
            return []

        if not raw:
            continue

        if raw.lower() == "all":
            selected = list(ap_list)
            break

        try:
            indices = [int(x.strip()) - 1 for x in raw.split(",")]
            if all(0 <= i < len(ap_list) for i in indices):
                selected = [ap_list[i] for i in indices]
                break
        except ValueError:
            pass
        rprint("[yellow]Invalid input. Enter numbers like 1,3,5 or 'all'.[/yellow]")

    rprint("\n[cyan]Selected targets:[/cyan]")
    for ap in selected:
        rprint(f"  [white]{ap['essid']}[/white] ({ap['bssid']}) ch {ap['channel']}")
    try:
        confirm = input("\nConfirm? [y/N]: ").strip().lower()
    except KeyboardInterrupt:
        return []

    return selected if confirm == "y" else []


def do_scan(state):
    if not state["monitor_iface"]:
        try:
            iface = state["iface"]
            # Stop NetworkManager/wpa_supplicant first so they don't grab the
            # interface out from under monitor mode / airodump-ng.
            if not state["services_killed"]:
                state["stopped_services"] = utils.kill_interfering_processes()
                state["services_killed"] = True
            state["monitor_iface"] = scanner.enable_monitor_mode(iface)
        except Exception as e:
            rprint(f"[red][-] Failed to enable monitor mode: {e}[/red]")
            return

    try:
        duration = 15
        raw = input("Scan duration in seconds [15]: ").strip()
        if raw.isdigit():
            duration = int(raw)
    except KeyboardInterrupt:
        return

    try:
        aps = scanner.scan_aps(state["monitor_iface"], duration=duration)
        state["last_scan"] = aps
        scanner.display_ap_table(aps)
    except Exception as e:
        rprint(f"[red][-] Scan failed: {e}[/red]")


def do_select(state):
    if not state["last_scan"]:
        rprint("[yellow][-] No scan results. Run a scan first.[/yellow]")
        return
    state["selected"] = select_targets(state["last_scan"])


def do_capture(state):
    if not state["selected"]:
        rprint("[yellow][-] No targets selected. Select targets first.[/yellow]")
        return
    if not state["monitor_iface"]:
        rprint("[yellow][-] No monitor interface. Run a scan first.[/yellow]")
        return

    utils.ensure_output_dir(OUTPUT_DIR)

    for ap in state["selected"]:
        bssid = ap["bssid"]
        essid = ap["essid"]
        channel = ap["channel"]

        rprint(f"\n[cyan][*] Processing target: {essid} ({bssid}) ch {channel}[/cyan]")

        # Start deauth in background thread
        deauth_thread, stop_event = deauth_mod.start_deauth_thread(
            state["monitor_iface"], bssid, channel
        )

        try:
            success, pcap_path = capture_mod.start_capture(
                state["monitor_iface"], bssid, channel, essid,
                output_dir=OUTPUT_DIR
            )
        finally:
            stop_event.set()
            deauth_thread.join(timeout=10)

        if success:
            state["captured"].append(pcap_path)


def do_list_pcaps():
    pcaps = utils.list_pcaps(OUTPUT_DIR)
    if not pcaps:
        rprint("[yellow][-] No pcap files saved yet.[/yellow]")
        return

    table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
    table.add_column("Filename", style="white")
    table.add_column("Size (KB)", justify="right")
    table.add_column("Modified", style="dim")

    for p in pcaps:
        table.add_row(p["name"], f"{p['size_kb']:.1f}", p["modified"])

    from rich.console import Console
    Console().print(table)


def main_menu(state):
    menu = """
[bold cyan]Wireless Audit Tool[/bold cyan]
  [1] Scan for APs
  [2] Select targets
  [3] Start capture
  [4] List saved pcaps
  [5] Exit
"""
    rprint(menu)
    try:
        return input("Choice: ").strip()
    except KeyboardInterrupt:
        return "5"


def main():
    utils.check_root()
    utils.check_tools()
    utils.ensure_output_dir(OUTPUT_DIR)

    rprint("[bold cyan]Wireless Audit Tool — authorized use only[/bold cyan]")

    iface = prompt_interface()
    state = {
        "iface": iface,
        "monitor_iface": None,
        "last_scan": [],
        "selected": [],
        "captured": [],
        "services_killed": False,
        "stopped_services": [],
    }

    try:
        while True:
            try:
                choice = main_menu(state)
            except KeyboardInterrupt:
                choice = "5"

            if choice == "1":
                do_scan(state)
            elif choice == "2":
                do_select(state)
            elif choice == "3":
                do_capture(state)
            elif choice == "4":
                do_list_pcaps()
            elif choice == "5":
                rprint("[cyan][*] Goodbye.[/cyan]")
                break
            else:
                rprint("[yellow]Invalid choice.[/yellow]")
    finally:
        cleanup(state)


def cleanup(state):
    """Restore the interface and any network services we stopped."""
    utils.restore_managed_mode(state.get("monitor_iface"))
    utils.restore_network_services(state.get("stopped_services", []))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        rprint("\n[cyan][*] Interrupted. Exiting cleanly.[/cyan]")
        sys.exit(0)
