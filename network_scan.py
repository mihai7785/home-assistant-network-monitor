import platform
import scapy.all as scapy
import json
import os
import socket
import threading

# Detect the OS
os_name = platform.system()

if os_name == "Windows":
    print("🔹 Running on Windows: Ensure Npcap is installed!")
elif os_name == "Linux":
    print("🔹 Running on Linux/HAOS: No extra setup needed.")
else:
    print(f"🔹 Running on {os_name}: Compatibility not tested.")

import socket
import threading

def get_hostname(ip, timeout=2, dns_servers=None):
    """Attempts to get the hostname of a device with multiple lookup strategies."""
    result = ["Unknown"]

    def lookup():
        try:
            # First, try the default system resolver
            result[0] = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.timeout):
            # If system resolver fails, try alternative DNS servers
            if dns_servers:
                for dns in dns_servers:
                    try:
                        result[0] = socket.gethostbyaddr(ip, (dns,))
                        break  # Stop once we get a valid hostname
                    except (socket.herror, socket.timeout):
                        continue

    thread = threading.Thread(target=lookup)
    thread.start()
    thread.join(timeout)

    return result[0]


def scan_network(ip_range="192.168.1.1/24", resolve_hostnames=False):
    """Scans the network using ARP and optionally resolves hostnames."""
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    devices = []
    for element in answered_list:
        ip = element[1].psrc
        mac = element[1].hwsrc
        hostname = "Unknown"

        if resolve_hostnames:
            hostname = get_hostname(ip)

        devices.append({
            "ip": ip,
            "mac": mac,
            "hostname": hostname
        })

    return devices
      

if __name__ == "__main__":
    devices = scan_network()
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}")
