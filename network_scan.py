import platform
import scapy.all as scapy
import os
import socket
import threading
import requests
from influxdb_client import InfluxDBClient, Point, WriteOptions
from dotenv import load_dotenv
import time
from influxdb_client import QueryApi


# Load environment variables from .env
load_dotenv()

# InfluxDB
INFLUX_URL = os.getenv("INFLUX_URL", "http://homeassistant.local:8086")
INFLUX_TOKEN = os.getenv("INFLUX_TOKEN")
INFLUX_ORG = os.getenv("INFLUX_ORG", "home_assistant")
INFLUX_BUCKET = os.getenv("INFLUX_BUCKET", "network_monitor")

# Home Assistant
HA_URL = os.getenv("HA_URL", "http://homeassistant.local:8123")
HA_TOKEN = os.getenv("HA_TOKEN")


def notify_home_assistant(title, message):
    """Sends a persistent notification to Home Assistant via the REST API."""
    if not HA_TOKEN:
        print("⚠️  HA_TOKEN not set, skipping Home Assistant notification.")
        return

    url = f"{HA_URL}/api/services/persistent_notification/create"
    headers = {
        "Authorization": f"Bearer {HA_TOKEN}",
        "Content-Type": "application/json",
    }
    payload = {"title": title, "message": message}

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=5)
        response.raise_for_status()
        print(f"✅ Home Assistant notified: {title}")
    except requests.RequestException as e:
        print(f"❌ Failed to notify Home Assistant: {e}")


def detect_network_changes(devices):
    """Compares current scan with past scan data from InfluxDB to detect new/missing devices."""
    client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
    query_api = client.query_api()

    query = f'''
    from(bucket: "{INFLUX_BUCKET}")
      |> range(start: -10m)
      |> filter(fn: (r) => r._measurement == "network_scan")
    '''
    result = query_api.query(org=INFLUX_ORG, query=query)

    previous_macs = set()
    for table in result:
        for record in table.records:
            previous_macs.add(record.values["device_mac"])

    current_macs = {device["mac"] for device in devices}

    new_devices = current_macs - previous_macs
    missing_devices = previous_macs - current_macs

    client.close()

    return new_devices, missing_devices


def write_to_influx(devices):
    """Stores network scan results in InfluxDB and ensures all writes complete before exit."""
    client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
    write_api = client.write_api(write_options=WriteOptions(batch_size=1))

    for device in devices:
        point = Point("network_scan") \
            .tag("device_mac", device["mac"]) \
            .field("device_ip", device["ip"]) \
            .field("hostname", device["hostname"]) \
            .field("last_seen", int(time.time()))  # Store timestamp

        write_api.write(bucket=INFLUX_BUCKET, record=point)

    # ✅ Ensure all pending writes are processed before closing
    write_api.flush()  # Ensures everything is written
    write_api.__del__()  # 🔹 Explicitly release InfluxDB client resources
    client.close()  # Properly close the client
    print("✅ InfluxDB write complete and connection closed.")



# Detect the OS
os_name = platform.system()

if os_name == "Windows":
    print("🔹 Running on Windows: Ensure Npcap is installed!")
elif os_name == "Linux":
    print("🔹 Running on Linux/HAOS: No extra setup needed.")
else:
    print(f"🔹 Running on {os_name}: Compatibility not tested.")

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
    devices = scan_network(resolve_hostnames=False)

    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}")

    # Store scan in InfluxDB
    write_to_influx(devices)

    # Detect network changes
    new_devices, missing_devices = detect_network_changes(devices)

    if new_devices:
        print(f"🔔 New Devices Detected: {new_devices}")
        notify_home_assistant(
            title="Network Monitor: New Device",
            message=f"New device(s) joined the network: {', '.join(new_devices)}",
        )

    if missing_devices:
        print(f"⚠️ Missing Devices: {missing_devices}")
        notify_home_assistant(
            title="Network Monitor: Device Offline",
            message=f"Device(s) no longer visible: {', '.join(missing_devices)}",
        )
