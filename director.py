import requests
import json
import csv
import xml.etree.ElementTree as ET
import feedparser
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor
from requests.exceptions import RequestException, Timeout, ConnectionError, HTTPError
import re
from scapy.all import sniff, IP, DNS, Raw, TCP
from collections import defaultdict, deque
import matplotlib.pyplot as plt
import matplotlib.animation as animation
from matplotlib import style
import threading
import time
import subprocess

# Initialize global data structures
data_usage = defaultdict(lambda: deque([0]*50, maxlen=50))  # ECG-style data usage tracking for each IP
dns_queries = defaultdict(set)  # Set to track DNS queries per IP
http_hosts = defaultdict(set)  # Set to track HTTP hosts per IP
device_info = {}  # Dictionary to store device info (device name, IP address, MAC address)

# Packet processing function
def process_packet(packet):
    # DNS query processing
    if packet.haslayer(DNS) and packet[DNS].qr == 0:
        ip_src = packet[IP].src
        queried_host = packet[DNS].qd.qname.decode('utf-8').rstrip('.')
        dns_queries[ip_src].add(queried_host)
    
    # HTTP host processing (for unencrypted traffic)
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode('utf-8')
            if "Host:" in payload:
                lines = payload.split('\r\n')
                for line in lines:
                    if line.startswith("Host:"):
                        host = line.split("Host: ")[1].strip()
                        http_hosts[packet[IP].src].add(host)
        except UnicodeDecodeError:
            pass
    
    # Data usage tracking
    if packet.haslayer(IP):
        data_usage[packet[IP].src].append(data_usage[packet[IP].src][-1] + len(packet))
        
        # Extract MAC address
        mac_address = packet.src
        
        # Extract device name from MAC address (you may need to replace this with your own logic)
        device_name = get_device_name(mac_address)
        
        # Update device info dictionary
        if mac_address not in device_info:
            device_info[mac_address] = {'Device Name': device_name, 'IP Address': packet[IP].src}

# Function to get device name from MAC address
def get_device_name(mac_address):
    arp_output = subprocess.check_output(["arp", "-a"])
    arp_lines = arp_output.decode("utf-8").splitlines()

    ip_address = None
    for line in arp_lines:
        if mac_address in line:
            ip_address = line.split()[1]
            break

    if ip_address:
        try:
            result = subprocess.check_output(["nslookup", ip_address])
            device_name = result.decode("utf-8").split("Name: ")[1].split("\n")[0].strip()
            return device_name
        except subprocess.CalledProcessError:
            return "Unknown Device"
    else:
        return "Unknown Device"

# Function to log accessed sites and device info to CSV file
def log_to_csv():
    while True:
        time.sleep(10)  # Log every 10 seconds
        with open('device.csv', mode='w', newline='', encoding='utf-8') as csv_file:
            fieldnames = ['MAC Address', 'Device Name', 'IP Address']
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            writer.writeheader()
            for mac_address, info in device_info.items():
                writer.writerow({'MAC Address': mac_address, 'Device Name': info['Device Name'], 'IP Address': info['IP Address']})

# Function to sniff network packets
def sniff_packets():
    sniff(prn=process_packet, store=False, filter="ip")

# Matplotlib setup for ECG-style visualization
style.use('ggplot')
fig, ax = plt.subplots()

# Animation function to update the plot
def animate(i):
    ax.clear()
    has_labels = False
    for ip, usage in data_usage.items():
        if usage:  # Ensure there's data to plot
            ax.plot(range(len(usage)), usage, label=ip)
            has_labels = True
    ax.set_title("Network Data Usage: ECG Style")
    ax.set_ylabel('Data Usage (Bytes)')
    ax.set_xlabel('Time (Last 50 Packets)')
    if has_labels:
        plt.legend(loc='upper right', fontsize='small')
    else:
        ax.set_title("Waiting for data...")

# Start packet sniffing in a separate thread
threading.Thread(target=sniff_packets, daemon=True).start()

# Start the site logging thread
threading.Thread(target=log_to_csv, daemon=True).start()

# Start the Matplotlib animation
ani = animation.FuncAnimation(fig, animate, interval=1000)
plt.show()
