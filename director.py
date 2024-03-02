from scapy.all import sniff, IP, DNS, Raw, TCP
from collections import defaultdict, deque
import matplotlib.pyplot as plt
import matplotlib.animation as animation
from matplotlib import style
import threading
import time

# Initialize global data structures
data_usage = defaultdict(lambda: deque([0]*50, maxlen=50))  # ECG-style data usage tracking for each IP
dns_queries = defaultdict(set)  # Set to track DNS queries per IP
http_hosts = defaultdict(set)  # Set to track HTTP hosts per IP

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

# Function to log accessed sites
def log_accessed_sites():
    while True:
        time.sleep(10)  # Log every 10 seconds
        print("\n[Accessed Domains and Hosts]")
        for ip, queries in dns_queries.items():
            if queries:
                print(f"{ip} DNS Queries: {', '.join(queries)}")
        for ip, hosts in http_hosts.items():
            if hosts:
                print(f"{ip} HTTP Hosts: {', '.join(hosts)}")

# Start packet sniffing in a separate thread
threading.Thread(target=sniff_packets, daemon=True).start()

# Start the site logging thread
threading.Thread(target=log_accessed_sites, daemon=True).start()

# Start the Matplotlib animation
ani = animation.FuncAnimation(fig, animate, interval=1000)
plt.show()
