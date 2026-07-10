import sys
import time
from scapy.all import sniff, wrpcap, TCP

loopback = "lo0" if sys.platform == "darwin" else "lo"
print(f"[*] Using interface: {loopback}")
print("[*] Capturing for 10 seconds — run tls_client.py now in another terminal...")

packets = sniff(iface=loopback, filter="tcp port 8443", timeout=10)

wrpcap("tls13_baseline.pcap", packets)
print(f"[+] Captured {len(packets)} packets -> tls13_baseline.pcap")

handshake_packets = [p for p in packets if p.haslayer(TCP)]
if len(handshake_packets) >= 2:
    rtt = handshake_packets[1].time - handshake_packets[0].time
    print(f"[*] RTT baseline delta: {rtt * 1000:.4f} ms")
else:
    print("[-] Too few packets — make sure server is running and client fired")
