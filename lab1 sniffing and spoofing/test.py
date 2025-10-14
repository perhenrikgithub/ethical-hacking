from scapy.all import *

def print_pkt(pkt):
    pkt.show()

print("Starting sniffing on interface 'br-6af679889217' for ICMP packets...")
pkt = sniff(iface='br-6af679889217', filter='icmp', prn=print_pkt)