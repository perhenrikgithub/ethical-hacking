from scapy.all import *

class host:
    def __init__(self, ip, name=None):
        self.ip = ip
        self.name = name if name else ip

    def __eq__(self, other):
        return self.ip == other.ip

class sniffer:
    def __init__(
            self, 
            iface: str, 
            filter_: str, 
            hosts=[], 
            print_packets: bool=False,
        ):
        self.iface = iface
        self.filter = filter_
        self.hosts = hosts
        self.tcp_history = {}
        self.print_packets = print_packets

        self.number_of_packets = 0

    def print_pkt(self, pkt):
        
        tcp = pkt[TCP]
        ip = pkt.payload

        seq = tcp.seq
        ack = tcp.ack
        payload_len = len(tcp.payload)

        print(f"[#{self.number_of_packets}] {ip.src}:{tcp.sport} → {ip.dst}:{tcp.dport} \t| SEQ: {seq}, ACK: {ack}, Payload length: {payload_len}, Payload: {bytes(tcp.payload)[:20].decode(errors='replace')}{'...' if len(tcp.payload) > 20 else ''}")

        # # Format source and destination for display
        # src_host = next((h for h in self.hosts if h.ip == ip.src), None)
        # dst_host = next((h for h in self.hosts if h.ip == ip.dst), None)
        # src_display = src_host.name if src_host else f"{ip.src}:{tcp.sport}"
        # dst_display = dst_host.name if dst_host else f"{ip.dst}:{tcp.dport}"
        # print(f"\n[#{self.number_of_packets}]Packet: {src_display} → {dst_display}")
        # print(f"{ip.src}:{tcp.sport} → {ip.dst}:{tcp.dport}")
        # print(f"SEQ: {seq}, ACK: {ack}, Payload length: {payload_len}")
        # if tcp.payload:
        #     print(f"\tPayload: {bytes(tcp.payload)[:20].decode(errors='replace')}{'...' if len(tcp.payload) > 20 else ''}")

    def send_malicious_command(self):
        # command="cat secret_passwords.txt"
        command="whoami"
        print(f"Sending malicious command: {command}")

        # ip = IP(src="10.9.0.5", dst="10.9.0.6")
        # tcp = TCP(sport=35144, dport=23, flags="PA", seq=@@@@, ack=@@@@)
        # data = b"" + command.encode() + b"\n"
        # pkt = ip/tcp/data
        # ls(pkt)
        # send(pkt,verbose=0)


    def process_packet(self, pkt):
        if not pkt.haslayer(TCP):
            return

        self.number_of_packets += 1

        # tcp = pkt[TCP]
        # ip = pkt.payload

        # flow_key = (ip.src, tcp.sport, ip.dst, tcp.dport)
        # reverse_key = (ip.dst, tcp.dport, ip.src, tcp.sport)

        # seq = tcp.seq
        # ack = tcp.ack
        # payload_len = len(tcp.payload)

        if self.print_packets:
            self.print_pkt(pkt)

    def run(self):
        print(f"Starting sniffer on {self.iface} with filter '{self.filter}'")

        sniff(
            iface=self.iface,
            filter=self.filter,
            prn=self.process_packet
        )


if __name__ == "__main__":
    hosts = [
        host("10.9.0.5", name="🟨 Client (Victim)"),
        host("10.9.0.6", name="🟦 Server (User1)")
    ]

    sniffer = sniffer(
        iface='br-ebe32bd8d831',
        filter_='',
        hosts=hosts,
        print_packets=True
    )
    sniffer.run()


