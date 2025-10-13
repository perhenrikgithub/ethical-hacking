from scapy.all import *
from typing import Dict, Tuple

# History of each TCP flow
tcp_history: Dict[Tuple[str, int, str, int], Dict[str, int]] = {}

def process_packet(pkt):
    if not pkt.haslayer(TCP):
        return

    tcp = pkt[TCP]
    ip = pkt.payload

    flow_key = (ip.src, tcp.sport, ip.dst, tcp.dport)
    reverse_key = (ip.dst, tcp.dport, ip.src, tcp.sport)

    seq = tcp.seq
    ack = tcp.ack
    payload_len = len(tcp.payload)

    direction = "\n🟨 victim → user1 (server)" if ip.src == "10.9.0.5" else "\n🟦 user1 (server) → victim"
    print(f"{direction}")
    print(f"SEQ: {seq}, ACK: {ack}, Payload length: {payload_len}")

    # if reverse_key in tcp_history:
    #     was_seq_correctly_projected = (seq == tcp_history[reverse_key]["last_ack"])
    #     was_ack_correctly_projected = (ack == tcp_history[reverse_key]["last_seq"] + tcp_history[reverse_key]["last_payload_len"])

    #     if was_ack_correctly_projected and was_seq_correctly_projected:
    #         print("✅ SEQ and ACK correctly projected")
    #     else:
    #         print(f"SEQ projection {'✅' if was_seq_correctly_projected else '❌'}")
    #         print(f"ACK projection {'✅' if was_ack_correctly_projected else '❌'}")
    # else:
    #     print("No reverse flow history yet — skipping projection check")

    # Calculate next sequence
    next_seq = seq + payload_len
    if tcp.flags & 0x02:  # SYN flag
        next_seq += 1
    if tcp.flags & 0x01:  # FIN flag
        next_seq += 1

    print(f"Next SEQ (this side): {next_seq}")

    # Calculate next ack
    if reverse_key in tcp_history:
        last_peer_seq = tcp_history[reverse_key]["last_seq"]
        last_peer_payload = tcp_history[reverse_key]["last_payload_len"]

        if last_peer_seq is not None:
            next_ack = last_peer_seq + last_peer_payload
            if tcp.flags & 0x02:
                next_ack += 1
            if tcp.flags & 0x01:
                next_ack += 1
            print(f"Next ACK (this side): {next_ack}")
    else:
        print("Next ACK (no history yet)")

    # Store history
    tcp_history[flow_key] = {
        "last_seq": seq,
        "last_ack": ack,
        "last_payload_len": payload_len
    }

sniff(
    iface='br-ebe32bd8d831',
    filter='tcp and (src host 10.9.0.5 or dst host 10.9.0.5) and port 23',
    prn=process_packet
)
