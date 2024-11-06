from scapy.all import rdpcap, sendp

def replay_packets(file_path):
    packets = rdpcap(file_path)
    for pkt in packets:
        sendp(pkt)
