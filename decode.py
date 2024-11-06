from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.http import HTTP
from scapy.all import Packet

def decode_packet(packet):
    details = {}
    if IP in packet:
        details['IP'] = packet[IP].summary()
        if TCP in packet:
            details['TCP'] = packet[TCP].summary()
        elif UDP in packet:
            details['UDP'] = packet[UDP].summary()
        elif ICMP in packet:
            details['ICMP'] = packet[ICMP].summary()
    return details
