from scapy.all import sniff, wrpcap
import threading

def start_capture(interface, filter_text, packet_handler, stop_flag):
    sniff(
        iface=interface,
        prn=packet_handler,
        filter=filter_text,
        stop_filter=lambda x: not stop_flag[0]
    )

def save_packets_to_file(file_path, packets):
    wrpcap(file_path, packets)
