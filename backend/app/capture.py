# backend/app/capture.py
from scapy.all import sniff
from typing import List, Dict

capturing = False
captured_packets = []

def start_packet_capture():
    global capturing
    capturing = True
    sniff(prn=packet_handler, stop_filter=lambda x: not capturing)

def stop_packet_capture():
    global capturing
    capturing = False

def get_capture_status() -> str:
    return "Capturing" if capturing else "Stopped"

def packet_handler(packet):
    global captured_packets
    captured_packets.append(packet.summary())
