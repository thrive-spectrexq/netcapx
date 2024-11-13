# backend/app/capture.py

from scapy.all import sniff
from scapy.packet import Packet
from scapy.layers.inet import IP, TCP, UDP
from typing import List, Dict, Union
import json
from datetime import datetime

# Capture state and storage for packets
capturing = False
captured_packets: List[Dict[str, Union[str, int]]] = []
capture_stats = {
    "total_packets": 0,
    "protocol_counts": {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0},
}

def start_packet_capture(filter: str = None):
    """Start capturing packets with an optional filter."""
    global capturing
    capturing = True
    sniff(prn=packet_handler, stop_filter=lambda x: not capturing, filter=filter)

def stop_packet_capture():
    """Stop the packet capture."""
    global capturing
    capturing = False

def get_capture_status() -> str:
    """Return current capture status."""
    return "Capturing" if capturing else "Stopped"

def packet_handler(packet: Packet):
    """Process each packet, updating statistics and saving a summary."""
    global captured_packets, capture_stats
    packet_info = {
        "timestamp": datetime.now().isoformat(),
        "protocol": packet.summary().split()[0],  # Protocol from summary
        "source_ip": packet[IP].src if IP in packet else "N/A",
        "destination_ip": packet[IP].dst if IP in packet else "N/A",
        "length": len(packet),
    }

    # Update capture stats
    capture_stats["total_packets"] += 1
    if TCP in packet:
        capture_stats["protocol_counts"]["TCP"] += 1
    elif UDP in packet:
        capture_stats["protocol_counts"]["UDP"] += 1
    elif packet_info["protocol"] == "ICMP":
        capture_stats["protocol_counts"]["ICMP"] += 1
    else:
        capture_stats["protocol_counts"]["Other"] += 1

    captured_packets.append(packet_info)

def get_capture_summary() -> Dict[str, Union[int, Dict[str, int]]]:
    """Return a summary of the capture statistics."""
    return capture_stats

def save_captured_packets(filename: str = "captured_packets.json") -> None:
    """Save captured packets to a JSON file."""
    with open(filename, "w") as file:
        json.dump(captured_packets, file, indent=4)
    print(f"Captured packets saved to {filename}")

def load_captured_packets(filename: str = "captured_packets.json") -> List[Dict[str, Union[str, int]]]:
    """Load captured packets from a JSON file."""
    global captured_packets
    try:
        with open(filename, "r") as file:
            captured_packets = json.load(file)
        print(f"Loaded packets from {filename}")
        return captured_packets
    except FileNotFoundError:
        print(f"File {filename} not found.")
        return []

def reset_capture():
    """Clear captured packets and reset statistics."""
    global captured_packets, capture_stats
    captured_packets.clear()
    capture_stats = {
        "total_packets": 0,
        "protocol_counts": {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0},
    }
    print("Capture reset.")
