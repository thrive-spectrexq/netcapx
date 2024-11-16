from scapy.all import sniff, IP, TCP, UDP, ICMP
from scapy.packet import Packet
from typing import List, Dict, Union
import json
import csv
from datetime import datetime

# Capture state and storage for packets
capturing = False
captured_packets: List[Dict[str, Union[str, int, Dict[str, Union[str, int]]]]] = []
capture_stats = {
    "total_packets": 0,
    "protocol_counts": {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0},
    "top_sources": {},
    "top_destinations": {},
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

    # Extract common packet details
    packet_info = {
        "timestamp": datetime.now().isoformat(),
        "protocol": "Unknown",
        "source_ip": packet[IP].src if IP in packet else "N/A",
        "destination_ip": packet[IP].dst if IP in packet else "N/A",
        "length": len(packet),
        "details": {},
    }

    # Extract protocol-specific details
    if IP in packet:
        if TCP in packet:
            packet_info["protocol"] = "TCP"
            packet_info["details"] = {
                "source_port": packet[TCP].sport,
                "destination_port": packet[TCP].dport,
                "flags": packet[TCP].flags,
            }
            capture_stats["protocol_counts"]["TCP"] += 1
        elif UDP in packet:
            packet_info["protocol"] = "UDP"
            packet_info["details"] = {
                "source_port": packet[UDP].sport,
                "destination_port": packet[UDP].dport,
            }
            capture_stats["protocol_counts"]["UDP"] += 1
        elif ICMP in packet:
            packet_info["protocol"] = "ICMP"
            packet_info["details"] = {
                "type": packet[ICMP].type,
                "code": packet[ICMP].code,
            }
            capture_stats["protocol_counts"]["ICMP"] += 1
        else:
            capture_stats["protocol_counts"]["Other"] += 1

    # Update statistics for top sources and destinations
    src_ip = packet_info["source_ip"]
    dst_ip = packet_info["destination_ip"]
    capture_stats["top_sources"][src_ip] = capture_stats["top_sources"].get(src_ip, 0) + 1
    capture_stats["top_destinations"][dst_ip] = capture_stats["top_destinations"].get(dst_ip, 0) + 1

    # Save packet details
    captured_packets.append(packet_info)
    capture_stats["total_packets"] += 1

def get_capture_summary() -> Dict[str, Union[int, Dict[str, int]]]:
    """Return a summary of the capture statistics."""
    return capture_stats

def save_captured_packets(filename: str = "captured_packets.json") -> None:
    """Save captured packets to a JSON file."""
    with open(filename, "w") as file:
        json.dump(captured_packets, file, indent=4)
    print(f"Captured packets saved to {filename}")

def save_captured_packets_csv(filename: str = "captured_packets.csv") -> None:
    """Save captured packets to a CSV file."""
    with open(filename, "w", newline="") as csvfile:
        fieldnames = ["timestamp", "protocol", "source_ip", "destination_ip", "length", "details"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for packet in captured_packets:
            writer.writerow(packet)
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
        "top_sources": {},
        "top_destinations": {},
    }
    print("Capture reset.")
