import os
import threading
import tkinter as tk
from collections import deque
from tkinter import filedialog, ttk

from scapy.all import DNS, IP, TCP, UDP, Ether, get_if_list, raw, sniff, wrpcap

# Global variables
packet_data = deque(maxlen=1000)  # Store up to 1000 packets
filtered_data = []
stop_event = threading.Event()


# Function to capture packets
def capture_packets(interface, stop_event):
    def process_packet(packet):
        if stop_event.is_set():
            return
        try:
            proto = (
                "TCP"
                if TCP in packet
                else "UDP" if UDP in packet else "DNS" if DNS in packet else "Other"
            )
            src = packet[IP].src if IP in packet else "Unknown"
            dst = packet[IP].dst if IP in packet else "Unknown"
            length = len(packet)
            info = packet.summary()
            packet_data.append(packet)
            update_table_safe(proto, src, dst, length, info)
        except Exception as e:
            print(f"Error processing packet: {e}")

    sniff(
        iface=interface,
        prn=process_packet,
        stop_filter=lambda x: stop_event.is_set(),
        store=0,
    )


# Thread-safe function to update the table
def update_table_safe(proto, src, dst, length, info):
    root.after(
        0, lambda: tree.insert("", "end", values=(proto, src, dst, length, info))
    )


# Function to start capturing packets
def start_capture():
    stop_event.clear()
    interface = interface_var.get()
    if interface not in available_interfaces:
        status_label.config(text="Status: Invalid Interface")
        return
    threading.Thread(
        target=capture_packets, args=(interface, stop_event), daemon=True
    ).start()
    status_label.config(text=f"Status: Capturing on {interface}")


# Function to stop capturing packets
def stop_capture():
    stop_event.set()
    status_label.config(text="Status: Stopped")


# Function to clear the table
def clear_table():
    tree.delete(*tree.get_children())
    packet_data.clear()
    status_label.config(text="Status: Table Cleared")


# Function to apply filters
def apply_filters():
    filter_protocol = protocol_filter_var.get()
    tree.delete(*tree.get_children())  # Clear table
    filtered_data.clear()
    for packet in packet_data:
        proto = (
            "TCP"
            if TCP in packet
            else "UDP" if UDP in packet else "DNS" if DNS in packet else "Other"
        )
        src = packet[IP].src if IP in packet else "Unknown"
        dst = packet[IP].dst if IP in packet else "Unknown"
        length = len(packet)
        info = packet.summary()
        if filter_protocol == "All" or proto == filter_protocol:
            filtered_data.append((proto, src, dst, length, info))
            tree.insert("", "end", values=(proto, src, dst, length, info))


# Function to export captured data to a PCAP file
def export_to_pcap():
    file_path = filedialog.asksaveasfilename(
        defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap")]
    )
    if file_path:
        try:
            wrpcap(file_path, packet_data)
            status_label.config(text=f"Data exported to {file_path}")
        except Exception as e:
            status_label.config(text=f"Error exporting data: {e}")


# Create main GUI window
root = tk.Tk()
root.title("NetCapX - Enhanced Network Capture Tool")

# Interface selection
tk.Label(root, text="Select Interface:").pack(pady=5)
interface_var = tk.StringVar()
available_interfaces = get_if_list()
interface_menu = ttk.Combobox(
    root, textvariable=interface_var, values=available_interfaces
)
interface_menu.pack(pady=5)

# Protocol filter
tk.Label(root, text="Filter by Protocol:").pack(pady=5)
protocol_filter_var = tk.StringVar(value="All")
protocol_filter_menu = ttk.Combobox(
    root, textvariable=protocol_filter_var, values=["All", "TCP", "UDP", "DNS"]
)
protocol_filter_menu.pack(pady=5)
apply_filter_button = tk.Button(root, text="Apply Filter", command=apply_filters)
apply_filter_button.pack(pady=5)

# Buttons for start, stop, clear, and export
button_frame = tk.Frame(root)
button_frame.pack(pady=10)

start_button = tk.Button(button_frame, text="Start Capture", command=start_capture)
start_button.pack(side=tk.LEFT, padx=5)

stop_button = tk.Button(button_frame, text="Stop Capture", command=stop_capture)
stop_button.pack(side=tk.LEFT, padx=5)

clear_button = tk.Button(button_frame, text="Clear Table", command=clear_table)
clear_button.pack(side=tk.LEFT, padx=5)

export_button = tk.Button(button_frame, text="Export to PCAP", command=export_to_pcap)
export_button.pack(side=tk.LEFT, padx=5)

# Status label
status_label = tk.Label(root, text="Status: Stopped")
status_label.pack(pady=5)

# Table to display captured packets
columns = ("Protocol", "Source", "Destination", "Length", "Info")
tree = ttk.Treeview(root, columns=columns, show="headings")
for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=150)
tree.pack(pady=10, fill=tk.BOTH, expand=True)

# Enhance Treeview appearance
style = ttk.Style()
style.configure("Treeview", font=("Arial", 10))
style.configure("Treeview.Heading", font=("Arial", 12, "bold"))

# Run the GUI loop
root.mainloop()
