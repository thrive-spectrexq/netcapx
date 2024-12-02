import os
import threading
import tkinter as tk
from collections import deque
from tkinter import filedialog, ttk
from scapy.all import (
    DNS, IP, TCP, UDP, Ether, ICMP, IPv6, raw, sniff, wrpcap, get_if_list
)

# Global variables
packet_data = deque(maxlen=1000)  # Store up to 1000 packets
filtered_data = []
stop_event = threading.Event()
dark_mode = False  # Track the current theme mode

# Protocol mapping
PROTOCOLS = {
    0: "IP",
    1: "ICMP",
    3: "GGP",
    6: "TCP",
    8: "EGP",
    12: "PUP",
    17: "UDP",
    20: "HMP",
    22: "XNS-IDP",
    27: "RDP",
    41: "IPv6",
    43: "IPv6-Route",
    44: "IPv6-Frag",
    50: "ESP",
    51: "AH",
    58: "IPv6-ICMP",
    59: "IPv6-NoNxt",
    60: "IPv6-Opts",
    66: "RVD",
}

# Toggle Dark Mode
def toggle_dark_mode():
    global dark_mode
    dark_mode = not dark_mode
    apply_theme()

def apply_theme():
    style = ttk.Style()
    if dark_mode:
        # Dark mode colors
        bg_color = "#2E2E2E"
        fg_color = "#FFFFFF"
        tree_bg = "#333333"
        tree_fg = "#FFFFFF"
        tree_sel = "#4D4D4D"

        style.configure("TButton", background=bg_color, foreground=fg_color)
        style.configure("TLabel", background=bg_color, foreground=fg_color)
        style.configure("TCombobox", fieldbackground=bg_color, foreground=fg_color)
        style.configure("Treeview", background=tree_bg, foreground=tree_fg, fieldbackground=tree_bg)
        style.configure("Treeview.Heading", background=bg_color, foreground=fg_color)
        root.configure(bg=bg_color)
        status_label.config(bg=bg_color, fg=fg_color)
    else:
        # Light mode colors
        bg_color = "#FFFFFF"
        fg_color = "#000000"
        tree_bg = "#FFFFFF"
        tree_fg = "#000000"
        tree_sel = "#D9D9D9"

        style.configure("TButton", background=bg_color, foreground=fg_color)
        style.configure("TLabel", background=bg_color, foreground=fg_color)
        style.configure("TCombobox", fieldbackground=bg_color, foreground=fg_color)
        style.configure("Treeview", background=tree_bg, foreground=tree_fg, fieldbackground=tree_bg)
        style.configure("Treeview.Heading", background=bg_color, foreground=fg_color)
        root.configure(bg=bg_color)
        status_label.config(bg=bg_color, fg=fg_color)

# Function to capture packets
def capture_packets(interface, stop_event):
    def process_packet(packet):
        if stop_event.is_set():
            return
        try:
            proto = PROTOCOLS.get(packet[IP].proto, "Other") if IP in packet else "Other"
            src = packet[IP].src if IP in packet else "Unknown"
            dst = packet[IP].dst if IP in packet else "Unknown"
            length = len(packet)
            info = packet.summary()
            packet_data.append(packet)
            update_table_safe(proto, src, dst, length, info)
        except Exception as e:
            print(f"Error processing packet: {e}")

    try:
        sniff(
            iface=interface,
            prn=process_packet,
            stop_filter=lambda x: stop_event.is_set(),
            store=0,
        )
    except Exception as e:
        print(f"Error starting capture: {e}")

# Thread-safe function to update the table
def update_table_safe(proto, src, dst, length, info):
    root.after(
        0, lambda: tree.insert("", "end", values=(proto, src, dst, length, info))
    )

# Function to display packet details
def show_packet_details(event):
    selected_item = tree.selection()
    if not selected_item:
        return
    packet_index = tree.index(selected_item[0])
    packet = packet_data[packet_index]

    details_window = tk.Toplevel(root)
    details_window.title("Packet Details")
    details_window.geometry("600x400")

    raw_data = raw(packet).hex()
    details_text = tk.Text(details_window, wrap="word")
    details_text.insert("1.0", f"Packet Details:\n\n{packet.show(dump=True)}")
    
    # Detailed protocol-specific analysis
    if DNS in packet:
        details_text.insert("end", f"\n\nDNS Query/Response Details:\n{packet[DNS].summary()}")
    if TCP in packet:
        details_text.insert("end", f"\n\nTCP Stream Information:\n{packet[TCP].summary()}")

    details_text.insert("end", f"\n\nRaw Data:\n\n{raw_data}")
    details_text.configure(state="disabled")
    details_text.pack(expand=True, fill="both")

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
        try:
            proto = PROTOCOLS.get(packet[IP].proto, "Other") if IP in packet else "Other"
            src = packet[IP].src if IP in packet else "Unknown"
            dst = packet[IP].dst if IP in packet else "Unknown"
            length = len(packet)
            info = packet.summary()
            if filter_protocol == "All" or proto == filter_protocol:
                filtered_data.append((proto, src, dst, length, info))
                tree.insert("", "end", values=(proto, src, dst, length, info))
        except Exception as e:
            print(f"Error applying filter: {e}")

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

# Add a toggle button for Dark Mode
theme_button = tk.Button(root, text="Toggle Dark Mode", command=toggle_dark_mode)
theme_button.pack(pady=5)

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
    root, textvariable=protocol_filter_var, values=["All"] + list(PROTOCOLS.values())
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

tree.bind("<Double-1>", show_packet_details)  # Bind double-click event

# Enhance Treeview appearance
style = ttk.Style()
style.configure("Treeview", font=("Arial", 10))
style.configure("Treeview.Heading", font=("Arial", 12, "bold"))

# Apply default theme (Light Mode)
apply_theme()

# Run the GUI loop
root.mainloop()
