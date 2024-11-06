import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from scapy.all import sniff
import threading
from capture import start_capture, save_packets_to_file
from interface import get_default_interface  # Modified to use default interface
from decode import decode_packet
from filters import filter_packets
from stats import update_protocol_chart
from hex_view import format_packet_hex
from replay import replay_packets
from utils import run_in_thread

class NetworkCaptureApp:
    def __init__(self, root):
        self.root = root
        self.root.title("netcapx")

        # Frame to hold the controls
        control_frame = ttk.Frame(root, padding="15")
        control_frame.grid(column=0, row=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Network Interface Dropdown (removed since we are using a default interface)
        ttk.Label(control_frame, text="Network Interface:").grid(column=0, row=0, padx=10, pady=10)
        self.interface_var = tk.StringVar()
        self.interface_dropdown = ttk.Combobox(
            control_frame, textvariable=self.interface_var, state="readonly", width=30
        )
        self.interface_dropdown.grid(column=1, row=0, padx=10, pady=10)
        self.interface_dropdown.set("Default Interface")  # Label for default interface

        # Start and Stop Capture Buttons
        self.start_button = ttk.Button(control_frame, text="Start Capture", command=self.start_capture)
        self.start_button.grid(column=2, row=0, padx=10, pady=10)

        self.stop_button = ttk.Button(control_frame, text="Stop Capture", command=self.stop_capture)
        self.stop_button.grid(column=3, row=0, padx=10, pady=10)
        self.stop_button.state(["disabled"])

        # Capturing Status Label
        self.status_label = ttk.Label(control_frame, text="Not Capturing", foreground="red")
        self.status_label.grid(column=4, row=0, padx=10, pady=10)

        # Text area to display captured packets
        self.log_area = scrolledtext.ScrolledText(root, width=70, height=25, wrap=tk.WORD)
        self.log_area.grid(column=0, row=1, rowspan=4, padx=15, pady=15, sticky=(tk.N, tk.S, tk.E, tk.W))

        # Set up tags for colored text
        self.log_area.tag_config("TCP", foreground="blue")
        self.log_area.tag_config("UDP", foreground="green")
        self.log_area.tag_config("OTHER", foreground="black")

        # Real-time Statistics
        ttk.Label(root, text="Real-time Statistics:").grid(column=0, row=5, padx=15, pady=5, sticky=tk.W)
        self.statistics_label = ttk.Label(root, text="")
        self.statistics_label.grid(column=0, row=6, padx=15, pady=5, sticky=tk.W)

        # Initialize capture flag and counters
        self.capture_active = False
        self.packet_count = 0
        self.captured_packets = []

        # Load default interface
        self.default_interface = get_default_interface()

    def start_capture(self):
        """
        Start capturing packets on the default interface.
        """
        if not self.default_interface:
            messagebox.showwarning("Warning", "No network interface found.")
            return

        self.capture_active = True
        self.status_label["text"] = "Capturing"
        self.status_label["foreground"] = "green"
        self.log_area.delete(1.0, tk.END)  # Clear existing log
        self.packet_count = 0
        self.captured_packets = []

        self.start_button.state(["disabled"])
        self.stop_button.state(["!disabled"])

        # Start sniffing on the default interface in a new thread
        run_in_thread(self.sniff_packets, args=[])  # Adjusted this line to pass empty args

    def sniff_packets(self):
        """
        Capture packets on the default network interface.
        """
        sniff(
            iface=self.default_interface,
            prn=self.packet_handler,
            stop_filter=lambda x: not self.capture_active,
        )

    def stop_capture(self):
        """
        Stop capturing packets.
        """
        self.capture_active = False
        self.status_label["text"] = "Not Capturing"
        self.status_label["foreground"] = "red"
        self.start_button.state(["!disabled"])
        self.stop_button.state(["disabled"])

    def packet_handler(self, pkt):
        """
        Process and log each captured packet.
        """
        if self.capture_active:
            self.captured_packets.append(pkt)
            packet_type = "OTHER"
            tag = "OTHER"
            if pkt.haslayer("TCP"):
                packet_type = "TCP"
                tag = "TCP"
            elif pkt.haslayer("UDP"):
                packet_type = "UDP"
                tag = "UDP"

            # Process and log the captured packet with color
            log_message = f"[{packet_type}] {pkt.summary()}"
            self.log_area.insert(tk.END, log_message + "\n", tag)
            self.log_area.yview(tk.END)
            self.root.update()

            # Update packet count and display
            self.packet_count += 1
            self.update_statistics_label()

    def update_statistics_label(self):
        """
        Update real-time statistics on the GUI.
        """
        statistics_text = f"Packets Captured: {self.packet_count}"
        self.statistics_label["text"] = statistics_text


if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkCaptureApp(root)
    root.mainloop()
