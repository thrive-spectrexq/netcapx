import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from scapy.all import sniff, ICMP, ARP, IP, TCP, UDP
from capture import save_packets_to_file
from interface import get_default_interface
from decode import decode_packet
from utils import run_in_thread

class NetworkCaptureApp:
    def __init__(self, root):
        self.root = root
        self.root.title("netcapx")

        # Frame to hold the controls
        control_frame = ttk.Frame(root, padding="15")
        control_frame.grid(column=0, row=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Interface label for default interface
        ttk.Label(control_frame, text="Network Interface:").grid(column=0, row=0, padx=10, pady=10)
        self.interface_var = tk.StringVar()
        self.interface_dropdown = ttk.Combobox(
            control_frame, textvariable=self.interface_var, state="readonly", width=30
        )
        self.interface_dropdown.grid(column=1, row=0, padx=10, pady=10)
        self.interface_dropdown.set("Default Interface")

        # Start, Stop, and Save Buttons
        self.start_button = ttk.Button(control_frame, text="Start Capture", command=self.start_capture)
        self.start_button.grid(column=2, row=0, padx=10, pady=10)

        self.stop_button = ttk.Button(control_frame, text="Stop Capture", command=self.stop_capture)
        self.stop_button.grid(column=3, row=0, padx=10, pady=10)
        self.stop_button.state(["disabled"])

        self.save_button = ttk.Button(control_frame, text="Save Packets", command=self.save_captured_packets)
        self.save_button.grid(column=4, row=0, padx=10, pady=10)

        # Capture Status Label
        self.status_label = ttk.Label(control_frame, text="Not Capturing", foreground="red")
        self.status_label.grid(column=5, row=0, padx=10, pady=10)

        # Packet Display Area
        self.log_area = scrolledtext.ScrolledText(root, width=70, height=15, wrap=tk.WORD)
        self.log_area.grid(column=0, row=1, rowspan=2, padx=15, pady=15, sticky=(tk.N, tk.S, tk.E, tk.W))
        self.log_area.bind("<Button-1>", self.show_packet_details)

        # Tagging for colored text
        self.log_area.tag_config("TCP", foreground="blue")
        self.log_area.tag_config("UDP", foreground="green")
        self.log_area.tag_config("ICMP", foreground="orange")
        self.log_area.tag_config("ARP", foreground="purple")
        self.log_area.tag_config("OTHER", foreground="black")

        # Real-time Statistics
        ttk.Label(root, text="Real-time Statistics:").grid(column=0, row=3, padx=15, pady=5, sticky=tk.W)
        self.statistics_label = ttk.Label(root, text="")
        self.statistics_label.grid(column=0, row=4, padx=15, pady=5, sticky=tk.W)

        # Packet Details Area
        ttk.Label(root, text="Packet Details:").grid(column=0, row=5, padx=15, pady=5, sticky=tk.W)
        self.details_area = scrolledtext.ScrolledText(root, width=70, height=10, wrap=tk.WORD)
        self.details_area.grid(column=0, row=6, padx=15, pady=15, sticky=(tk.N, tk.S, tk.E, tk.W))

        # Initialize capture status and counters
        self.capture_active = False
        self.packet_count = 0
        self.captured_packets = []
        self.packet_counts_by_type = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'ARP': 0, 'OTHER': 0}

        # Load default interface
        self.default_interface = get_default_interface()

    def start_capture(self):
        if not self.default_interface:
            messagebox.showwarning("Warning", "No network interface found.")
            return

        self.capture_active = True
        self.status_label.config(text="Capturing", foreground="green")
        self.log_area.delete(1.0, tk.END)
        self.packet_count = 0
        self.captured_packets = []
        self.packet_counts_by_type = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'ARP': 0, 'OTHER': 0}

        self.start_button.state(["disabled"])
        self.stop_button.state(["!disabled"])

        run_in_thread(self.sniff_packets, args=[])

    def sniff_packets(self):
        sniff(
            iface=self.default_interface,
            prn=self.packet_handler,
            stop_filter=lambda x: not self.capture_active,
        )

    def stop_capture(self):
        self.capture_active = False
        self.status_label.config(text="Not Capturing", foreground="red")
        self.start_button.state(["!disabled"])
        self.stop_button.state(["disabled"])

    def packet_handler(self, pkt):
        if self.capture_active:
            self.captured_packets.append(pkt)
            packet_type, tag = "OTHER", "OTHER"
            if pkt.haslayer(TCP):
                packet_type, tag = "TCP", "TCP"
            elif pkt.haslayer(UDP):
                packet_type, tag = "UDP", "UDP"
            elif pkt.haslayer(ICMP):
                packet_type, tag = "ICMP", "ICMP"
            elif pkt.haslayer(ARP):
                packet_type, tag = "ARP", "ARP"

            self.packet_counts_by_type[packet_type] += 1
            self.packet_count += 1

            log_message = f"[{packet_type}] {pkt.summary()}"
            self.log_area.insert(tk.END, log_message + "\n", tag)
            self.log_area.yview(tk.END)
            self.root.update()

            self.update_statistics_label()

    def show_packet_details(self, event):
        index = self.log_area.index("@%s,%s linestart" % (event.x, event.y))
        line = self.log_area.get(index, "%s lineend" % index)

        for pkt in self.captured_packets:
            if pkt.summary() in line:
                src = pkt[IP].src if pkt.haslayer(IP) else "N/A"
                dst = pkt[IP].dst if pkt.haslayer(IP) else "N/A"
                
                # Decode the packet details and format as a string
                decoded_details = decode_packet(pkt)
                details_str = "\n".join(f"{key}: {value}" for key, value in decoded_details.items())
                
                # Combine all information into the details text
                details = f"Source: {src}\nDestination: {dst}\n\n{details_str}"
                
                self.details_area.delete(1.0, tk.END)
                self.details_area.insert(tk.END, details)
                break


    def save_captured_packets(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap")])
        if file_path:
            save_packets_to_file(self.captured_packets, file_path)
            messagebox.showinfo("Saved", f"Packets saved to {file_path}")

    def update_statistics_label(self):
        stats = (f"Total: {self.packet_count} | "
                 f"TCP: {self.packet_counts_by_type['TCP']} | "
                 f"UDP: {self.packet_counts_by_type['UDP']} | "
                 f"ICMP: {self.packet_counts_by_type['ICMP']} | "
                 f"ARP: {self.packet_counts_by_type['ARP']} | "
                 f"Other: {self.packet_counts_by_type['OTHER']}")
        self.statistics_label.config(text=stats)

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkCaptureApp(root)
    root.mainloop()
