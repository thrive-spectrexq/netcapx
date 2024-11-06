import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from scapy.all import sniff, wrpcap, IP, TCP, UDP, Raw
import threading


class NetworkCaptureApp:
    def __init__(self, root):
        self.root = root
        self.root.title("netcapx")

        # Frame to hold the controls
        control_frame = ttk.Frame(root, padding="15")
        control_frame.grid(column=0, row=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Start Capture Button
        self.start_button = ttk.Button(
            control_frame, text="Start Capture", command=self.start_capture
        )
        self.start_button.grid(column=0, row=0, padx=10, pady=10)

        # Stop Capture Button
        self.stop_button = ttk.Button(
            control_frame, text="Stop Capture", command=self.stop_capture
        )
        self.stop_button.grid(column=1, row=0, padx=10, pady=10)
        self.stop_button.state(["disabled"])  # Initially disable the stop button

        # Capturing Status Label
        self.status_label = ttk.Label(
            control_frame, text="Not Capturing", foreground="red"
        )
        self.status_label.grid(column=2, row=0, padx=10, pady=10)

        # Filter Entry
        ttk.Label(control_frame, text="Filter:").grid(column=3, row=0, padx=10, pady=10)
        self.filter_entry = ttk.Entry(control_frame, width=25)
        self.filter_entry.grid(column=4, row=0, padx=10, pady=10)

        # Save to File Button
        self.save_button = ttk.Button(
            control_frame, text="Save to File", command=self.save_to_file
        )
        self.save_button.grid(column=5, row=0, padx=10, pady=10)

        # Text area to display captured packets
        self.log_area = scrolledtext.ScrolledText(
            root, width=70, height=25, wrap=tk.WORD
        )
        self.log_area.grid(
            column=0,
            row=1,
            rowspan=4,
            padx=15,
            pady=15,
            sticky=(tk.N, tk.S, tk.E, tk.W),
        )

        # Set up tags for colored text
        self.log_area.tag_config("TCP", foreground="blue")
        self.log_area.tag_config("UDP", foreground="green")
        self.log_area.tag_config("OTHER", foreground="black")

        # Real-time Statistics
        ttk.Label(root, text="Real-time Statistics:").grid(
            column=0, row=5, padx=15, pady=5, sticky=tk.W
        )
        self.statistics_label = ttk.Label(root, text="")
        self.statistics_label.grid(column=0, row=6, padx=15, pady=5, sticky=tk.W)

        # Detailed packet view
        ttk.Label(root, text="Packet Details:").grid(
            column=1, row=0, padx=15, pady=5, sticky=tk.NW
        )
        self.packet_details = scrolledtext.ScrolledText(
            root, width=55, height=10, wrap=tk.WORD
        )
        self.packet_details.grid(
            column=1,
            row=1,
            rowspan=6,
            padx=15,
            pady=15,
            sticky=(tk.N, tk.S, tk.E, tk.W),
        )

        # Initialize capture flag and statistics counters
        self.capture_active = False
        self.packet_count = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.captured_packets = []

    def start_capture(self):
        self.capture_active = True
        self.status_label["text"] = "Capturing"
        self.status_label["foreground"] = "green"
        self.log_area.delete(1.0, tk.END)  # Clear existing log
        self.packet_count = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.captured_packets = []
        filter_text = self.filter_entry.get().strip()

        self.start_button.state(["disabled"])
        self.stop_button.state(["!disabled"])

        # Start sniffing in a new thread
        self.sniff_thread = threading.Thread(
            target=self.sniff_packets, args=(filter_text,)
        )
        self.sniff_thread.start()

    def sniff_packets(self, filter_text):
        try:
            sniff(
                prn=self.packet_handler,
                filter=filter_text,
                stop_filter=lambda x: not self.capture_active,
            )
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while sniffing: {e}")
            self.stop_capture()

    def stop_capture(self):
        self.capture_active = False
        self.status_label["text"] = "Not Capturing"
        self.status_label["foreground"] = "red"

        self.start_button.state(["!disabled"])
        self.stop_button.state(["disabled"])

    def packet_handler(self, pkt):
        if self.capture_active:
            self.captured_packets.append(pkt)
            # Determine packet type and color
            packet_type = "OTHER"
            tag = "OTHER"  # Default tag for other protocols
            if IP in pkt:
                if TCP in pkt:
                    packet_type = "TCP"
                    tag = "TCP"
                elif UDP in pkt:
                    packet_type = "UDP"
                    tag = "UDP"

            # Process and log the captured packet with color
            log_message = f"[{packet_type}] {str(pkt.summary())}"
            self.log_area.insert(tk.END, log_message + "\n", tag)
            self.log_area.yview(tk.END)
            self.root.update()

            # Update real-time statistics
            self.packet_count += 1
            if packet_type == "TCP":
                self.tcp_count += 1
            elif packet_type == "UDP":
                self.udp_count += 1

            self.update_statistics_label()
            self.log_area.tag_bind(
                tag, "<Button-1>", lambda e, pkt=pkt: self.show_packet_details(pkt)
            )

    def show_packet_details(self, pkt):
        self.packet_details.delete(1.0, tk.END)
        self.packet_details.insert(tk.END, pkt.show(dump=True))

    def update_statistics_label(self):
        statistics_text = f"Packets: {self.packet_count} | TCP: {self.tcp_count} | UDP: {self.udp_count}"
        self.statistics_label["text"] = statistics_text

    def save_to_file(self):
        if not self.captured_packets:
            messagebox.showwarning("Warning", "No packets captured to save!")
            return
        file_path = filedialog.asksaveasfilename(
            defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap")]
        )
        if file_path:
            try:
                wrpcap(file_path, self.captured_packets)
                messagebox.showinfo("Success", f"Packets saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred while saving: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkCaptureApp(root)
    root.mainloop()
