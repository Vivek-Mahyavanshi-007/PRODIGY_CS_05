import tkinter as tk
from tkinter import scrolledtext
from scapy.all import *

def start_sniffing(interface):
    sniff(iface=interface, prn=process_packet)

def process_packet(packet):
    # Extract relevant information from the packet
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    protocol = packet[IP].proto
    payload = str(packet[TCP].payload)
    
    # Write the information to a .txt file
    with open("packet_info.txt", "a") as f:
        f.write(f"Source IP: {src_ip}\n")
        f.write(f"Destination IP: {dst_ip}\n")
        f.write(f"Protocol: {protocol}\n")
        f.write(f"Payload: {payload}\n\n")

# Create GUI
window = tk.Tk()
window.title("Network Packet Analyzer")
window.geometry("800x500")

interface_label = tk.Label(window, text="Enter Interface:")
interface_label.grid(row=0, column=0, padx=10, pady=10)

interface_entry = tk.Entry(window, width=50)
interface_entry.grid(row=0, column=1, padx=10, pady=10)

start_button = tk.Button(window, text="Start Sniffing", command=lambda: start_sniffing(interface_entry.get()))
start_button.grid(row=0, column=2, padx=10, pady=10)

output_label = tk.Label(window, text="Packet Information:")
output_label.grid(row=1, column=0, padx=10, pady=10)

output_text = scrolledtext.ScrolledText(window, width=80, height=20)
output_text.grid(row=2, column=0, columnspan=3, padx=10, pady=10)

# Redirect stdout to GUI text area
import sys
sys.stdout = output_text

window.mainloop()
