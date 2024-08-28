import scapy.all as scapy
import tkinter as tk
from tkinter import scrolledtext, ttk, filedialog
import threading
import subprocess
import os
os.environ['SDL_AUDIODRIVER'] = 'dummy'
import pygame
import re
import tkinter.messagebox as messagebox
import smtplib
from email.mime.text import MIMEText
import time
import json
import csv
import signal
from datetime import datetime
import pandas as pd
import plotly.graph_objs as go
import plotly.express as px
from plotly.subplots import make_subplots
from tkinterweb import HtmlFrame  # Import HtmlFrame from tkinterweb
import plotly.offline as pyo
import webbrowser

# Global DataFrame to store packet details
packet_df = pd.DataFrame(columns=['Timestamp', 'Protocol', 'Source IP', 'Destination IP', 'Source Port', 'Destination Port', 'Flags', 'Payload'])

# SMTP email configuration
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT =  587
SMTP_USERNAME = 'your_email@gmail.com'
SMTP_PASSWORD = 'your_email_password'
SENDER_EMAIL = 'your_email@gmail.com'
RECIPIENT_EMAIL = 'recipient_email@example.com'

snort_process = None  # Initialize the snort_process variable
alert_interval = 300  # Time interval in seconds to play sound (5 minutes)
last_alert_time = 0
alert_sound = "/home/snortmaster/Downloads/alert.wav"  # Path to your alert sound file

# Initialize Pygame for sound alerts
pygame.mixer.init()

# Global event to control packet capture
stop_event = threading.Event()

def play_alert_sound():
    global last_alert_time
    try:
        pygame.mixer.music.load(alert_sound)
        pygame.mixer.music.play()
        last_alert_time = time.time()
    except pygame.error as e:
        print(f"Error playing sound with pygame: {e}")

def start_capture():
    filter_str = filter_text.get().strip()
    
    stop_event.clear()
    t = threading.Thread(target=capture_packets, args=(filter_str,))
    t.start()
    update_status("Capturing")

def capture_packets(filter_str):
    # If no filter is provided, capture all packets
    if filter_str:
        scapy.sniff(prn=display_packet, iface="eth0",
                    filter=filter_str, store=False, stop_filter=lambda x: stop_event.is_set())
    else:
        scapy.sniff(prn=display_packet, iface="eth0",
                    store=False, stop_filter=lambda x: stop_event.is_set())

# Function to detect higher-level protocols
def detect_protocol(packet):
    if scapy.TCP in packet:
        sport = packet[scapy.TCP].sport
        dport = packet[scapy.TCP].dport
        if sport == 80 or dport == 80:
            return "HTTP"
        elif sport == 443 or dport == 443:
            return "HTTPS"
        elif sport == 25 or dport == 25:
            return "SMTP"
        elif sport == 110 or dport == 110:
            return "POP3"
        elif sport == 143 or dport == 143:
            return "IMAP"
        elif sport == 21 or dport == 21:
            return "FTP"
        return "TCP"
    elif scapy.UDP in packet:
        sport = packet[scapy.UDP].sport
        dport = packet[scapy.UDP].dport
        if sport == 53 or dport == 53:
            return "DNS"
        return "UDP"
    elif scapy.ICMP in packet:
        return "ICMP"
    # Add more protocol detections as necessary
    return "Unknown"

def display_packet(packet):
    global packet_df
    packet_info = f"{packet.summary()}\n"
    
    # Capture the current time
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
    # Determine the protocol
    protocol = detect_protocol(packet)
    
    packet_details = {
        'Timestamp': timestamp,
        'Source IP': packet[scapy.IP].src if scapy.IP in packet else 'N/A',
        'Destination IP': packet[scapy.IP].dst if scapy.IP in packet else 'N/A',
        'Source Port': packet[scapy.TCP].sport if scapy.TCP in packet else 'N/A',
        'Destination Port': packet[scapy.TCP].dport if scapy.TCP in packet else 'N/A',
        'Flags': parse_flags(packet[scapy.TCP].flags) if scapy.TCP in packet else 'N/A',
        'Payload': packet.load.decode(errors='ignore') if hasattr(packet, 'load') else 'N/A'
    }

    # Insert into the details frame (log_tree)
    log_tree.insert("", tk.END, values=(
        packet_details['Timestamp'],
        packet_details['Source IP'],
        packet_details['Destination IP'],
        packet_details['Source Port'],
        packet_details['Destination Port'],
        packet_details['Flags'],
        packet_details['Payload']
    ))

    # Add packet details to DataFrame
    # Convert the packet details dictionary to a DataFrame
    packet_df_temp = pd.DataFrame([packet_details])

    # Append the new DataFrame to the global packet_df using concat
    packet_df = pd.concat([packet_df, packet_df_temp], ignore_index=True)
    
    # Safely update the GUI in the main thread
    window.after(0, lambda: update_gui_packet(packet_details))

    # Insert in-depth details into the in-depth-details frame (in_depth_tree)
    in_depth_details = {
        'Version': packet.version if hasattr(packet, 'version') else 'N/A',
        'IHL': packet.ihl if hasattr(packet, 'ihl') else 'N/A',
        'TOS': packet.tos if hasattr(packet, 'tos') else 'N/A',
        'Length': packet.len if hasattr(packet, 'len') else 'N/A',
        'ID': packet.id if hasattr(packet, 'id') else 'N/A',
        # 'Flags': packet.flags if hasattr(packet, 'flags') else 'N/A',
        'Fragment Offset': packet.frag if hasattr(packet, 'frag') else 'N/A',
        'TTL': packet.ttl if hasattr(packet, 'ttl') else 'N/A',
        'Protocol': protocol,
        'Checksum': packet.chksum if hasattr(packet, 'chksum') else 'N/A',
    }

    in_depth_tree.insert("", tk.END, values=(
        in_depth_details['Version'],
        in_depth_details['IHL'],
        in_depth_details['TOS'],
        in_depth_details['Length'],
        in_depth_details['ID'],
        # in_depth_details['Flags'],
        in_depth_details['Fragment Offset'],
        in_depth_details['TTL'],
        in_depth_details['Protocol'],
        in_depth_details['Checksum']
    ))

    log_text.insert(tk.END, packet_info)
    log_text.see(tk.END)

    # Safely update the GUI with in-depth details
    window.after(0, lambda: update_gui_in_depth(in_depth_details))

    if "XMAS" in packet_info:
            log_text.tag_configure("alert", background="yellow", foreground="red")
            log_text.insert(tk.END, packet_info, "alert")
            launch_snort()
            send_email_alert(packet_info)
    
def update_gui_packet(packet_details):
    log_tree.insert("", tk.END, values=(
        packet_details['Timestamp'],
        packet_details['Source IP'],
        packet_details['Destination IP'],
        packet_details['Source Port'],
        packet_details['Destination Port'],
        packet_details['Flags'],
        packet_details['Payload']
    ))
    log_text.insert(tk.END, f"{packet_details['Timestamp']} {packet_details['Source IP']} {packet_details['Destination IP']} {packet_details['Source Port']} {packet_details['Destination Port']} {packet_details['Flags']} {packet_details['Payload']}\n")
    log_text.see(tk.END)

def update_gui_in_depth(in_depth_details):
    in_depth_tree.insert("", tk.END, values=(
        in_depth_details['Version'],
        in_depth_details['IHL'],
        in_depth_details['TOS'],
        in_depth_details['Length'],
        in_depth_details['ID'],
        # in_depth_details['Flags'],
        in_depth_details['Fragment Offset'],
        in_depth_details['TTL'],
        in_depth_details['Protocol'],
        in_depth_details['Checksum']
    ))

def parse_flags(flags):
    flag_map = {
        0x02: 'SYN',
        0x01: 'FIN',
        0x10: 'ACK',
        0x08: 'PSH',
        0x04: 'RST',
        0x20: 'URG'
    }
    active_flags = [flag for bit, flag in flag_map.items() if flags & bit]
    return ','.join(active_flags) if active_flags else 'None'

# Visualization function using Plotly
def visualize_data():
    global packet_df
    if packet_df.empty:
        print("No data available to visualize.")
        return
    # print(packet_df)
    # Visualize Protocol Distribution
    print("Creating Protocol Distribution chart...")
    # Count occurrences of each protocol
    protocol_counts = packet_df['Protocol'].value_counts().reset_index()
    protocol_counts.columns = ['Protocol', 'Count']  # Rename columns for clarity
    
    # Create a bar chart using Plotly Express
    fig_protocol = px.bar(
        protocol_counts,
        x='Protocol',
        y='Count',
        title="Protocol Distribution"
    )

    # Visualize Traffic Over Time
    print("Creating Traffic Over Time chart...")
    packet_df['Timestamp'] = pd.to_datetime(packet_df['Timestamp'])
    traffic_over_time = packet_df.set_index('Timestamp').resample('T').size()  # Resample by minute
    fig_traffic_time = px.line(traffic_over_time, x=traffic_over_time.index, y=traffic_over_time.values, title="Traffic Over Time")

    # Visualize Source IP Distribution
    print("Creating Source IP Distribution chart...")
    source_ip_counts = packet_df['Source IP'].value_counts().head(10)  # Top 10 IPs
    fig_source_ip = px.bar(source_ip_counts, x=source_ip_counts.index, y=source_ip_counts.values, title="Top 10 Source IPs")

    # Visualize Destination IP Distribution
    print("Creating Destination IP Distribution chart...")
    destination_ip_counts = packet_df['Destination IP'].value_counts().head(10)  # Top 10 IPs
    fig_dest_ip = px.bar(destination_ip_counts, x=destination_ip_counts.index, y=destination_ip_counts.values, title="Top 10 Destination IPs")

    # Visualize Port Activity
    print("Creating Port Activity heatmap...")
    port_activity = packet_df.groupby(['Source Port', 'Destination Port']).size().unstack(fill_value=0)
    fig_port_activity = px.imshow(port_activity,
                                  labels=dict(x="Destination Port", y="Source Port", color="Count"),
                                  title="Port Activity Heatmap",
                                  aspect="auto")

    # Combine all charts into a single figure with subplots
    print("Combining all charts into a single figure...")
     # Combine all charts into one figure
    combined_fig = go.Figure()
    
    for fig_part in [fig_protocol, fig_traffic_time, fig_source_ip, fig_dest_ip, fig_port_activity]:
        if fig_part.data:  # Check if there are traces
            for trace in fig_part.data:
                combined_fig.add_trace(trace)
        else:
            print(f"No data in {fig_part}")

    # Update layout if necessary
    # combined_fig.update_layout(title='Combined Visualization', xaxis_title='X Axis', yaxis_title='Y Axis')

    # Save the combined figure as an HTML file
    html_file_path = "visualization.html"
    pyo.plot(combined_fig, filename=html_file_path, auto_open=False)

    # Open the HTML file in the default web browser
    webbrowser.open('file://' + os.path.realpath(html_file_path))

def stop_capture():
    stop_event.set()
    update_status("Stopped")

def clear_log():
    log_text.delete(1.0, tk.END)
    log_tree.delete(*log_tree.get_children())
    in_depth_tree.delete(*in_depth_tree.get_children())

def launch_snort():
    global snort_process
    command = ['snort', '-A', 'console', '-c',
               '/etc/snort/snort.conf', '-i', 'eth1:eth0', '-Q']
    snort_process = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)

    t = threading.Thread(target=update_output)
    t.start()

def send_email_alert(alert_message):
    message = MIMEText(alert_message)
    message['Subject'] = 'Snort Alert'
    message['From'] = SENDER_EMAIL
    message['To'] = RECIPIENT_EMAIL

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(message)

def update_output():
    global alert_sound, last_alert_time

    while True:
        output = snort_process.stdout.readline()

        if snort_process.poll() is not None:
            break

        log_text.insert(tk.END, output)
        log_text.see(tk.END)
        window.update_idletasks()

        if re.search(r"XMAS", output):
            elapsed_time = time.time() - last_alert_time

            if elapsed_time >= alert_interval:
                play_alert_sound()
                send_email_alert(output)

def stop_snort():
    global snort_process
    if snort_process and snort_process.poll() is None:
        snort_process.send_signal(subprocess.signal.SIGINT)
        snort_process.wait()

def update_status(message):
    status_label.config(text=f"Status: {message}")

def export_logs():
    log_file = filedialog.asksaveasfilename(defaultextension=".csv",
                                           filetypes=[("CSV files", "*.csv"), ("JSON files", "*.json")])
    if log_file.endswith('.csv'):
        with open(log_file, 'w', newline='') as file:
            writer = csv.writer(file, escapechar='\\')
            writer.writerow(["Source IP", "Destination IP", "Source Port", "Destination Port", "Flags", "Payload"])
            for row in log_tree.get_children():
                writer.writerow(log_tree.item(row)['values'])
    elif log_file.endswith('.json'):
        logs = []
        for row in log_tree.get_children():
            logs.append(dict(zip(["Source IP", "Destination IP", "Source Port", "Destination Port", "Flags", "Payload"],
                                 log_tree.item(row)['values'])))
        with open(log_file, 'w') as file:
            json.dump(logs, file, indent=4)

def apply_filter():
    filter_value = filter_text.get().strip()
    
    # If the filter is blank, capture all packets
    if not filter_value:
        filter_str = "ip"  # Default to capturing all IP packets
    else:
        filter_str = f"tcp and ({filter_value})"

    # Clear previous log entries
    for item in log_tree.get_children():
        log_tree.delete(item)
    
    scapy.sniff(prn=display_packet, iface="eth0", filter=filter_str, store=False)

def on_closing():
    stop_capture()
    stop_snort()
    window.destroy()

# Signal handler for Ctrl+C and Ctrl+Z
def signal_handler(signum, frame):
    print("Signal detected. Closing application...")
    on_closing()

# Register signal handler
signal.signal(signal.SIGINT, signal_handler)  # Handle Ctrl+C
signal.signal(signal.SIGTSTP, signal_handler)  # Handle Ctrl+Z

# Pratham Deshik, [24-08-2024 22:36]

# GUI setup
window = tk.Tk()
window.title("Network Monitoring and Intrusion Detection Tool")

# Create a frame to hold the Start, Stop, and Clear & Exit buttons
button_frame = tk.Frame(window)
button_frame.pack(pady=5, fill=tk.X)

start_button = tk.Button(button_frame, text="Start Capture", command=start_capture,
                         bg="green", fg="white", padx=10, pady=5)
start_button.pack(side=tk.LEFT, padx=10)

stop_button = tk.Button(button_frame, text="Stop Capture", command=stop_capture,
                        bg="red", fg="white", padx=10, pady=5)
stop_button.pack(side=tk.LEFT, padx=10)

clear_button = tk.Button(button_frame, text="Clear Log", command=clear_log,
                         bg="orange", fg="white", padx=10, pady=5)
clear_button.pack(side=tk.LEFT, padx=10)

visualize_button = tk.Button(button_frame, text="Visualize", command=visualize_data,
                         bg="green", fg="white", padx=10, pady=5)
visualize_button.pack(side=tk.LEFT, padx=10)

exit_button = tk.Button(button_frame, text="Exit", command=on_closing,
                         bg="red", fg="white", padx=10, pady=5)
exit_button.pack(side=tk.RIGHT, padx=10)

filter_text = tk.Entry(window, width=50)
filter_text.pack(pady=5)

apply_filter_button = tk.Button(window, text="Apply Filter", command=apply_filter)
apply_filter_button.pack(pady=5)

# Add a frame to display packet details
details_frame = tk.Frame(window)
details_frame.pack(fill=tk.BOTH, padx=5, pady=5, expand=True)

columns = ("Timestamp", "Source IP", "Destination IP", "Source Port", "Destination Port", "Flags", "Payload")
log_tree = ttk.Treeview(details_frame, columns=columns, show="headings", height=8)
for col in columns:
    log_tree.heading(col, text=col)
    log_tree.column(col, minwidth=0, width=100)

log_tree.pack(fill=tk.BOTH, expand=True)

# Add a frame to display in-depth details of the packets
in_depth_frame = tk.Frame(window)
in_depth_frame.pack(fill=tk.BOTH, padx=5, pady=5, expand=True)

in_depth_columns = ("Version", "IHL", "TOS", "Length", "ID", "Fragment Offset", "TTL", "Protocol", "Checksum") #"Flags",
in_depth_tree = ttk.Treeview(in_depth_frame, columns=in_depth_columns, show="headings", height=8)
for col in in_depth_columns:
    in_depth_tree.heading(col, text=col)
    in_depth_tree.column(col, minwidth=0, width=100)

in_depth_tree.pack(fill=tk.BOTH, expand=True)

# Create a scrolled text widget for log display
log_text = scrolledtext.ScrolledText(window, height=10)
log_text.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)

export_button = tk.Button(window, text="Export Logs", command=export_logs)
export_button.pack(pady=5)

# Add a status label
status_label = tk.Label(window, text="Status: Idle", bd=1, relief=tk.SUNKEN, anchor=tk.W)
status_label.pack(side=tk.BOTTOM, fill=tk.X)

# Set up window close protocol
window.protocol("WM_DELETE_WINDOW", on_closing)

window.mainloop()