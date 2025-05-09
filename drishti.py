import socket
import random
import ipaddress
import requests
from scapy.all import sniff, IP, TCP, ICMP
from datetime import datetime
import subprocess
import telebot
import threading
from flask import Flask, jsonify, request
from ratelimit import limits, sleep_and_retry
import matplotlib.pyplot as plt
from io import BytesIO
import base64

# Telegram Bot Configuration
TELEGRAM_BOT_TOKEN = "TG Bot Token"
TELEGRAM_CHAT_ID = "Chat ID"
bot = telebot.TeleBot(TELEGRAM_BOT_TOKEN)

# Discord Webhook URL
DISCORD_WEBHOOK_URL = "WEBHOOK URL"

# GeoIP Lookup Configuration
IPSTACK_API_KEY = "de0873fbd49ca6c2e2cfa5eda4215f30"
IPSTACK_API_URL = "http://api.ipstack.com/{ip}?access_key={key}"

# Honeypot Fake Service Configuration
HONEYPOT_SERVICES = {
    "ssh": 22,
    "http": 80,
    "smtp": 456,
    "ftp": 21
}
HONEYPOT_PORT_RANGE = (1000, 5000)

# Excluded IPs (Add your local IP or trusted IPs here)
EXCLUDED_IPS = ["127.0.0.1", "192.168.149.35"]

# Logs for the real-time dashboard
traffic_logs = []

# Flask Web Application for Dashboard
app = Flask(_name_)

# Rate Limiting for Telegram Alerts (1 alert per second)
@sleep_and_retry
@limits(calls=1, period=1)
def send_alert(ip, reason):
    if ip in EXCLUDED_IPS:
        print(f"Skipping alert for excluded IP: {ip}")
        return
    geo_data = fetch_geoip(ip)
    location = geo_data.get("city", "Unknown") + ", " + geo_data.get("country_name", "Unknown")
    message = f"\ud83d\udea8 Alert: {reason}\nIP: {ip}\nLocation: {location}\nTimestamp: {datetime.now()}"
    bot.send_message(TELEGRAM_CHAT_ID, message)
    send_discord_alert(ip, reason, location)

# Send alert to Discord
def send_discord_alert(ip, reason, location):
    if ip in EXCLUDED_IPS:
        return
    message = {
        "content": f"\ud83d\udea8 Alert: {reason}\nIP: {ip}\nLocation: {location}\nTimestamp: {datetime.now()}"
    }
    try:
        requests.post(DISCORD_WEBHOOK_URL, json=message)
    except Exception as e:
        print(f"Failed to send alert to Discord: {e}")

# Function to fetch GeoIP data
def fetch_geoip(ip):
    try:
        response = requests.get(IPSTACK_API_URL.format(ip=ip, key=IPSTACK_API_KEY))
        return response.json()
    except Exception as e:
        print(f"Failed to fetch GeoIP data: {e}")
        return {}

# Function to block IP
def block_ip(ip):
    if ip in EXCLUDED_IPS:
        print(f"Skipping block for excluded IP: {ip}")
        return
    try:
        command = ["netsh", "advfirewall", "firewall", "add", "rule", f"name=Block_{ip}", "dir=in", "action=block", f"remoteip={ip}"]
        subprocess.run(command, check=True)
        print(f"Successfully blocked IP: {ip}")
        send_alert(ip, "IP Blocked by Firewall")
    except subprocess.CalledProcessError as e:
        print(f"Error blocking IP {ip}: {e}")

# Function to log traffic
def log_traffic(ip, reason, packet):
    log_entry = {
        "ip": ip,
        "reason": reason,
        "timestamp": str(datetime.now()),
        "packet": str(packet)
    }
    traffic_logs.append(log_entry)

# Honeypot Fake Services
def start_honeypot_service(port, service_name):
    try:
        honeypot_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        honeypot_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        honeypot_socket.bind(("127.0.0.1", port))  # Bind only to localhost for security
        honeypot_socket.listen(5)
        print(f"{service_name.capitalize()} Honeypot listening on port {port}...")

        while True:
            conn, addr = honeypot_socket.accept()
            ip, attacker_port = addr
            if ip in EXCLUDED_IPS:
                print(f"Skipping honeypot alert for excluded IP: {ip}")
                conn.close()
                continue
            log_traffic(ip, f"{service_name.capitalize()} Honeypot Triggered", None)
            send_alert(ip, f"{service_name.capitalize()} Honeypot Intrusion Detected")
            block_ip(ip)
            conn.close()

    except Exception as e:
        print(f"Error in {service_name.capitalize()} Honeypot: {e}")

# Intrusion Detection
def detect_intrusion(packet):
    ip_layer = packet.getlayer(IP)
    tcp_layer = packet.getlayer(TCP)
    icmp_layer = packet.getlayer(ICMP)

    if ip_layer:
        ip = ip_layer.src
        if ip in EXCLUDED_IPS:
            print(f"Skipping intrusion detection for excluded IP: {ip}")
            return

        # Detect suspicious ICMP flood
        if icmp_layer:
            log_traffic(ip, "Possible ICMP Flood", packet)
            block_ip(ip)

        # Detect suspicious TCP scans (e.g., SYN scans)
        if tcp_layer and tcp_layer.flags == "S":
            log_traffic(ip, "Possible TCP SYN Scan", packet)
            block_ip(ip)

# Main packet sniffing function
def packet_sniffer(packet):
    ip_layer = packet.getlayer(IP)
    if ip_layer:
        detect_intrusion(packet)

# Start Honeypot Services for SSH and HTTP
def start_honeypot_services():
    for service_name, port in HONEYPOT_SERVICES.items():
        threading.Thread(target=start_honeypot_service, args=(port, service_name), daemon=True).start()

# Flask Route for Traffic Logs
def generate_logs_graph():
    plt.figure(figsize=(10, 6))
    timestamps = [log["timestamp"] for log in traffic_logs]
    reasons = [log["reason"] for log in traffic_logs]
    plt.barh(timestamps, range(len(reasons)), color="skyblue")
    plt.xlabel("Reason")
    plt.ylabel("Timestamp")
    plt.title("Traffic Logs")
    buffer = BytesIO()
    plt.savefig(buffer, format="png")
    buffer.seek(0)
    graph_image = base64.b64encode(buffer.read()).decode("utf-8")
    buffer.close()
    return graph_image

@app.route("/dashboard", methods=["GET"])
def dashboard():
    return jsonify(traffic_logs)

@app.route("/graph", methods=["GET"])
def graph():
    graph_image = generate_logs_graph()
    return f"<img src='data:image/png;base64,{graph_image}'/>"

# Start Firewall
if _name_ == "_main_":
    # Start honeypots
    threading.Thread(target=start_honeypot_services, daemon=True).start()

    # Start Flask dashboard
    threading.Thread(target=lambda: app.run(host="127.0.0.1", port=5000, debug=False), daemon=True).start()

    # Start packet sniffing
    print("Starting Maharaksha Firewall...")
    sniff(prn=packet_sniffer, store=False)
