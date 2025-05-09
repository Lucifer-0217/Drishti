# Drishti Defence System - Version 1

### Developed by **Amit Kasbe**

Transforming cybersecurity with innovation and precision.

**Drishti Defence System Version 1** is a state-of-the-art cybersecurity solution meticulously designed to safeguard your system from malicious attacks and unauthorized intrusions. With advanced features like honeypot services, intrusion detection, real-time alerts, and a dynamic web-based dashboard, it offers unparalleled protection and visibility.

---

## Key Features

### 1. **Honeypot Services**

* Simulates fake services (e.g., SSH, HTTP, SMTP, FTP) to attract attackers and analyze their behavior.
* Operates dynamically on predefined ports to log and block intruders effectively.

### 2. **Intrusion Detection**

* Identifies ICMP floods, TCP SYN scans, and other suspicious network activities.
* Monitors incoming traffic and logs suspicious packets for analysis.

### 3. **GeoIP Lookups**

* Retrieves geographical details (city, country) of the attacking IP using the IPStack API.

### 4. **Real-Time Alerts**

* Instantly notifies you of detected intrusions via:

  * **Telegram Bot**
  * **Discord Webhooks**

### 5. **IP Blocking**

* Automatically blocks malicious IPs using Windows Firewall rules, ensuring secure system operation.

### 6. **Web-Based Dashboard**

* Flask-powered dashboard for real-time monitoring of traffic logs and activity.
* Offers graphical visualizations of logged events for quick insights.

---

## Installation Guide

### Prerequisites

1. **Python**: Ensure Python 3.8+ is installed.
2. **Dependencies**:
   Install the required Python libraries using pip:

   ```bash
   pip install scapy flask telebot requests ratelimit matplotlib
   ```
3. **API Keys**:

   * Obtain an IPStack API Key from [IPStack](https://ipstack.com/).
   * Create a Telegram bot via [BotFather](https://core.telegram.org/bots#botfather).
   * Set up a Discord Webhook URL in your Discord server.

### Configuration

Edit the script to replace placeholders with your actual credentials:

* **Telegram Configuration**:

  ```python
  TELEGRAM_BOT_TOKEN = "<Your Telegram Bot Token>"
  TELEGRAM_CHAT_ID = "<Your Telegram Chat ID>"
  ```

* **Discord Configuration**:

  ```python
  DISCORD_WEBHOOK_URL = "<Your Discord Webhook URL>"
  ```

* **IPStack Configuration**:

  ```python
  IPSTACK_API_KEY = "<Your IPStack API Key>"
  ```

* **Excluded IPs**:
  Add your trusted or local IPs to avoid unnecessary alerts:

  ```python
  EXCLUDED_IPS = ["127.0.0.1", "192.168.x.x"]
  ```

---

## Usage Instructions

### Running the Defence System

1. Open a terminal or PowerShell.
2. Execute the script:

   ```bash
   python advanced_firewall.py
   ```

The system will:

* Start honeypot services.
* Begin packet sniffing for intrusion detection.
* Launch the Flask-based dashboard for monitoring.

### Accessing the Dashboard

* Open a browser and navigate to:

  ```
  http://127.0.0.1:5000/dashboard
  ```
* For graphical logs, visit:

  ```
  http://127.0.0.1:5000/graph
  ```

---

## Code Overview

### Main Components

#### 1. Honeypot Services

* Simulates fake service ports (e.g., 22 for SSH, 80 for HTTP).
* Logs potential intrusions and blocks IPs triggering honeypots.

#### 2. Intrusion Detection

* Monitors packets for suspicious activity, including:

  * **ICMP Floods**
  * **TCP SYN Scans**
* Logs and blocks malicious activity.

#### 3. Real-Time Alerts

* Sends Telegram and Discord notifications containing:

  * Attacker's IP Address
  * Geo-location
  * Time of Attack

#### 4. Flask Dashboard

* Offers a user-friendly web interface for:

  * Real-time traffic monitoring.
  * Graphical summaries of logged events.

---

## Troubleshooting

### Common Issues & Solutions

1. **Missing Dependencies**:

   * Ensure all required Python libraries are installed.
   * Verify using `pip list`.

2. **Firewall Rules**:

   * Ensure Windows Firewall allows netsh commands.

3. **API Connectivity**:

   * Confirm API keys are correctly configured.
   * Check your network connectivity.

4. **Port Conflicts**:

   * Verify that honeypot ports (e.g., 22, 80) are not in use by other services.

---

## Advanced Configuration

* **Modify Honeypot Services and Ports**:

  ```python
  HONEYPOT_SERVICES = {
      "ssh": 2222,
      "http": 8080
  }
  ```

* **Exclude Additional IPs**:

  ```python
  EXCLUDED_IPS.append("192.168.1.100")
  ```

---

## Contributions

Contributions are always welcome! Fork the repository and submit a pull request for improvements or bug fixes. Together, we can make Drishti Defence System even better.

---

## License

This project is licensed under the MIT License. See the LICENSE file for more details.
