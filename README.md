# Fake AP Detector

**Fake AP Detector** is a cybersecurity tool designed to scan Wi-Fi networks and identify potentially suspicious access points. It helps detect fake ESP-based hotspots, unsecured open networks, and SSIDs with unusually strong signals, which may indicate malicious intent.

## Key Features

- **Real-Time Monitoring**: Continuously scans available Wi-Fi channels to discover access points.
- **Suspicious AP Detection**: Flags potentially dangerous networks based on specific criteria.
- **Network Summarization**: Displays structured tables of available and flagged access points.
- **Detection for Mobile Hotspots**: Identifies Android-based mobile hotspots and ESP-based fake APs.

---

## Prerequisites

### 1. Install Python 3.x

Ensure that you have Python installed. You can install or update Python using the following command:

```sh
sudo apt update && sudo apt install python3 python3-pip
```

### 2. Install Required Python Libraries

Install the necessary dependencies:

```sh
sudo pip3 install scapy prettytable
```

### 3. Enable Monitor Mode on Wireless Interface

Your wireless card must support monitor mode. If it does, install **aircrack-ng** and enable monitor mode:

```sh
sudo apt install aircrack-ng
```

Start monitor mode on your Wi-Fi interface (replace `wlan0` with your interface name if different):

```sh
sudo airmon-ng start wlan0
```

Check if monitor mode is enabled:

```sh
iwconfig
```

---

## Installation and Usage

### 1. Clone the Repository

```sh
git clone https://github.com/yourusername/fake-ap-detector.git
cd fake-ap-detector
```

### 2. Run the Fake AP Detector

Execute the script to start scanning for fake access points:

```sh
sudo python3 fake_ap_detector.py
```

### 3. Example Output

```
Scanning Wi-Fi networks...
-------------------------------------------------
SSID          | BSSID             | Signal | Flags
-------------------------------------------------
Public_WiFi   | 12:34:56:78:9A:BC |  -30dBm | Open Network (Unsecured)
ESP_Hotspot   | AB:CD:EF:12:34:56 |  -25dBm | Suspicious (ESP-based AP)
MyHomeWiFi    | 98:76:54:32:10:FE |  -45dBm | Secure
-------------------------------------------------
```

---

## Troubleshooting

### 1. **Monitor Mode Not Enabled**

- Ensure you have a compatible Wi-Fi adapter.
- Run `sudo airmon-ng check kill` before enabling monitor mode.
- Use `iwconfig` to check the interface mode.

### 2. **Scapy Permission Issues**

- Run the script as root: `sudo python3 fake_ap_detector.py`.
- Ensure your user has the correct permissions for network interfaces.

### 3. **No Networks Detected**

- Try using a different wireless adapter.
- Ensure you are in an area with available Wi-Fi networks.

---

## Contributing

Contributions are welcome! If you have improvements or new detection methods, feel free to submit a pull request.

---

## License

This project is licensed under the MIT License. See the LICENSE file for details.

---

## Disclaimer

This tool is intended for ethical security research and educational purposes only. Do not use it to interfere with networks without proper authorization.

---

### Author

**CyberClarity**\
[GitHub](https://github.com/yourusername)\
[Twitter](https://twitter.com/yourhandle)
