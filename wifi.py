from scapy.all import *
from prettytable import PrettyTable
from collections import defaultdict
import argparse
import os
import time

access_points = {}
suspicious_aps = []
flagged_ssids = set()
channels = [1, 6, 11]  # You can extend this list for full Wi-Fi spectrum scanning.

def set_channel(interface, channel):
    os.system(f"iwconfig {interface} channel {channel}")

def packet_handler(packet):
    if packet.haslayer(Dot11):
        ssid = get_ssid(packet)
        bssid = packet.addr2
        signal_strength = packet.dBm_AntSignal if hasattr(packet, "dBm_AntSignal") else "N/A"
        encryption = get_encryption(packet)

        if ssid and bssid and bssid not in access_points:
            access_points[bssid] = {"SSID": ssid, "Encryption": encryption, "Signal": signal_strength}
            check_for_suspicious(ssid, bssid, encryption, signal_strength)

        print_table()

def get_ssid(packet):
    if packet.haslayer(Dot11Elt):
        ssid = packet[Dot11Elt].info.decode(errors="ignore")
        return ssid if ssid else "Hidden"
    return None

def get_encryption(packet):
    if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
        capabilities = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
        if "privacy" in capabilities:
            if packet.haslayer(Dot11Elt) and packet[Dot11Elt].info.startswith(b'\x00P\xf2\x04'):
                return "WPA/WPA2"
            else:
                return "WEP"
        else:
            return "Open"
    return "N/A"

def check_for_suspicious(ssid, bssid, encryption, signal_strength):
    if ssid in flagged_ssids:
        return

    reasons = []
    if ssid.lower().startswith("androidap") or ssid.lower().startswith("esp"):
        reasons.append("Likely Mobile Hotspot or Fake ESP AP")

    ssid_bssids = [ap for ap in access_points.values() if ap["SSID"] == ssid]
    if len(ssid_bssids) > 1:
        reasons.append("Duplicate SSID with different BSSIDs")

    if encryption == "Open":
        reasons.append("Open Network (No Encryption)")

    if signal_strength != "N/A" and int(signal_strength) > -40:
        reasons.append("Unusually Strong Signal (-40 dBm or better)")

    if reasons:
        suspicious_aps.append({"SSID": ssid, "BSSID": bssid, "Reasons": ", ".join(reasons)})
        flagged_ssids.add(ssid)

def print_table():
    table = PrettyTable(["SSID", "BSSID", "Encryption", "Signal"])
    for bssid, ap in access_points.items():
        table.add_row([ap["SSID"], bssid, ap["Encryption"], ap["Signal"]])
    print(table)

    if suspicious_aps:
        print("\n[ALERT] Suspicious Access Points Detected:")
        alert_table = PrettyTable(["SSID", "BSSID", "Reasons"])
        for ap in suspicious_aps:
            alert_table.add_row([ap["SSID"], ap["BSSID"], ap["Reasons"]])
        print(alert_table)

def main():
    args = argparse.ArgumentParser(description="Fake AP Detector (Including Mobile Hotspots and ESP APs)")
    args.add_argument("-i", "--interface", required=True, help="Wireless interface in monitor mode (e.g., wlan0mon)")
    interface = args.parse_args().interface

    print("[*] Scanning for Access Points. Press Ctrl+C to stop.")
    try:
        while True:
            for channel in channels:
                set_channel(interface, channel)
                print(f"[INFO] Scanning on Channel {channel}")
                sniff(iface=interface, prn=packet_handler, timeout=5, store=False)
    except KeyboardInterrupt:
        print("\n[!] Stopping the scan...")
        print("[*] Final Scan Summary:")
        print_table()
        print("[*] Scan complete.")

if __name__ == "__main__":
    main()
