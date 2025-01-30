##The Fake AP Detector is a cybersecurity tool designed to scan Wi-Fi networks and identify potentially suspicious access points. It flags networks such as fake ESP-based hotspots, unsecured open networks, and SSIDs with unusually strong signals.


#Key Features

Real-Time Monitoring: Continuously scans available Wi-Fi channels to discover access points.

Suspicious AP Detection: Identifies suspicious networks based on specific criteria.

Network Summarization: Displays tables for available and flagged access points.

Detection for Mobile Hotspots: Identifies Android-based mobile hotspots and ESP fake APs.



-Python 3.x: Install the latest version of Python.

#sudo apt update && sudo apt install python3 python3-pip

-Scapy Library: Install it using the following command:

#sudo pip3 install scapy


-PrettyTable Library: Install it using the following command:

#sudo pip3 install prettytable

-Wireless Interface in Monitor Mode:

-Ensure your wireless card supports monitor mode.

-Install aircrack-ng if you don't have it:

#sudo apt install aircrack-ng

-Enable monitor mode using:

#sudo airmon-ng start wlan0
