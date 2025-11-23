#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Modern Network Scanner
Author: Saleh (Custom Built)
Features: ARP Discovery, Multi-threaded Port Scan, Banner Grabbing, MAC Vendor Lookup.
"""

import scapy.all as scapy
import argparse
import socket
import requests
import json
import threading
from queue import Queue
from datetime import datetime
from colorama import init, Fore, Style

# Initialize Colorama for auto-resetting colors
init(autoreset=True)

# Configuration
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3306, 3389, 8080, 8443]
Mac_Vendor_API = "https://api.macvendors.co/"

class NetworkScanner:
    def __init__(self):
        self.target_ip = ""
        self.results = []
        self.lock = threading.Lock()

    def get_arguments(self):
        """Parse command line arguments."""
        parser = argparse.ArgumentParser(description="Advanced Python Network Scanner")
        parser.add_argument("-t", "--target", dest="target", help="Target IP / IP Range (e.g. 192.168.1.1/24)", required=True)
        parser.add_argument("--ports", dest="ports", help="Scan specific ports? (yes/no)", default="no")
        options = parser.parse_args()
        self.target_ip = options.target
        return options

    def print_logo(self):
        print(Fore.GREEN + """
        ╔══════════════════════════════════════╗
        ║     ADVANCED NETWORK SCANNER v2.0    ║
        ║     [ARP] [TCP] [Banner Grab]        ║
        ╚══════════════════════════════════════╝
        """ + Style.RESET_ALL)

    def get_mac_vendor(self, mac_address):
        """Fetch device manufacturer via API."""
        try:
            response = requests.get(f"{Mac_Vendor_API}{mac_address}")
            if response.status_code == 200:
                return response.text.strip()
            return "Unknown Vendor"
        except:
            return "Unknown"

    def scan_port(self, ip, port, open_ports_list):
        """Try to connect to a port and grab the banner."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1) # Fast timeout
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                # Port is Open, try Banner Grabbing
                banner = "Unknown Service"
                try:
                    sock.send(b'HEAD / HTTP/1.0\r\n\r\n') # Trigger HTTP response
                    banner_bytes = sock.recv(1024)
                    banner = banner_bytes.decode('utf-8', errors='ignore').split('\n')[0].strip()
                except:
                    pass
                
                with self.lock:
                    print(f"    {Fore.GREEN}[+] Port {port} OPEN: {Fore.YELLOW}{banner}")
                    open_ports_list.append({"port": port, "service": banner})
            sock.close()
        except:
            pass

    def thread_port_scan(self, ip):
        """Manage threads for port scanning."""
        print(f"{Fore.CYAN}[*] Scanning Top Ports on {ip}...")
        open_ports = []
        threads = []
        
        for port in COMMON_PORTS:
            t = threading.Thread(target=self.scan_port, args=(ip, port, open_ports))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
            
        return open_ports

    def arp_scan(self, ip):
        """Perform ARP Request to find active devices."""
        print(f"{Fore.BLUE}[*] Starting ARP Discovery on {ip}...\n")
        
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        
        # Verbose=False to hide scapy default output
        answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

        clients_list = []
        print(f"{'IP Address':<20} {'MAC Address':<20} {'Vendor'}")
        print("-" * 60)

        for element in answered_list:
            client_ip = element[1].psrc
            client_mac = element[1].hwsrc
            vendor = self.get_mac_vendor(client_mac)
            
            print(f"{Fore.WHITE}{client_ip:<20} {Fore.RED}{client_mac:<20} {Fore.MAGENTA}{vendor}")
            
            client_dict = {
                "ip": client_ip, 
                "mac": client_mac, 
                "vendor": vendor,
                "open_ports": []
            }
            clients_list.append(client_dict)

        return clients_list

    def save_results(self):
        """Save scan data to JSON."""
        filename = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, "w") as f:
            json.dump(self.results, f, indent=4)
        print(f"\n{Fore.GREEN}[√] Report saved to: {filename}")

    def run(self):
        self.print_logo()
        options = self.get_arguments()
        
        # 1. Start ARP Discovery
        active_hosts = self.arp_scan(self.target_ip)
        self.results = active_hosts

        # 2. Port Scan if user requested or default logic
        if active_hosts:
            print(f"\n{Fore.BLUE}[*] Hosts found: {len(active_hosts)}. Starting Port Scan & Banner Grabbing...\n")
            for host in active_hosts:
                # Do Deep Scan on found hosts
                found_ports = self.thread_port_scan(host['ip'])
                host['open_ports'] = found_ports
        else:
            print(f"{Fore.RED}[!] No hosts found or permission denied (Try sudo).")

        # 3. Save
        self.save_results()

if __name__ == "__main__":
    try:
        scanner = NetworkScanner()
        scanner.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Ctrl+C Detected. Exiting gracefully.")
    except PermissionError:
        print(f"\n{Fore.RED}[!] Error: Run as Root/Administrator (Required for ARP/Scapy).")