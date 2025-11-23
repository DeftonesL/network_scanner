#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import scapy.all as scapy
import argparse
import socket
import requests
import json
import concurrent.futures
from datetime import datetime
from colorama import init, Fore, Style
from tqdm import tqdm

init(autoreset=True)

Mac_Vendor_API = "https://api.macvendors.co/"

class NetworkScanner:
    def __init__(self):
        self.target_ip = ""
        self.port_range = []
        self.results = []

    def get_arguments(self):
        parser = argparse.ArgumentParser(description="Ultimate Python Network Scanner v3.0")
        parser.add_argument("-t", "--target", dest="target", required=True)
        parser.add_argument("-p", "--ports", dest="ports", default="top")
        options = parser.parse_args()
        self.target_ip = options.target
        self.port_range = self.parse_ports(options.ports)
        return options

    def parse_ports(self, port_str):
        if port_str == "top":
            return [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3306, 3389, 5900, 8080, 8443]
        elif "-" in port_str:
            start, end = map(int, port_str.split("-"))
            return range(start, end + 1)
        else:
            return [int(p) for p in port_str.split(",")]

    def print_logo(self):
        print(Fore.CYAN + Style.BRIGHT + """
    ╔═══════════════════════════════════════════════╗
    ║      ULTIMATE NETWORK SCANNER v3.0 🚀         ║
    ║   [OS Detect] [ThreadPools] [Smart Scan]      ║
    ╚═══════════════════════════════════════════════╝
        """ + Style.RESET_ALL)

    def get_mac_vendor(self, mac_address):
        try:
            response = requests.get(f"{Mac_Vendor_API}{mac_address}", timeout=2)
            if response.status_code == 200:
                return response.text.strip()
        except:
            pass
        return "Unknown Vendor"

    def detect_os(self, ip_address):
        try:
            pkt = scapy.IP(dst=ip_address)/scapy.ICMP()
            ans = scapy.sr1(pkt, timeout=1, verbose=0)
            if ans:
                ttl = ans.ttl
                if ttl <= 64:
                    return "Linux/Unix"
                elif ttl <= 128:
                    return "Windows"
                elif ttl <= 255:
                    return "Cisco/Network Device"
        except:
            pass
        return "Unknown OS"

    def scan_port_worker(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            banner = ""
            if result == 0:
                try:
                    sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').split('\n')[0].strip()
                except:
                    pass
                sock.close()
                return {"port": port, "status": "open", "service": banner if banner else "Unknown"}
            sock.close()
        except:
            pass
        return None

    def arp_scan(self, ip):
        print(f"{Fore.BLUE}[*] Discovery Phase: Sending ARP Requests to {ip}...")
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        answered_list = scapy.srp(broadcast/arp_request, timeout=2, verbose=False)[0]
        clients = []
        for element in answered_list:
            clients.append({"ip": element[1].psrc, "mac": element[1].hwsrc})
        return clients

    def run(self):
        self.print_logo()
        self.get_arguments()
        
        active_hosts = self.arp_scan(self.target_ip)
        
        if not active_hosts:
            print(f"{Fore.RED}[!] No hosts found. Check your permissions (sudo) or IP range.")
            return

        print(f"{Fore.GREEN}[+] Found {len(active_hosts)} active hosts.\n")
        
        for host in active_hosts:
            ip = host['ip']
            mac = host['mac']
            vendor = self.get_mac_vendor(mac)
            os_guess = self.detect_os(ip)

            print(f"{Fore.YELLOW}══════════════════════════════════════════════════")
            print(f"Target: {Fore.WHITE}{ip}")
            print(f"MAC:    {Fore.WHITE}{mac} ({vendor})")
            print(f"OS:     {Fore.CYAN}{os_guess} (TTL estimate)")
            print(f"{Fore.YELLOW}══════════════════════════════════════════════════")

            open_ports = []
            print(f"[*] Scanning {len(self.port_range)} ports...")
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                future_to_port = {executor.submit(self.scan_port_worker, ip, port): port for port in self.port_range}
                
                for future in tqdm(concurrent.futures.as_completed(future_to_port), total=len(self.port_range), leave=False, unit="port"):
                    result = future.result()
                    if result:
                        print(f"    {Fore.GREEN}➜ Port {result['port']:<5} OPEN : {result['service']}")
                        open_ports.append(result)

            host['vendor'] = vendor
            host['os'] = os_guess
            host['ports'] = open_ports
            self.results.append(host)
            print("")

        self.save_results()

    def save_results(self):
        filename = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, "w") as f:
            json.dump(self.results, f, indent=4)
        print(f"{Fore.GREEN}[√] Full report saved to: {filename}")

if __name__ == "__main__":
    try:
        scanner = NetworkScanner()
        scanner.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Aborted by user.")
    except PermissionError:
        print(f"\n{Fore.RED}[!] Error: Please run as Root/Administrator.")
