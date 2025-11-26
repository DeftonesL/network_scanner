#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import scapy.all as scapy
import argparse
import socket
import requests
import json
import os
import concurrent.futures
from datetime import datetime
from colorama import init, Fore, Style
from tqdm import tqdm

init(autoreset=True)

Mac_Vendor_API = "https://api.macvendors.co/"

# قاموس للخدمات الشائعة كبديل في حال فشل الـ Banner Grabbing
COMMON_SERVICES = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5900: "VNC", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt"
}

class NetworkScanner:
    def __init__(self):
        self.target_ip = ""
        self.port_range = []
        self.results = []
        self.args = None

    def get_arguments(self):
        parser = argparse.ArgumentParser(description="Ultimate Python Network Scanner v4.0")
        parser.add_argument("-t", "--target", dest="target", required=True, help="Target IP Range (e.g. 192.168.1.0/24)")
        parser.add_argument("-p", "--ports", dest="ports", default="top", help="Port range (top, all, or 1-1000)")
        parser.add_argument("--threads", dest="threads", type=int, default=100, help="Number of threads (Default: 100)")
        parser.add_argument("--timeout", dest="timeout", type=float, default=0.5, help="Socket timeout (Default: 0.5s)")
        parser.add_argument("-o", "--output", dest="output", default="scan_result", help="Output filename prefix")
        self.args = parser.parse_args()
        self.target_ip = self.args.target
        self.port_range = self.parse_ports(self.args.ports)

    def parse_ports(self, port_str):
        if port_str == "top":
            return list(COMMON_SERVICES.keys())
        elif port_str == "all":
            return range(1, 65536)
        elif "-" in port_str:
            start, end = map(int, port_str.split("-"))
            return range(start, end + 1)
        else:
            return [int(p) for p in port_str.split(",")]

    def print_logo(self):
        print(Fore.CYAN + Style.BRIGHT + """
    ╔═══════════════════════════════════════════════╗
    ║      ULTIMATE NETWORK SCANNER v4.0 🚀         ║
    ║   [HTML Report] [Smart Service] [Fast Scan]   ║
    ╚═══════════════════════════════════════════════╝
        """ + Style.RESET_ALL)

    def get_mac_vendor(self, mac_address):
        try:
            response = requests.get(f"{Mac_Vendor_API}{mac_address}", timeout=3)
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
                if ttl <= 64: return "Linux/Unix"
                elif ttl <= 128: return "Windows"
                elif ttl <= 255: return "Cisco/Network Device"
        except: pass
        return "Unknown OS"

    def scan_port_worker(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.args.timeout)
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                service_name = COMMON_SERVICES.get(port, "Unknown")
                banner = ""
                try:
                    sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').split('\n')[0].strip()
                except: pass
                
                sock.close()
                
                final_service = banner if banner else service_name
                return {"port": port, "status": "open", "service": final_service}
            sock.close()
        except: pass
        return None

    def arp_scan(self, ip):
        print(f"{Fore.BLUE}[*] Discovery Phase: Sending ARP Requests to {ip}...")
        try:
            arp_request = scapy.ARP(pdst=ip)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            answered_list = scapy.srp(broadcast/arp_request, timeout=2, verbose=False)[0]
            clients = []
            for element in answered_list:
                clients.append({"ip": element[1].psrc, "mac": element[1].hwsrc})
            return clients
        except Exception as e:
            print(f"{Fore.RED}[!] ARP Scan Error: {e}")
            return []

    def generate_html_report(self, filename):
        html_content = f"""
        <html>
        <head>
            <title>Scan Report - {self.target_ip}</title>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #1e1e1e; color: #f0f0f0; padding: 20px; }}
                h1 {{ color: #00ff41; border-bottom: 2px solid #00ff41; padding-bottom: 10px; }}
                .host-card {{ background-color: #2d2d2d; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }}
                .host-header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #444; padding-bottom: 10px; margin-bottom: 10px; }}
                .tag {{ background-color: #007acc; color: white; padding: 3px 8px; border-radius: 4px; font-size: 0.8em; margin-left: 10px; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
                th, td {{ text-align: left; padding: 8px; border-bottom: 1px solid #444; }}
                th {{ color: #00ff41; }}
                .closed {{ color: #ff5555; }}
            </style>
        </head>
        <body>
            <h1>🚀 Network Scan Report</h1>
            <p>Target: {self.target_ip} | Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        """
        
        for host in self.results:
            html_content += f"""
            <div class="host-card">
                <div class="host-header">
                    <h2>{host['ip']} <span class="tag">{host['os']}</span></h2>
                    <span>{host['mac']} ({host['vendor']})</span>
                </div>
                <table>
                    <tr><th>Port</th><th>Status</th><th>Service / Banner</th></tr>
            """
            if host['ports']:
                for port in host['ports']:
                    html_content += f"<tr><td>{port['port']}</td><td style='color:#00ff41'>OPEN</td><td>{port['service']}</td></tr>"
            else:
                html_content += "<tr><td colspan='3'>No open ports found in scanned range.</td></tr>"
            
            html_content += "</table></div>"

        html_content += "</body></html>"
        
        with open(f"{filename}.html", "w", encoding='utf-8') as f:
            f.write(html_content)
        print(f"{Fore.GREEN}[√] HTML Report generated: {filename}.html")

    def run(self):
        self.get_arguments()
        self.print_logo()
        
        active_hosts = self.arp_scan(self.target_ip)
        
        if not active_hosts:
            print(f"{Fore.RED}[!] No hosts found. Check your permissions (sudo) or IP range.")
            return

        print(f"{Fore.GREEN}[+] Found {len(active_hosts)} active hosts. Starting Deep Scan...\n")
        
        for host in active_hosts:
            ip = host['ip']
            mac = host['mac']
            vendor = self.get_mac_vendor(mac)
            os_guess = self.detect_os(ip)

            print(f"{Fore.YELLOW}══════════════════════════════════════════════════")
            print(f"Target: {Fore.WHITE}{ip}")
            print(f"MAC:    {Fore.WHITE}{mac} ({vendor})")
            print(f"OS:     {Fore.CYAN}{os_guess}")
            print(f"{Fore.YELLOW}══════════════════════════════════════════════════")

            open_ports = []
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.args.threads) as executor:
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

        # Save Reports
        self.generate_html_report(self.args.output)
        
        with open(f"{self.args.output}.json", "w") as f:
            json.dump(self.results, f, indent=4)
        print(f"{Fore.GREEN}[√] JSON Report saved: {self.args.output}.json")

if __name__ == "__main__":
    try:
        scanner = NetworkScanner()
        scanner.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Aborted by user.")
    except PermissionError:
        print(f"\n{Fore.RED}[!] Error: Please run as Root/Administrator.")
