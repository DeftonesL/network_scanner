 # 🛡️ Advanced Network Scanner


![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)

![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey?style=for-the-badge)


A powerful, multi-threaded network reconnaissance tool built from scratch using Python. It combines Layer 2 discovery (ARP) with Layer 4 analysis (TCP) to provide a complete map of the target network.


> **Designed for Penetration Testers and Network Admins.**


---


## 🚀 Features


* **⚡ Blazing Fast:** Uses **Multi-threading** to scan ports concurrently, making it significantly faster than traditional sequential scanners.

* **🕵️ Active Discovery:** Utilizes **ARP Requests** (Layer 2) to identify all active hosts on a local network, bypassing ICMP firewalls.

* **🏭 Device Fingerprinting:** Automatically identifies device manufacturers (Apple, Huawei, Dell, etc.) via **MAC Vendor API**.

* **🔓 Service Enumeration:** Performs **Banner Grabbing** to detect running services and versions (Apache, SSH, FTP, etc.).

* **💾 Auto-Reporting:** Exports scan results automatically to a **JSON file** for further analysis.

* **🎨 Clean Interface:** User-friendly CLI with color-coded output.


---


## 🛠️ Installation


### 1. Clone the Repository

```bash

git clone [https://github.com/DeftonesL/network_scanner/blob/main/Network_Scanner.py](https://github.com/DeftonesL/network_scanner/blob/main/Network_Scanner.py)

cd Network_Scanner

```

### 2. Install Dependencies

```bash

pip install -r requirements.txt

```

Note: If you prefer manual installation or don't use the requirements file:

```bash

pip install scapy colorama requests

```

## ⚠️ Windows Users (Important)


Since this tool uses raw packets (Scapy), you must install Npcap to allow it to work on Windows.


 1   Download Npcap from npcap.com.


 2   During installation, check the box: Install Npcap in WinPcap API-compatible Mode.

    

## 💻 Usage

```bash

sudo python3 Network_Scanner.py -t 192.168.1.1/24

```

Command Line Arguments:

```bash

Argument,               Description,                   Example

"-t, --target",   Target IP or Subnet (Required),    -t 10.0.0.1/24

--ports,          Scan specific ports (Future update), --ports yes


Run the script with root (Linux) or Administrator (Windows) privileges.

```


Basic Scan (Discovery & Top Ports)


## 📸 Screenshots

```Plaintext

[+] Port 22 OPEN: SSH-2.0-OpenSSH_8.2p1 Ubuntu

[+] Port 80 OPEN: Apache/2.4.41 (Ubuntu)

```

(Results are saved to scan_report_2024.json)


## ⚠️ Disclaimer


This tool is developed for educational purposes and authorized security testing only.


  1  Do not scan networks you do not own or have explicit permission to test.


  2 The author is not responsible for any misuse of this tool.


 ##  👨‍💻 Author


* ### Saleh


    Role: Penetration Tester & Developer


    GitHub: DeftonesL


## 🌟 Show Support


If you find this tool useful, please give it a star on GitHub! ⭐ 
