# 🛡️ Ultimate Network Scanner v4.0

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-4.0-orange?style=for-the-badge)

**The Ultimate Network Reconnaissance Tool.** A powerful, multi-threaded network scanner built from scratch using Python. It combines Layer 2 discovery (ARP) with Layer 4 analysis (TCP), OS Fingerprinting, and generates professional HTML reports.

> **Designed for Red Teamers, Penetration Testers, and Network Admins.**

---

## 🚀 Key Features

* **⚡ Turbo Speed:** Uses `ThreadPoolExecutor` to scan thousands of ports in seconds with adjustable thread count.
* **📊 HTML Dashboards:** Automatically generates a beautiful **HTML Report** for your findings, alongside a raw JSON file.
* **🧠 Smart Service Detection:** Combines **Banner Grabbing** with a fallback service mapping database to identify services even if they don't talk back.
* **🕵️ Deep Recon:**
    * **ARP Discovery:** Finds all active hosts (Layer 2).
    * **OS Fingerprinting:** Analyses TTL values to guess the Operating System (Windows/Linux/Cisco).
    * **MAC Vendor:** Identifies device manufacturers via API.
* **🎨 Interactive UI:** Features a clean CLI with progress bars (`tqdm`) and color-coded output.

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

pip install scapy colorama requests tqdm

```

## ⚠️ Windows Users (Important)


Since this tool uses raw packets (Scapy), you must install Npcap to allow it to work on Windows.


 1   Download Npcap from npcap.com.


 2   During installation, check the box: Install Npcap in WinPcap API-compatible Mode.

    

## 💻 Usage

```bash

sudo python3 Network_Scanner.py -t 192.168.1.1/24

```
```bash

Argument,               Description,                   Example

"-t, --target",   Target IP or Subnet (Required),    -t 10.0.0.1/24

--ports,          Scan specific ports (Future update), --ports yes


Run the script with root (Linux) or Administrator (Windows) privileges.

```


Basic Scan (Discovery & Top Ports)

## ⚡ Turbo Mode (High Speed)
Increase threads to 200 and lower timeout for blazing fast results.
```bash
sudo python3 Network_Scanner.py -t 192.168.1.0/24 --threads 200 --timeout 0.2
Command Line Arguments:
```

## 🎯 Full Range Scan
Scan all 65,535 ports with a custom output name.
```bash
sudo python3 Network_Scanner.py -t 192.168.1.15 -p all -o target_report
```

## 📸 output example

```Plaintext

[+] Found 5 active hosts. Starting Deep Scan...

Target: 192.168.1.15
MAC:    00:0C:29:BD:12:34 (VMware, Inc.)
OS:     Linux/Unix
══════════════════════════════════════════════════
    ➜ Port 22    OPEN : SSH-2.0-OpenSSH_8.2p1
    ➜ Port 80    OPEN : HTTP (Apache/2.4.41)

```

(Results are saved to scan_report_2024.json)

## HTML Report

The tool generates a file named scan_result.html containing a visual table of all discovered assets, ports, and services.

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
