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
