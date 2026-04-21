<br>
<p align="center">
  <img src="banner.png" alt="ATTENTION Banner" width="80%" style="max-width:1200px; border-radius:12px;">
</p>
<br>
<h1 align="center">ATTENTION</h1>
<p align="center">Network Audit & Pentest Tool</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue">
  <img src="https://img.shields.io/badge/status-active-success">
  <img src="https://img.shields.io/badge/license-MIT-green">
</p>

Advanced Network Audit & Pentest Tool

A powerful, multi-language (English/Russian) Python-based reconnaissance and network auditing tool. It acts as an intelligent wrapper around Nmap, automating complex scans, assessing network vulnerability, and generating clear, readable reports in the terminal and output files.

🌟 Features

Multi-Language UI: Native support for English and Russian interfaces (--lang en/ru).

Interactive & CLI Modes: Use the beautiful interactive console menu or run it headless via command-line arguments.

6 Specialized Scan Modes: Ranging from basic footprinting (fast) to active vulnerability scanning (vuln) and simulated attacks (pentest).

Smart Parsing: Filters out Nmap noise and highlights confirmed vulnerabilities and successful brute-force attempts.

Vulnerability Scoring: Automatically calculates a 0-100% risk score for your network based on open ports, services, and CVEs.

Export Ready: Automatically saves results to JSON and TXT for reporting or further automation.

⚠️ Legal Disclaimer

EDUCATIONAL AND AUTHORIZED USE ONLY. This tool is intended strictly for legal security auditing, penetration testing, and educational purposes. You must only scan networks, systems, and devices that you own or have explicit, written permission to test. Unauthorized scanning or attacking of third-party systems is illegal. The authors assume no liability and are not responsible for any misuse or damage caused by this program.

⚙️ Requirements & Installation

1. Install Nmap (Required)

This script relies on the core Nmap engine. You must install it on your system:

Windows: Download the installer from nmap.org/download.html. Ensure it's added to your system PATH.

Linux (Debian/Ubuntu): sudo apt-get install nmap

macOS: brew install nmap

2. Setup the Repository

Optional: Create a virtual environment

python -m venv venv
# On Windows use:
venv\Scripts\activate
# On Linux/macOS use:
source venv/bin/activate


Install dependencies

pip install -r requirements.txt


🚀 Usage

Interactive Mode (Recommended)

Simply run the script without any arguments to enter the interactive console:

python nmap_scanner.py


You will be prompted to select the language, target IP, scan mode, and file export options.

Command-Line Interface (CLI)

Perfect for automation, scripting, or quick scans.

python nmap_scanner.py <TARGET_IP> [OPTIONS]


Options:

-m, --mode: Set scan mode (fast, full, aggressive, vuln, pentest, dos_check). Default: aggressive.

-o, --output: Base name for saved report files (e.g., -o report creates report.txt & report.json).

-l, --lang: Set language to English (en) or Russian (ru).

CLI Examples:

Fast scan with Russian output

python nmap_scanner.py 192.168.1.1 -m fast -l ru


Full pentest against a specific local server, saving reports to "audit_results"

python nmap_scanner.py 10.0.0.5 -m pentest -o audit_results


🛡️ Scan Modes Explained

Fast: Top 100 ports + Version detection. Very fast.

Full: All 65535 ports + Version detection. Slow but thorough.

Aggressive: OS detection, service fingerprinting, and default scripts.

Vuln: Searches for known CVE vulnerabilities against identified services (--script vuln,vulners).

Pentest: Active attack mode. Attempts brute-forcing default credentials and running exploits. (Time-limited to avoid hanging).

DoS Check: Checks service resistance against DoS scripts (--script dos).

🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the issues page.
We are waiting for your help and additions! Any feedback, code reviews, or suggestions are greatly appreciated.
