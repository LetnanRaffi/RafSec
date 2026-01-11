<h1 align="center">
  <br>
  <img src="assets/logo.png" alt="RafSec" width="120">
  <br>
  RafSec Total Security
  <br>
  <small>Open Source EDR Platform</small>
</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776ab?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-blue?style=for-the-badge" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Build-Passing-brightgreen?style=for-the-badge" alt="Build">
  <img src="https://img.shields.io/badge/Version-4.0.0-orange?style=for-the-badge" alt="Version">
</p>

<p align="center">
  <b>Enterprise-grade endpoint protection with behavioral analysis, memory forensics, and real-time threat detection.</b>
</p>

---

## 🎯 Overview

**RafSec Total Security** is a comprehensive Endpoint Detection & Response (EDR) platform that combines:

- 🔬 **Static Analysis** - PE parsing, YARA signatures, ML classification
- 🧠 **Behavioral Analysis** - Real-time detection of ransomware & process injection
- 💾 **Memory Forensics** - Scan running processes for fileless malware
- 🌐 **Network Security** - Connection monitoring & ARP spoofing detection
- 🛡️ **System Hardening** - Vulnerability scanning & privacy controls

Built with Python and CustomTkinter for a modern, cross-platform experience.

---

## ✨ Features

### 🔍 Malware Detection
| Feature | Description |
|---------|-------------|
| **YARA Engine** | 15+ rules for ransomware, trojans, keyloggers |
| **ML Classification** | Random Forest threat scoring |
| **EICAR Detection** | Standard AV test file support |
| **VirusTotal Cloud** | Hash lookup against 70+ engines |

### 🧠 Behavioral Analysis (EDR)
| Feature | Description |
|---------|-------------|
| **Ransomware Detector** | Blocks rapid file encryption (5+ files/2 sec) |
| **Process Injection Monitor** | Detects macro attacks (Word→PowerShell) |
| **Memory Scanner** | YARA scanning of process memory |
| **Rootkit Hunter** | Detect hidden processes |

### 🌐 Network Security
| Feature | Description |
|---------|-------------|
| **Connection Monitor** | View all active network connections |
| **WiFi Guard** | Detect ARP spoofing/MITM attacks |
| **Threat Intel Sync** | Download malicious IP feeds |
| **Kill Process** | Terminate suspicious connections |

### 🔐 Privacy & Hardening
| Feature | Description |
|---------|-------------|
| **Webcam Blocker** | Disable camera at system level |
| **Microphone Blocker** | Disable mic at system level |
| **RDP Disable** | Block Remote Desktop |
| **SMBv1 Disable** | Protect against WannaCry |
| **Telemetry Disable** | Stop Windows data collection |

### 🛠️ Tools
| Feature | Description |
|---------|-------------|
| **File Vault** | AES-256 encryption/decryption |
| **File Shredder** | Secure multi-pass deletion |
| **System Cleaner** | Remove temp/cache files |
| **USB Vaccine** | Immunize against AutoRun |
| **Stego Hunter** | Detect hidden image data |
| **PDF Reports** | Professional incident reports |

---

## 📦 Installation

### Prerequisites
- Python 3.10 or higher
- pip package manager

### Quick Install

```bash
# Clone the repository
git clone https://github.com/LetnanRaffi/RafSec.git
cd RafSec

# Install dependencies
pip install -r requirements.txt

# Run the application
python gui.py
```

### Platform-Specific Notes

**Windows:**
```batch
pip install -r requirements.txt
python gui.py
```

**Linux:**
```bash
pip3 install -r requirements.txt
python3 gui.py
```

> **Note:** Some features (Privacy Shield, System Hardener) require Administrator/root privileges.

---

## 🚀 Usage

### GUI Mode (Recommended)
```bash
python gui.py
```

### CLI Mode
```bash
# Basic scan
python main.py suspicious.exe

# Full analysis
python main.py malware.exe --full

# JSON output
python main.py sample.exe --json
```

---

## 🏗️ Architecture

```
RafSec/
├── gui.py                  # Main GUI Application
├── gui_splash.py           # Splash Screen
├── main.py                 # CLI Interface
│
├── engine/                 # Core Security Engine
│   ├── analyzer.py         # Heuristic + YARA Analysis
│   ├── extractor.py        # PE Feature Extraction
│   ├── ml_model.py         # ML Classification
│   ├── behavior_monitor.py # Real-time Behavioral Detection
│   ├── memory_scanner.py   # Process Memory Scanning
│   ├── rootkit_hunter.py   # Hidden Process Detection
│   ├── threat_intel.py     # Threat Feed Sync
│   ├── cloud_scanner.py    # VirusTotal Integration
│   ├── net_monitor.py      # Network Connections
│   ├── wifi_guard.py       # ARP Spoofing Detection
│   ├── vault.py            # File Encryption
│   ├── quarantine.py       # Threat Isolation
│   ├── honeypot.py         # Ransomware Trap
│   ├── cleaner.py          # System Cleanup
│   ├── shredder.py         # Secure Deletion
│   ├── firewall.py         # Firewall Control
│   ├── privacy.py          # Hardware Privacy
│   ├── hardener.py         # System Hardening
│   ├── stego_hunter.py     # Steganography
│   └── usb_vaccine.py      # AutoRun Protection
│
├── utils/                  # Utilities
│   ├── config.py           # Settings Manager
│   ├── voice.py            # Voice Alerts
│   ├── whitelist.py        # Exclusions
│   ├── helpers.py          # Hash/Validation
│   └── reporter.py         # PDF Reports
│
├── rules/                  # YARA Rules
│   ├── malware_index.yar   # File-based rules
│   └── memory_threats.yar  # In-memory rules
│
└── assets/                 # Icons & Images
    └── logo.png
```

---

## ⚠️ Disclaimer

> **THIS SOFTWARE IS PROVIDED FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY.**
>
> RafSec is designed to demonstrate:
> - Endpoint Detection & Response (EDR) concepts
> - Static and behavioral malware analysis
> - Memory forensics techniques
> - Network security monitoring
> - System hardening practices
>
> **IMPORTANT:**
> - This is NOT a replacement for enterprise security solutions
> - Do NOT rely solely on this tool for production protection
> - Always use proper sandboxing when analyzing malware
> - Some features require Administrator/root privileges
> - The authors are not responsible for any misuse or damage
>
> **Use at your own risk.** For production environments, use certified security solutions like CrowdStrike, SentinelOne, or Microsoft Defender.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**RafSec Developer**

- GitHub: [@LetnanRaffi](https://github.com/LetnanRaffi)

---

<p align="center">
  <b>Stay Safe, Stay Secure</b> 🛡️
  <br><br>
  Made with ❤️ by RafSec Team
</p>
