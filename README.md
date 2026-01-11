<h1 align="center">
  <br>
  <img src="assets/logo.png" alt="RafSec" width="120">
  <br>
  RafSec Total Security
  <br>
</h1>

<h4 align="center">A Complete Security Suite for Windows & Linux</h4>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#building">Building</a> •
  <a href="#disclaimer">Disclaimer</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-3776ab?style=flat-square&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-blue?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/Version-3.0.0-orange?style=flat-square" alt="Version">
</p>

---

## 🛡️ Overview

**RafSec Total Security** is a comprehensive security suite that combines static malware analysis, real-time protection, and system utilities into one powerful application.

Built with Python and CustomTkinter, it features a premium dark-themed UI and professional-grade security tools.

## ✨ Features

### 🔍 Malware Scanner
- **YARA Signature Scanning** - Industry-standard pattern matching
- **Heuristic Analysis** - Entropy, imports, sections analysis
- **EICAR Detection** - Standard antivirus test file detection
- **Machine Learning** - Random Forest threat classification

### ☁️ Cloud Intelligence
- **VirusTotal Integration** - Check files against 70+ AV engines
- **Hash Lookup** - MD5, SHA256, Imphash verification

### 📡 Network Monitor
- **Active Connections** - View all network activity
- **Process Identification** - See which apps are connecting
- **Kill Process** - Terminate suspicious connections
- **Suspicious Port Detection** - Flag known malware ports

### 🔐 File Vault
- **AES-256 Encryption** - Military-grade file protection
- **Password Protection** - PBKDF2 key derivation
- **Secure Storage** - Encrypted .rafenc format

### 🛑 Ransomware Protection
- **Honeypot Files** - Decoy files to detect ransomware early
- **Real-time Monitoring** - Instant alert on tampering

### 🧹 System Tools
- **Junk Cleaner** - Remove temp files and caches
- **File Shredder** - Secure deletion (3-pass overwrite)
- **Quarantine Manager** - Isolate suspicious files

### 🎙️ Additional Features
- **Voice Alerts** - Audio notifications for threats
- **System Tray** - Background operation
- **Live Protection** - Monitor Downloads folder
- **Whitelist** - Exclude trusted files

## 📦 Installation

### Prerequisites
- Python 3.8 or higher
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

### Windows Users
```batch
pip install -r requirements.txt
python gui.py
```

### Linux Users
```bash
pip3 install -r requirements.txt
python3 gui.py
```

## 🚀 Usage

### GUI Mode (Recommended)
```bash
python gui.py
```

### CLI Mode
```bash
# Basic scan
python main.py suspicious.exe

# Full scan with ML
python main.py malware.exe --full

# JSON output
python main.py sample.exe --json
```

## 🔧 Configuration

### VirusTotal API
1. Get a free API key at [virustotal.com](https://www.virustotal.com)
2. Go to Settings → Enter API Key → Save

### Settings are auto-saved to `config.json`

## 🏗️ Building

### Create Standalone Executable

**Windows:**
```batch
build_windows.bat
```

**Linux:**
```bash
chmod +x build_linux.sh
./build_linux.sh
```

Output: `dist/RafSec.exe` (Windows) or `dist/RafSec` (Linux)

### Manual Build
```bash
pyinstaller --noconfirm --onefile --windowed \
    --name "RafSec" \
    --add-data "engine:engine" \
    --add-data "utils:utils" \
    --add-data "rules:rules" \
    gui.py
```

## 📁 Project Structure

```
RafSec/
├── gui.py              # Main GUI Application
├── gui_splash.py       # Splash Screen
├── main.py             # CLI Interface
├── requirements.txt    # Dependencies
├── LICENSE             # MIT License
│
├── engine/             # Core Security Engine
│   ├── analyzer.py     # Heuristic + YARA Analysis
│   ├── extractor.py    # PE Feature Extraction
│   ├── cloud_scanner.py# VirusTotal Integration
│   ├── net_monitor.py  # Network Monitor
│   ├── vault.py        # File Encryption
│   ├── quarantine.py   # Quarantine Manager
│   ├── honeypot.py     # Ransomware Trap
│   ├── cleaner.py      # System Cleaner
│   ├── shredder.py     # Secure Delete
│   ├── firewall.py     # Firewall Control
│   └── ml_model.py     # ML Classification
│
├── utils/              # Utilities
│   ├── config.py       # Settings Manager
│   ├── voice.py        # Voice Alerts
│   ├── whitelist.py    # Exclusions
│   └── helpers.py      # Hash/Validation
│
├── rules/              # YARA Rules
│   └── malware_index.yar
│
└── assets/             # Icons & Images
    └── logo.png
```

## ⚠️ Disclaimer

> **THIS SOFTWARE IS PROVIDED FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY.**
>
> RafSec is designed to demonstrate:
> - Static malware analysis techniques
> - PE file format parsing
> - YARA signature matching
> - Machine learning for security
> - Modern Python GUI development
>
> **IMPORTANT:**
> - This is NOT a replacement for professional antivirus software
> - Do NOT rely solely on this tool for malware protection
> - Always use proper sandboxing when analyzing suspicious files
> - The authors are not responsible for any misuse or damage
>
> Use at your own risk. For production environments, use certified security solutions.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**RafSec Developer**

- GitHub: [@LetnanRaffi](https://github.com/LetnanRaffi)

---

<p align="center">
  Made with ❤️ by RafSec Team
  <br>
  <b>Stay Safe, Stay Secure</b> 🛡️
</p>
