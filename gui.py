#!/usr/bin/env python3
"""
RafSec Security Suite - Premium Edition
========================================
Complete security solution with premium UI.

Author: RafSec Team
Version: 3.0.0 PREMIUM

Features:
- File Scanner with YARA & ML
- VirusTotal Cloud Intelligence
- Network Monitor with Kill Process
- File Vault (Encryption)
- Ransomware Honeypot
- System Cleaner
- File Shredder
- Voice Alerts
- Live Protection
- System Tray Integration
"""

import customtkinter as ctk
from tkinter import filedialog, messagebox
import threading
import time
import os
import sys
import platform
import webbrowser
from datetime import datetime
from typing import Optional, Dict, Any, List

# ============================================================
# PATH CONFIGURATION
# ============================================================
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
    BUNDLE_DIR = sys._MEIPASS
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    BUNDLE_DIR = BASE_DIR

sys.path.insert(0, BASE_DIR)

# ============================================================
# IMPORTS - Engine Modules
# ============================================================
ENGINE_AVAILABLE = False
try:
    from engine.extractor import PEExtractor
    from engine.analyzer import MalwareAnalyzer, ThreatLevel, YaraScanner
    ENGINE_AVAILABLE = True
except ImportError as e:
    print(f"[WARNING] Core engine: {e}")

try:
    from engine.cloud_scanner import CloudScanner
    CLOUD_AVAILABLE = True
except:
    CLOUD_AVAILABLE = False

try:
    from engine.net_monitor import NetworkMonitor, PSUTIL_AVAILABLE
except:
    PSUTIL_AVAILABLE = False
    class NetworkMonitor:
        @staticmethod
        def get_connections(): return []
        @staticmethod
        def kill_process(pid): return False

try:
    from engine.vault import FileVault, CRYPTO_AVAILABLE
except:
    CRYPTO_AVAILABLE = False

try:
    from engine.honeypot import RansomwareHoneypot, WATCHDOG_AVAILABLE
except:
    WATCHDOG_AVAILABLE = False

try:
    from engine.cleaner import SystemCleaner
except:
    class SystemCleaner:
        @staticmethod
        def scan_junk(): return type('obj', (object,), {'size_formatted': '0 B', 'locations': {}})()
        @staticmethod
        def clean_junk(callback=None): return (True, "0 B", 0)

try:
    from engine.shredder import FileShredder
except:
    class FileShredder:
        @staticmethod
        def secure_delete(path, passes=3): return (False, "Not available")

try:
    from utils.voice import VoiceAlert
except:
    class VoiceAlert:
        @classmethod
        def speak(cls, text): pass
        @classmethod
        def set_enabled(cls, enabled): pass
        @classmethod
        def is_available(cls): return False

try:
    from utils.whitelist import Whitelist
except:
    class Whitelist:
        def __init__(self): self._list = []
        def add(self, path): return True
        def remove(self, path): return True
        def is_whitelisted(self, path): return False
        def get_all(self): return []

try:
    from utils.helpers import FileValidator
except:
    class FileValidator:
        @staticmethod
        def validate_for_analysis(path): return (True, "")

# System tray & Images
try:
    import pystray
    from PIL import Image
    TRAY_AVAILABLE = True
except:
    TRAY_AVAILABLE = False

# Load logo image
LOGO_IMAGE = None
try:
    logo_path = os.path.join(BASE_DIR, 'assets', 'logo.png')
    if os.path.exists(logo_path):
        LOGO_IMAGE = ctk.CTkImage(
            light_image=Image.open(logo_path),
            dark_image=Image.open(logo_path),
            size=(80, 80)
        )
except:
    pass

# ============================================================
# PREMIUM THEME - "CLEAN LIGHT" PALETTE
# ============================================================
ctk.set_appearance_mode("Light")
ctk.set_default_color_theme("blue")

THEME = {
    # Backgrounds (Light Mode)
    'bg_deep': '#f8fafc',       # Very light grey (main)
    'bg_sidebar': '#ffffff',    # Pure white sidebar
    'bg_card': '#ffffff',       # White cards
    'bg_elevated': '#f1f5f9',   # Slightly grey elevated
    'bg_input': '#f1f5f9',      # Input fields
    
    # Accents
    'accent_primary': '#3b82f6',  # Bright blue
    'accent_hover': '#2563eb',
    'accent_success': '#10b981',  # Emerald
    'accent_warning': '#f59e0b',  # Amber
    'accent_danger': '#ef4444',   # Red
    
    # Text (Dark on Light)
    'text_primary': '#1e293b',    # Dark slate grey
    'text_secondary': '#64748b',  # Medium grey
    'text_muted': '#94a3b8',      # Light grey
    
    # Special
    'glow': '#3b82f6',
    'border': '#e2e8f0',          # Light border
    'shadow': '#cbd5e1',          # Shadow color
}

# Fonts
FONT_FAMILY = "Segoe UI" if platform.system() == "Windows" else "SF Pro Display"
FONT_MONO = "Consolas" if platform.system() == "Windows" else "SF Mono"


# ============================================================
# STATISTICS TRACKER
# ============================================================
class Stats:
    files_scanned = 0
    threats_found = 0
    last_scan = None
    quarantine = []


# ============================================================
# MAIN APPLICATION
# ============================================================
class RafSecApp(ctk.CTk):
    """Main application window - Premium Edition."""
    
    VERSION = "3.0.0"
    
    def __init__(self):
        super().__init__()
        
        # Window config
        self.title(f"RafSec Security Suite v{self.VERSION}")
        self.geometry("1100x750")
        self.minsize(1000, 700)
        self.configure(fg_color=THEME['bg_deep'])
        
        # Grid
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        # Components
        self.whitelist = Whitelist()
        self.honeypot = None
        self.tray_icon = None
        
        # Create frames
        self.sidebar = Sidebar(self)
        self.sidebar.grid(row=0, column=0, sticky="nswe")
        
        self.frames = {}
        self.frames['dashboard'] = DashboardFrame(self)
        self.frames['scanner'] = ScannerFrame(self)
        self.frames['network'] = NetworkFrame(self)
        self.frames['quarantine'] = QuarantineFrame(self)
        self.frames['vault'] = VaultFrame(self)
        self.frames['tools'] = ToolsFrame(self)
        self.frames['settings'] = SettingsFrame(self)
        
        self.show_frame('dashboard')
        
        # Window close handler
        self.protocol("WM_DELETE_WINDOW", self._on_close)
    
    def show_frame(self, name: str):
        """Switch to a frame."""
        for frame in self.frames.values():
            frame.grid_forget()
        
        self.frames[name].grid(row=0, column=1, sticky="nswe", padx=25, pady=25)
        self.sidebar.set_active(name)
        
        if name == 'dashboard':
            self.frames['dashboard'].refresh()
    
    def add_log(self, msg: str):
        """Add to system log."""
        if hasattr(self.frames.get('scanner'), 'add_log'):
            self.frames['scanner'].add_log(msg)
    
    def _on_close(self):
        """Handle window close."""
        if TRAY_AVAILABLE and hasattr(self, 'minimize_to_tray') and self.minimize_to_tray:
            self.withdraw()
            self._create_tray()
        else:
            self._cleanup_and_exit()
    
    def _cleanup_and_exit(self):
        """Cleanup and exit."""
        if self.honeypot:
            try:
                self.honeypot.stop_monitoring()
            except:
                pass
        
        if self.tray_icon:
            try:
                self.tray_icon.stop()
            except:
                pass
        
        self.destroy()
    
    def _create_tray(self):
        """Create system tray icon."""
        if not TRAY_AVAILABLE:
            self._cleanup_and_exit()
            return
        
        def on_open(icon, item):
            self.after(0, self.deiconify)
        
        def on_quit(icon, item):
            icon.stop()
            self.after(0, self._cleanup_and_exit)
        
        # Create simple icon
        try:
            img = Image.new('RGB', (64, 64), '#3b82f6')
            menu = pystray.Menu(
                pystray.MenuItem("Open RafSec", on_open),
                pystray.MenuItem("Quit", on_quit)
            )
            self.tray_icon = pystray.Icon("RafSec", img, "RafSec Security", menu)
            threading.Thread(target=self.tray_icon.run, daemon=True).start()
        except:
            self._cleanup_and_exit()


# ============================================================
# SIDEBAR - MODERN NAVIGATION
# ============================================================
class Sidebar(ctk.CTkFrame):
    """Modern sidebar navigation."""
    
    def __init__(self, parent):
        super().__init__(parent, width=240, fg_color=THEME['bg_sidebar'], corner_radius=0)
        self.parent = parent
        self.grid_propagate(False)
        self.buttons = {}
        
        self._create_widgets()
    
    def _create_widgets(self):
        # Logo
        logo_frame = ctk.CTkFrame(self, fg_color="transparent")
        logo_frame.pack(pady=(30, 20), padx=20)
        
        # Use actual logo image if available
        if LOGO_IMAGE:
            ctk.CTkLabel(
                logo_frame,
                text="",
                image=LOGO_IMAGE
            ).pack()
        else:
            ctk.CTkLabel(
                logo_frame,
                text="◆",
                font=ctk.CTkFont(size=40, weight="bold"),
                text_color=THEME['accent_primary']
            ).pack()
        
        ctk.CTkLabel(
            logo_frame,
            text="RAFSEC",
            font=ctk.CTkFont(family=FONT_FAMILY, size=22, weight="bold"),
            text_color=THEME['text_primary']
        ).pack()
        
        ctk.CTkLabel(
            logo_frame,
            text="Security Suite",
            font=ctk.CTkFont(size=11),
            text_color=THEME['text_muted']
        ).pack()
        
        # Divider
        ctk.CTkFrame(self, height=1, fg_color=THEME['border']).pack(fill='x', padx=20, pady=15)
        
        # Navigation items
        nav_items = [
            ('dashboard', '⬡', 'Dashboard'),
            ('scanner', '⎔', 'Scanner'),
            ('network', '◎', 'Network'),
            ('quarantine', '⬣', 'Quarantine'),
            ('vault', '⬢', 'Vault'),
            ('tools', '⚡', 'Tools'),
            ('settings', '⚙', 'Settings'),
        ]
        
        for name, icon, label in nav_items:
            btn = ctk.CTkButton(
                self,
                text=f"  {icon}   {label}",
                font=ctk.CTkFont(family=FONT_FAMILY, size=14),
                anchor="w",
                height=45,
                corner_radius=12,
                fg_color="transparent",
                text_color=THEME['text_secondary'],
                hover_color=THEME['bg_card'],
                command=lambda n=name: self.parent.show_frame(n)
            )
            btn.pack(fill='x', padx=15, pady=3)
            self.buttons[name] = btn
        
        # Bottom spacer
        ctk.CTkFrame(self, fg_color="transparent").pack(expand=True, fill='both')
        
        # Status
        self.status_label = ctk.CTkLabel(
            self,
            text="● Engine Online",
            font=ctk.CTkFont(size=10),
            text_color=THEME['accent_success'] if ENGINE_AVAILABLE else THEME['accent_danger']
        )
        self.status_label.pack(pady=20)
    
    def set_active(self, name: str):
        """Set active navigation button."""
        for btn_name, btn in self.buttons.items():
            if btn_name == name:
                btn.configure(fg_color=THEME['accent_primary'], text_color=THEME['text_primary'])
            else:
                btn.configure(fg_color="transparent", text_color=THEME['text_secondary'])


# ============================================================
# DASHBOARD FRAME
# ============================================================
class DashboardFrame(ctk.CTkFrame):
    """Dashboard with status overview."""
    
    def __init__(self, parent):
        super().__init__(parent, fg_color="transparent")
        self.parent = parent
        self._create_widgets()
    
    def _create_widgets(self):
        # Header
        ctk.CTkLabel(
            self,
            text="Dashboard",
            font=ctk.CTkFont(family=FONT_FAMILY, size=28, weight="bold"),
            text_color=THEME['text_primary']
        ).pack(anchor="w", pady=(0, 20))
        
        # Status card
        status_card = ctk.CTkFrame(self, fg_color=THEME['bg_card'], corner_radius=15)
        status_card.pack(fill='x', pady=(0, 20))
        
        status_inner = ctk.CTkFrame(status_card, fg_color="transparent")
        status_inner.pack(pady=30, padx=30)
        
        self.status_icon = ctk.CTkLabel(
            status_inner,
            text="◆",
            font=ctk.CTkFont(size=60, weight="bold"),
            text_color=THEME['accent_success']
        )
        self.status_icon.pack()
        
        self.status_text = ctk.CTkLabel(
            status_inner,
            text="SYSTEM SECURE",
            font=ctk.CTkFont(family=FONT_FAMILY, size=24, weight="bold"),
            text_color=THEME['accent_success']
        )
        self.status_text.pack(pady=(10, 5))
        
        self.status_detail = ctk.CTkLabel(
            status_inner,
            text="All systems operational",
            font=ctk.CTkFont(size=12),
            text_color=THEME['text_secondary']
        )
        self.status_detail.pack()
        
        # Protection toggles card
        protect_card = ctk.CTkFrame(self, fg_color=THEME['bg_card'], corner_radius=12)
        protect_card.pack(fill='x', pady=(20, 20))
        
        protect_inner = ctk.CTkFrame(protect_card, fg_color="transparent")
        protect_inner.pack(fill='x', padx=25, pady=15)
        protect_inner.grid_columnconfigure((0, 1, 2, 3), weight=1)
        
        # Real-Time Protection toggle
        ctk.CTkLabel(
            protect_inner,
            text="🛡️ Real-Time Protection",
            font=ctk.CTkFont(family=FONT_FAMILY, size=12, weight="bold"),
            text_color=THEME['text_primary']
        ).grid(row=0, column=0, sticky="w")
        
        self.realtime_var = ctk.BooleanVar(value=False)
        self.realtime_toggle = ctk.CTkSwitch(
            protect_inner,
            text="",
            variable=self.realtime_var,
            onvalue=True,
            offvalue=False,
            fg_color=THEME['accent_success'],
            command=self._toggle_realtime
        )
        self.realtime_toggle.grid(row=0, column=1, sticky="w", padx=(10, 40))
        
        # Startup Monitor toggle
        ctk.CTkLabel(
            protect_inner,
            text="🔒 Startup Monitor",
            font=ctk.CTkFont(family=FONT_FAMILY, size=12, weight="bold"),
            text_color=THEME['text_primary']
        ).grid(row=0, column=2, sticky="w")
        
        self.startup_var = ctk.BooleanVar(value=False)
        self.startup_toggle = ctk.CTkSwitch(
            protect_inner,
            text="",
            variable=self.startup_var,
            onvalue=True,
            offvalue=False,
            fg_color=THEME['accent_success'],
            command=self._toggle_startup
        )
        self.startup_toggle.grid(row=0, column=3, sticky="w")
        
        # Initialize guards
        self.realtime_guard = None
        self.persistence_monitor = None
        
        # Quick actions row
        actions = ctk.CTkFrame(self, fg_color="transparent")
        actions.pack(fill='x', pady=(0, 20))
        actions.grid_columnconfigure((0,1,2,3), weight=1)
        
        actions_data = [
            ("⎔ Quick Scan", THEME['accent_primary'], lambda: self.parent.show_frame('scanner')),
            ("◎ Network", THEME['bg_card'], lambda: self.parent.show_frame('network')),
            ("⬢ Vault", THEME['bg_card'], lambda: self.parent.show_frame('vault')),
            ("⚡ Tools", THEME['bg_card'], lambda: self.parent.show_frame('tools')),
        ]
        
        for i, (text, color, cmd) in enumerate(actions_data):
            btn = ctk.CTkButton(
                actions,
                text=text,
                font=ctk.CTkFont(family=FONT_FAMILY, size=13, weight="bold"),
                height=50,
                corner_radius=12,
                fg_color=color,
                hover_color=THEME['accent_hover'] if color == THEME['accent_primary'] else THEME['bg_elevated'],
                command=cmd
            )
            btn.grid(row=0, column=i, padx=8, sticky="ew")
        
        # Stats row
        stats_frame = ctk.CTkFrame(self, fg_color="transparent")
        stats_frame.pack(fill='x')
        stats_frame.grid_columnconfigure((0,1,2,3), weight=1)
        
        self.stat_labels = {}
        stats_data = [
            ('scanned', '0', 'Files Scanned', THEME['accent_primary']),
            ('threats', '0', 'Threats Found', THEME['accent_danger']),
            ('protected', '✓', 'Protection', THEME['accent_success']),
            ('cloud', 'Ready', 'Cloud Intel', THEME['accent_primary']),
        ]
        
        for i, (key, value, title, color) in enumerate(stats_data):
            card = ctk.CTkFrame(stats_frame, fg_color=THEME['bg_card'], corner_radius=12)
            card.grid(row=0, column=i, padx=8, sticky="ew")
            
            val = ctk.CTkLabel(
                card,
                text=value,
                font=ctk.CTkFont(family=FONT_FAMILY, size=28, weight="bold"),
                text_color=color
            )
            val.pack(pady=(25, 5))
            self.stat_labels[key] = val
            
            ctk.CTkLabel(
                card,
                text=title,
                font=ctk.CTkFont(size=11),
                text_color=THEME['text_secondary']
            ).pack(pady=(0, 25))
    
    def refresh(self):
        """Refresh statistics."""
        self.stat_labels['scanned'].configure(text=str(Stats.files_scanned))
        self.stat_labels['threats'].configure(text=str(Stats.threats_found))
    
    def set_status(self, score: float, detail: str = ""):
        """Update status display based on score thresholds."""
        if score < 40:
            # GREEN - Clean/Secure
            self.status_icon.configure(text="✓", text_color=THEME['accent_success'])
            self.status_text.configure(text="SYSTEM SECURE", text_color=THEME['accent_success'])
        elif score < 70:
            # YELLOW - Suspicious
            self.status_icon.configure(text="⚠", text_color=THEME['accent_warning'])
            self.status_text.configure(text="SUSPICIOUS ACTIVITY", text_color=THEME['accent_warning'])
        else:
            # RED - Threat
            self.status_icon.configure(text="⛔", text_color=THEME['accent_danger'])
            self.status_text.configure(text="THREAT DETECTED!", text_color=THEME['accent_danger'])
        
        if detail:
            self.status_detail.configure(text=detail)
    
    def _toggle_realtime(self):
        """Toggle real-time protection."""
        try:
            from engine.realtime_guard import RealTimeGuard
            
            if self.realtime_var.get():
                # Start protection
                if self.realtime_guard is None:
                    self.realtime_guard = RealTimeGuard(
                        threat_callback=self._on_realtime_threat
                    )
                
                if self.realtime_guard.start():
                    self.status_detail.configure(text="Real-time protection active")
                else:
                    self.realtime_var.set(False)
                    messagebox.showerror("Error", "Failed to start real-time protection")
            else:
                # Stop protection
                if self.realtime_guard:
                    self.realtime_guard.stop()
                self.status_detail.configure(text="All systems operational")
                
        except ImportError:
            self.realtime_var.set(False)
            messagebox.showerror("Error", "Real-time guard module not available")
    
    def _on_realtime_threat(self, path: str, score: float, threat_name: str):
        """Handle threat detected by real-time guard."""
        self.set_status(score, f"Threat blocked: {os.path.basename(path)}")
        Stats.threats_found += 1
        self.refresh()
    
    def _toggle_startup(self):
        """Toggle startup monitor."""
        try:
            from engine.persistence import PersistenceMonitor
            
            if self.startup_var.get():
                # Start monitoring
                if self.persistence_monitor is None:
                    self.persistence_monitor = PersistenceMonitor(
                        alert_callback=self._on_startup_alert
                    )
                
                self.persistence_monitor.start_monitoring(interval=60)
                self.status_detail.configure(text="Startup monitoring active")
            else:
                # Stop monitoring
                if self.persistence_monitor:
                    self.persistence_monitor.stop_monitoring()
                self.status_detail.configure(text="All systems operational")
                
        except ImportError:
            self.startup_var.set(False)
            messagebox.showerror("Error", "Persistence monitor not available")
    
    def _on_startup_alert(self, name: str, value: str):
        """Handle new startup entry detected."""
        try:
            from plyer import notification
            notification.notify(
                title="⚠️ New Startup Item Detected!",
                message=f"{name}\n{value[:50]}",
                app_name="RafSec",
                timeout=15
            )
        except:
            pass
        
        # Update status
        self.after(0, lambda: self.set_status(50, f"New startup: {name}"))


# ============================================================
# SCANNER FRAME
# ============================================================
class ScannerFrame(ctk.CTkFrame):
    """File scanner with terminal output."""
    
    def __init__(self, parent):
        super().__init__(parent, fg_color="transparent")
        self.parent = parent
        self.selected_file = None
        self.is_scanning = False
        
        self._create_widgets()
    
    def _create_widgets(self):
        # Header
        ctk.CTkLabel(
            self,
            text="File Scanner",
            font=ctk.CTkFont(family=FONT_FAMILY, size=28, weight="bold"),
            text_color=THEME['text_primary']
        ).pack(anchor="w", pady=(0, 20))
        
        # File selection
        file_card = ctk.CTkFrame(self, fg_color=THEME['bg_card'], corner_radius=15)
        file_card.pack(fill='x', pady=(0, 15))
        
        file_inner = ctk.CTkFrame(file_card, fg_color="transparent")
        file_inner.pack(fill='x', padx=25, pady=20)
        file_inner.grid_columnconfigure(1, weight=1)
        
        self.file_label = ctk.CTkLabel(
            file_inner,
            text="No file selected",
            font=ctk.CTkFont(family=FONT_MONO, size=12),
            text_color=THEME['text_secondary'],
            anchor="w"
        )
        self.file_label.grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 15))
        
        ctk.CTkButton(
            file_inner,
            text="Select File",
            font=ctk.CTkFont(family=FONT_FAMILY, size=12),
            height=40,
            corner_radius=10,
            fg_color=THEME['bg_elevated'],
            hover_color=THEME['border'],
            command=self._select_file
        ).grid(row=1, column=0)
        
        self.scan_btn = ctk.CTkButton(
            file_inner,
            text="⎔ Analyze",
            font=ctk.CTkFont(family=FONT_FAMILY, size=12, weight="bold"),
            height=40,
            corner_radius=10,
            fg_color=THEME['accent_primary'],
            hover_color=THEME['accent_hover'],
            state="disabled",
            command=self._start_scan
        )
        self.scan_btn.grid(row=1, column=2, sticky="e")
        
        # Cloud scan toggle
        self.cloud_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            file_inner,
            text="Cloud Scan (VirusTotal)",
            font=ctk.CTkFont(size=11),
            variable=self.cloud_var,
            fg_color=THEME['accent_primary']
        ).grid(row=1, column=1, padx=20)
        
        # Progress
        self.progress = ctk.CTkProgressBar(self, progress_color=THEME['accent_primary'])
        self.progress.pack(fill='x', pady=(0, 10))
        self.progress.set(0)
        self.progress.pack_forget()
        
        # Terminal
        ctk.CTkLabel(
            self,
            text="Analysis Output",
            font=ctk.CTkFont(family=FONT_FAMILY, size=14, weight="bold"),
            text_color=THEME['text_secondary']
        ).pack(anchor="w", pady=(10, 5))
        
        self.terminal = ctk.CTkTextbox(
            self,
            font=ctk.CTkFont(family=FONT_MONO, size=11),
            fg_color=THEME['bg_deep'],
            text_color=THEME['accent_success'],
            corner_radius=10,
            border_width=1,
            border_color=THEME['border']
        )
        self.terminal.pack(fill='both', expand=True)
        
        self._log("RafSec Scanner Ready")
        self._log(f"Engine: {'Online' if ENGINE_AVAILABLE else 'Offline'}")
        self._log(f"Cloud:  {'Available' if CLOUD_AVAILABLE else 'Unavailable'}")
        self._log("=" * 50)
    
    def _select_file(self):
        path = filedialog.askopenfilename(
            filetypes=[("Executables", "*.exe *.dll *.sys"), ("All", "*.*")]
        )
        if path:
            self.selected_file = path
            name = os.path.basename(path)
            size = os.path.getsize(path)
            size_str = f"{size/1024:.1f} KB" if size < 1024*1024 else f"{size/(1024*1024):.1f} MB"
            self.file_label.configure(text=f"📄 {name} ({size_str})", text_color=THEME['text_primary'])
            self.scan_btn.configure(state="normal")
            self._log(f"\nTarget: {path}")
    
    def _start_scan(self):
        if not self.selected_file or self.is_scanning:
            return
        
        # Check whitelist
        if self.parent.whitelist.is_whitelisted(self.selected_file):
            self._log(f"[SKIP] File is whitelisted")
            return
        
        self.is_scanning = True
        self.scan_btn.configure(state="disabled", text="Analyzing...")
        self.progress.pack(fill='x', pady=(0, 10))
        self.progress.set(0)
        
        VoiceAlert.speak("Scanning system.")
        threading.Thread(target=self._run_scan, daemon=True).start()
    
    def _run_scan(self):
        path = self.selected_file
        
        try:
            self._log("\n" + "=" * 50)
            self._log("INITIATING THREAT ANALYSIS")
            self._log("=" * 50)
            
            # Validate
            self._progress(0.1)
            if ENGINE_AVAILABLE:
                valid, msg = FileValidator.validate_for_analysis(path)
                if not valid:
                    self._log(f"[ERROR] {msg}")
                    self._complete(None)
                    return
            
            # EICAR check
            self._progress(0.15)
            self._log("\n[1] Signature Scan...")
            
            if ENGINE_AVAILABLE:
                analyzer = MalwareAnalyzer(None)
                is_eicar, _ = analyzer.check_eicar(path)
                if is_eicar:
                    self._log("  ⚠ EICAR TEST FILE DETECTED!")
                    result = analyzer.analyze(path)
                    self._show_result(result)
                    self._complete(result)
                    return
                self._log("  ✓ No known signatures")
            
            # YARA
            self._progress(0.25)
            self._log("\n[2] YARA Rules...")
            
            if ENGINE_AVAILABLE:
                scanner = YaraScanner()
                matches = scanner.scan(path)
                if matches:
                    for m in matches:
                        self._log(f"  ⚠ {m.rule_name}: {m.description}")
                else:
                    self._log("  ✓ No YARA matches")
            
            # PE Analysis
            self._progress(0.5)
            self._log("\n[3] PE Analysis...")
            
            result = None
            if ENGINE_AVAILABLE:
                extractor = PEExtractor(path)
                features = extractor.extract_all()
                
                self._log(f"  Entropy: {features.overall_entropy:.2f}")
                self._log(f"  Sections: {features.number_of_sections}")
                self._log(f"  Imports: {features.total_imports}")
                
                if features.suspicious_imports:
                    self._log(f"  ⚠ Suspicious APIs: {len(features.suspicious_imports)}")
                
                # Heuristics
                self._progress(0.7)
                self._log("\n[4] Heuristic Analysis...")
                
                analyzer = MalwareAnalyzer(features)
                result = analyzer.analyze(path)
                
                self._log(f"  Score: {result.suspicion_score:.1f}/100")
                
                extractor.close()
            
            # Cloud scan
            if self.cloud_var.get() and CLOUD_AVAILABLE:
                self._progress(0.85)
                self._log("\n[5] Cloud Intelligence...")
                
                cloud = CloudScanner()
                if cloud.is_configured():
                    import hashlib
                    with open(path, 'rb') as f:
                        sha256 = hashlib.sha256(f.read()).hexdigest()
                    
                    cloud_result = cloud.check_hash(sha256)
                    
                    if cloud_result.found:
                        self._log(f"  VirusTotal: {cloud_result.malicious_count}/{cloud_result.total_engines} detections")
                        if cloud_result.malicious_count > 0:
                            self._log(f"  ⚠ KNOWN THREAT ({cloud_result.malicious_count} vendors)")
                            if cloud_result.threat_names:
                                self._log(f"  Names: {', '.join(cloud_result.threat_names[:3])}")
                    else:
                        self._log("  ✓ Not found in VirusTotal")
                else:
                    self._log("  [Cloud] Info: Scan skipped (API Key not configured in Settings)")
            
            # Final
            self._progress(1.0)
            if result:
                self._show_result(result)
            
            self._complete(result)
            
        except Exception as e:
            self._log(f"\n[ERROR] {str(e)}")
            import traceback
            self._log(traceback.format_exc())
            self._complete(None)
    
    def _show_result(self, result):
        """Display scan result."""
        self._log("\n" + "=" * 50)
        threat = result.threat_level.value
        score = result.suspicion_score
        
        if threat in ['CRITICAL', 'HIGH']:
            self._log(f"⚠ VERDICT: {threat}")
            self._log(f"  Score: {score:.1f}/100")
            VoiceAlert.speak("Warning! Threat detected!")
        else:
            self._log(f"✓ VERDICT: {threat}")
            self._log(f"  Score: {score:.1f}/100")
        
        self._log("=" * 50)
    
    def _complete(self, result):
        """Complete scan."""
        def update():
            self.is_scanning = False
            self.scan_btn.configure(state="normal", text="⎔ Analyze")
            
            if result:
                Stats.files_scanned += 1
                score = result.suspicion_score
                
                # Update threat count based on score thresholds
                if score >= 70:
                    Stats.threats_found += 1
                
                # Update dashboard with score
                self.parent.frames['dashboard'].set_status(score, f"Score: {score:.1f}")
                self.parent.frames['dashboard'].refresh()
                
                # Voice feedback based on score
                if score < 40:
                    VoiceAlert.speak("Scan complete. System is secure.")
                elif score < 70:
                    VoiceAlert.speak("Scan complete. Suspicious activity detected.")
        
        self.after(0, update)
    
    def _progress(self, val):
        self.after(0, lambda: self.progress.set(val))
    
    def _log(self, msg):
        self.after(0, lambda: self._append(msg))
    
    def _append(self, msg):
        self.terminal.configure(state="normal")
        self.terminal.insert("end", msg + "\n")
        self.terminal.see("end")
        self.terminal.configure(state="disabled")
    
    def add_log(self, msg):
        self._log(msg)


# ============================================================
# NETWORK FRAME
# ============================================================
class NetworkFrame(ctk.CTkFrame):
    """Network connection monitor."""
    
    def __init__(self, parent):
        super().__init__(parent, fg_color="transparent")
        self.parent = parent
        self._create_widgets()
    
    def _create_widgets(self):
        # Header
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill='x', pady=(0, 15))
        header.grid_columnconfigure(0, weight=1)
        
        ctk.CTkLabel(
            header,
            text="Network Monitor",
            font=ctk.CTkFont(family=FONT_FAMILY, size=28, weight="bold"),
            text_color=THEME['text_primary']
        ).grid(row=0, column=0, sticky="w")
        
        ctk.CTkButton(
            header,
            text="⟳ Refresh",
            font=ctk.CTkFont(size=12),
            width=100,
            height=35,
            corner_radius=10,
            fg_color=THEME['accent_primary'],
            command=self._refresh
        ).grid(row=0, column=1)
        
        # Connections list
        self.scroll = ctk.CTkScrollableFrame(
            self,
            fg_color=THEME['bg_card'],
            corner_radius=12
        )
        self.scroll.pack(fill='both', expand=True)
        
        # Column headers
        headers = ctk.CTkFrame(self.scroll, fg_color="transparent")
        headers.pack(fill='x', padx=15, pady=10)
        
        cols = [("Process", 150), ("PID", 60), ("Remote IP", 150), ("Port", 60), ("Status", 100)]
        for i, (name, width) in enumerate(cols):
            ctk.CTkLabel(
                headers,
                text=name,
                font=ctk.CTkFont(size=11, weight="bold"),
                text_color=THEME['text_muted'],
                width=width
            ).pack(side='left', padx=5)
        
        self.conn_frames = []
        self._refresh()
    
    def _refresh(self):
        """Refresh connections list."""
        # Clear existing
        for frame in self.conn_frames:
            frame.destroy()
        self.conn_frames = []
        
        if not PSUTIL_AVAILABLE:
            lbl = ctk.CTkLabel(
                self.scroll,
                text="psutil not available",
                text_color=THEME['text_muted']
            )
            lbl.pack(pady=20)
            self.conn_frames.append(lbl)
            return
        
        connections = NetworkMonitor.get_connections()
        
        # Filter out Unknown processes and PID 0
        connections = [c for c in connections if c.process_name != "Unknown" and c.pid > 0]
        
        if not connections:
            lbl = ctk.CTkLabel(
                self.scroll,
                text="No active connections",
                text_color=THEME['text_muted']
            )
            lbl.pack(pady=20)
            self.conn_frames.append(lbl)
            return
        
        for conn in connections[:50]:  # Limit to 50
            row = ctk.CTkFrame(self.scroll, fg_color=THEME['bg_elevated'], corner_radius=8, height=40)
            row.pack(fill='x', padx=15, pady=2)
            row.pack_propagate(False)
            
            inner = ctk.CTkFrame(row, fg_color="transparent")
            inner.pack(fill='both', expand=True, padx=10, pady=5)
            
            # Process
            ctk.CTkLabel(
                inner,
                text=conn.process_name[:20],
                font=ctk.CTkFont(family=FONT_MONO, size=11),
                text_color=THEME['text_primary'],
                width=150,
                anchor="w"
            ).pack(side='left')
            
            # PID
            ctk.CTkLabel(
                inner,
                text=str(conn.pid),
                font=ctk.CTkFont(family=FONT_MONO, size=11),
                text_color=THEME['text_secondary'],
                width=60
            ).pack(side='left')
            
            # Remote
            ctk.CTkLabel(
                inner,
                text=conn.remote_addr or "-",
                font=ctk.CTkFont(family=FONT_MONO, size=11),
                text_color=THEME['text_primary'],
                width=150
            ).pack(side='left')
            
            # Port
            port_color = THEME['accent_danger'] if NetworkMonitor.is_suspicious_port(conn.remote_port) else THEME['text_secondary']
            ctk.CTkLabel(
                inner,
                text=str(conn.remote_port) if conn.remote_port else "-",
                font=ctk.CTkFont(family=FONT_MONO, size=11),
                text_color=port_color,
                width=60
            ).pack(side='left')
            
            # Status
            status_color = THEME['accent_success'] if conn.status == 'ESTABLISHED' else THEME['text_muted']
            ctk.CTkLabel(
                inner,
                text=conn.status,
                font=ctk.CTkFont(size=10),
                text_color=status_color,
                width=100
            ).pack(side='left')
            
            # Kill button
            if conn.pid > 0:
                ctk.CTkButton(
                    inner,
                    text="Kill",
                    font=ctk.CTkFont(size=10),
                    width=50,
                    height=25,
                    corner_radius=5,
                    fg_color=THEME['accent_danger'],
                    command=lambda p=conn.pid: self._kill_process(p)
                ).pack(side='right')
            
            self.conn_frames.append(row)
    
    def _kill_process(self, pid):
        """Kill a process."""
        if messagebox.askyesno("Confirm", f"Kill process {pid}?"):
            if NetworkMonitor.kill_process(pid):
                messagebox.showinfo("Success", f"Process {pid} terminated")
                self._refresh()
            else:
                messagebox.showerror("Error", "Failed to kill process")


# ============================================================
# QUARANTINE FRAME
# ============================================================
class QuarantineFrame(ctk.CTkFrame):
    """Quarantine manager for isolated files."""
    
    def __init__(self, parent):
        super().__init__(parent, fg_color="transparent")
        self.parent = parent
        self.selected_file = None
        
        # Import quarantine manager
        try:
            from engine.quarantine import QuarantineManager
            self.quarantine = QuarantineManager()
        except:
            self.quarantine = None
        
        self._create_widgets()
    
    def _create_widgets(self):
        # Header
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill='x', pady=(0, 15))
        header.grid_columnconfigure(0, weight=1)
        
        ctk.CTkLabel(
            header,
            text="Quarantine",
            font=ctk.CTkFont(family=FONT_FAMILY, size=28, weight="bold"),
            text_color=THEME['text_primary']
        ).grid(row=0, column=0, sticky="w")
        
        ctk.CTkButton(
            header,
            text="⟳ Refresh",
            font=ctk.CTkFont(size=12),
            width=100,
            height=35,
            corner_radius=10,
            fg_color=THEME['accent_primary'],
            command=self._refresh
        ).grid(row=0, column=1)
        
        # Info card
        info_card = ctk.CTkFrame(self, fg_color=THEME['bg_card'], corner_radius=12)
        info_card.pack(fill='x', pady=(0, 15))
        
        ctk.CTkLabel(
            info_card,
            text="🔒 Isolated files are stored safely here. They cannot harm your system.",
            font=ctk.CTkFont(size=11),
            text_color=THEME['text_secondary']
        ).pack(padx=20, pady=15)
        
        # Files list
        self.scroll = ctk.CTkScrollableFrame(
            self,
            fg_color=THEME['bg_card'],
            corner_radius=12
        )
        self.scroll.pack(fill='both', expand=True, pady=(0, 15))
        
        self.file_frames = []
        
        # Action buttons
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(fill='x')
        
        self.restore_btn = ctk.CTkButton(
            btn_frame,
            text="Restore Selected",
            font=ctk.CTkFont(size=12, weight="bold"),
            height=40,
            corner_radius=10,
            fg_color=THEME['accent_success'],
            state="disabled",
            command=self._restore_file
        )
        self.restore_btn.pack(side='left', padx=(0, 10))
        
        self.delete_btn = ctk.CTkButton(
            btn_frame,
            text="Delete Forever",
            font=ctk.CTkFont(size=12, weight="bold"),
            height=40,
            corner_radius=10,
            fg_color=THEME['accent_danger'],
            state="disabled",
            command=self._delete_file
        )
        self.delete_btn.pack(side='left')
        
        self._refresh()
    
    def _refresh(self):
        """Refresh quarantine list."""
        # Clear existing
        for frame in self.file_frames:
            frame.destroy()
        self.file_frames = []
        self.selected_file = None
        self.restore_btn.configure(state="disabled")
        self.delete_btn.configure(state="disabled")
        
        if not self.quarantine:
            lbl = ctk.CTkLabel(
                self.scroll,
                text="Quarantine manager not available",
                text_color=THEME['text_muted']
            )
            lbl.pack(pady=30)
            self.file_frames.append(lbl)
            return
        
        files = self.quarantine.list_quarantined()
        
        if not files:
            lbl = ctk.CTkLabel(
                self.scroll,
                text="✓ Quarantine is empty",
                text_color=THEME['accent_success']
            )
            lbl.pack(pady=30)
            self.file_frames.append(lbl)
            return
        
        for f in files:
            row = ctk.CTkFrame(self.scroll, fg_color=THEME['bg_elevated'], corner_radius=8, height=50)
            row.pack(fill='x', padx=15, pady=3)
            row.pack_propagate(False)
            
            inner = ctk.CTkFrame(row, fg_color="transparent")
            inner.pack(fill='both', expand=True, padx=15, pady=10)
            
            # Selection radio
            var = ctk.StringVar()
            rb = ctk.CTkRadioButton(
                inner,
                text="",
                variable=var,
                value=f['name'],
                fg_color=THEME['accent_primary'],
                command=lambda fn=f['name']: self._select_file(fn)
            )
            rb.pack(side='left')
            
            # File info
            ctk.CTkLabel(
                inner,
                text=f['original_name'][:30],
                font=ctk.CTkFont(family=FONT_MONO, size=11, weight="bold"),
                text_color=THEME['text_primary']
            ).pack(side='left', padx=(10, 20))
            
            # Date
            ctk.CTkLabel(
                inner,
                text=f['date'],
                font=ctk.CTkFont(size=10),
                text_color=THEME['text_muted']
            ).pack(side='left')
            
            # Size
            size_str = f"{f['size']/1024:.1f} KB" if f['size'] < 1024*1024 else f"{f['size']/(1024*1024):.1f} MB"
            ctk.CTkLabel(
                inner,
                text=size_str,
                font=ctk.CTkFont(size=10),
                text_color=THEME['text_secondary']
            ).pack(side='right')
            
            self.file_frames.append(row)
    
    def _select_file(self, filename):
        """Handle file selection."""
        self.selected_file = filename
        self.restore_btn.configure(state="normal")
        self.delete_btn.configure(state="normal")
    
    def _restore_file(self):
        """Restore selected file."""
        if not self.selected_file or not self.quarantine:
            return
        
        try:
            from utils.config import ConfigManager
            config = ConfigManager()
        except:
            config = None
        
        success, msg = self.quarantine.restore_file(self.selected_file, config)
        
        if success:
            messagebox.showinfo("Restored", msg)
            self._refresh()
        else:
            messagebox.showerror("Error", msg)
    
    def _delete_file(self):
        """Permanently delete selected file."""
        if not self.selected_file or not self.quarantine:
            return
        
        if not messagebox.askyesno("⚠ Confirm", f"Permanently delete this file?\n\nThis cannot be undone!"):
            return
        
        try:
            from utils.config import ConfigManager
            config = ConfigManager()
        except:
            config = None
        
        success, msg = self.quarantine.delete_permanently(self.selected_file, config)
        
        if success:
            messagebox.showinfo("Deleted", msg)
            self._refresh()
        else:
            messagebox.showerror("Error", msg)


# ============================================================
# VAULT FRAME
# ============================================================
class VaultFrame(ctk.CTkFrame):
    """File encryption vault."""
    
    def __init__(self, parent):
        super().__init__(parent, fg_color="transparent")
        self._create_widgets()
    
    def _create_widgets(self):
        ctk.CTkLabel(
            self,
            text="File Vault",
            font=ctk.CTkFont(family=FONT_FAMILY, size=28, weight="bold"),
            text_color=THEME['text_primary']
        ).pack(anchor="w", pady=(0, 20))
        
        if not CRYPTO_AVAILABLE:
            ctk.CTkLabel(
                self,
                text="⚠ cryptography library not installed",
                text_color=THEME['accent_warning']
            ).pack(pady=20)
            return
        
        # Encrypt card
        enc_card = ctk.CTkFrame(self, fg_color=THEME['bg_card'], corner_radius=15)
        enc_card.pack(fill='x', pady=(0, 15))
        
        enc_inner = ctk.CTkFrame(enc_card, fg_color="transparent")
        enc_inner.pack(padx=25, pady=25, fill='x')
        
        ctk.CTkLabel(
            enc_inner,
            text="🔒 Encrypt File",
            font=ctk.CTkFont(family=FONT_FAMILY, size=16, weight="bold"),
            text_color=THEME['text_primary']
        ).pack(anchor="w")
        
        ctk.CTkLabel(
            enc_inner,
            text="Select a file to encrypt with AES-256",
            font=ctk.CTkFont(size=11),
            text_color=THEME['text_secondary']
        ).pack(anchor="w", pady=(5, 15))
        
        pass_frame = ctk.CTkFrame(enc_inner, fg_color="transparent")
        pass_frame.pack(fill='x', pady=(0, 10))
        
        self.enc_password = ctk.CTkEntry(
            pass_frame,
            placeholder_text="Password",
            font=ctk.CTkFont(size=12),
            show="•",
            height=40,
            corner_radius=10,
            fg_color=THEME['bg_input']
        )
        self.enc_password.pack(side='left', fill='x', expand=True, padx=(0, 10))
        
        ctk.CTkButton(
            pass_frame,
            text="Lock File",
            font=ctk.CTkFont(size=12, weight="bold"),
            height=40,
            corner_radius=10,
            fg_color=THEME['accent_primary'],
            command=self._encrypt
        ).pack(side='right')
        
        # Decrypt card
        dec_card = ctk.CTkFrame(self, fg_color=THEME['bg_card'], corner_radius=15)
        dec_card.pack(fill='x')
        
        dec_inner = ctk.CTkFrame(dec_card, fg_color="transparent")
        dec_inner.pack(padx=25, pady=25, fill='x')
        
        ctk.CTkLabel(
            dec_inner,
            text="🔓 Decrypt File",
            font=ctk.CTkFont(family=FONT_FAMILY, size=16, weight="bold"),
            text_color=THEME['text_primary']
        ).pack(anchor="w")
        
        ctk.CTkLabel(
            dec_inner,
            text="Select a .rafenc file to decrypt",
            font=ctk.CTkFont(size=11),
            text_color=THEME['text_secondary']
        ).pack(anchor="w", pady=(5, 15))
        
        pass_frame2 = ctk.CTkFrame(dec_inner, fg_color="transparent")
        pass_frame2.pack(fill='x')
        
        self.dec_password = ctk.CTkEntry(
            pass_frame2,
            placeholder_text="Password",
            font=ctk.CTkFont(size=12),
            show="•",
            height=40,
            corner_radius=10,
            fg_color=THEME['bg_input']
        )
        self.dec_password.pack(side='left', fill='x', expand=True, padx=(0, 10))
        
        ctk.CTkButton(
            pass_frame2,
            text="Unlock File",
            font=ctk.CTkFont(size=12, weight="bold"),
            height=40,
            corner_radius=10,
            fg_color=THEME['accent_success'],
            command=self._decrypt
        ).pack(side='right')
    
    def _encrypt(self):
        password = self.enc_password.get()
        if not password:
            messagebox.showerror("Error", "Enter a password")
            return
        
        path = filedialog.askopenfilename(title="Select file to encrypt")
        if not path:
            return
        
        success, msg = FileVault.encrypt_file(path, password)
        if success:
            VoiceAlert.speak("File encrypted.")
            messagebox.showinfo("Success", f"File encrypted:\n{msg}")
            self.enc_password.delete(0, 'end')
        else:
            messagebox.showerror("Error", msg)
    
    def _decrypt(self):
        password = self.dec_password.get()
        if not password:
            messagebox.showerror("Error", "Enter a password")
            return
        
        path = filedialog.askopenfilename(
            title="Select encrypted file",
            filetypes=[("RafSec Encrypted", "*.rafenc")]
        )
        if not path:
            return
        
        success, msg = FileVault.decrypt_file(path, password)
        if success:
            VoiceAlert.speak("File decrypted successfully.")
            messagebox.showinfo("Success", f"File decrypted:\n{msg}")
            self.dec_password.delete(0, 'end')
        else:
            messagebox.showerror("Error", msg)


# ============================================================
# TOOLS FRAME
# ============================================================
class ToolsFrame(ctk.CTkFrame):
    """Utility tools: cleaner, shredder."""
    
    def __init__(self, parent):
        super().__init__(parent, fg_color="transparent")
        self._create_widgets()
    
    def _create_widgets(self):
        ctk.CTkLabel(
            self,
            text="Tools",
            font=ctk.CTkFont(family=FONT_FAMILY, size=28, weight="bold"),
            text_color=THEME['text_primary']
        ).pack(anchor="w", pady=(0, 20))
        
        # System Cleaner
        cleaner_card = ctk.CTkFrame(self, fg_color=THEME['bg_card'], corner_radius=15)
        cleaner_card.pack(fill='x', pady=(0, 15))
        
        cleaner_inner = ctk.CTkFrame(cleaner_card, fg_color="transparent")
        cleaner_inner.pack(padx=25, pady=25, fill='x')
        
        ctk.CTkLabel(
            cleaner_inner,
            text="🧹 System Cleaner",
            font=ctk.CTkFont(family=FONT_FAMILY, size=16, weight="bold"),
            text_color=THEME['text_primary']
        ).pack(anchor="w")
        
        self.junk_label = ctk.CTkLabel(
            cleaner_inner,
            text="Click scan to find junk files",
            font=ctk.CTkFont(size=11),
            text_color=THEME['text_secondary']
        )
        self.junk_label.pack(anchor="w", pady=(5, 15))
        
        btn_frame = ctk.CTkFrame(cleaner_inner, fg_color="transparent")
        btn_frame.pack(fill='x')
        
        ctk.CTkButton(
            btn_frame,
            text="Scan Junk",
            font=ctk.CTkFont(size=12),
            height=40,
            corner_radius=10,
            fg_color=THEME['bg_elevated'],
            command=self._scan_junk
        ).pack(side='left', padx=(0, 10))
        
        self.clean_btn = ctk.CTkButton(
            btn_frame,
            text="Clean Now",
            font=ctk.CTkFont(size=12, weight="bold"),
            height=40,
            corner_radius=10,
            fg_color=THEME['accent_success'],
            state="disabled",
            command=self._clean_junk
        )
        self.clean_btn.pack(side='left')
        
        # File Shredder
        shred_card = ctk.CTkFrame(self, fg_color=THEME['bg_card'], corner_radius=15)
        shred_card.pack(fill='x')
        
        shred_inner = ctk.CTkFrame(shred_card, fg_color="transparent")
        shred_inner.pack(padx=25, pady=25, fill='x')
        
        ctk.CTkLabel(
            shred_inner,
            text="🗑️ File Shredder",
            font=ctk.CTkFont(family=FONT_FAMILY, size=16, weight="bold"),
            text_color=THEME['text_primary']
        ).pack(anchor="w")
        
        ctk.CTkLabel(
            shred_inner,
            text="⚠ Securely delete files beyond recovery",
            font=ctk.CTkFont(size=11),
            text_color=THEME['accent_warning']
        ).pack(anchor="w", pady=(5, 15))
        
        ctk.CTkButton(
            shred_inner,
            text="Select File to Shred",
            font=ctk.CTkFont(size=12, weight="bold"),
            height=40,
            corner_radius=10,
            fg_color=THEME['accent_danger'],
            command=self._shred_file
        ).pack(anchor="w")
    
    def _scan_junk(self):
        result = SystemCleaner.scan_junk()
        self.junk_label.configure(text=f"Found: {result.size_formatted} of junk files")
        self.clean_btn.configure(state="normal")
    
    def _clean_junk(self):
        if not messagebox.askyesno("Confirm", "Clean all junk files?"):
            return
        
        success, msg, bytes_freed = SystemCleaner.clean_junk()
        self.junk_label.configure(text=msg)
        self.clean_btn.configure(state="disabled")
        VoiceAlert.speak(f"Cleanup complete.")
    
    def _shred_file(self):
        path = filedialog.askopenfilename(title="Select file to shred")
        if not path:
            return
        
        if not messagebox.askyesno("⚠ WARNING", f"Permanently destroy:\n{path}\n\nThis cannot be undone!"):
            return
        
        success, msg = FileShredder.secure_delete(path)
        if success:
            messagebox.showinfo("Success", msg)
        else:
            messagebox.showerror("Error", msg)


# ============================================================
# SETTINGS FRAME
# ============================================================
class SettingsFrame(ctk.CTkFrame):
    """Configuration settings."""
    
    def __init__(self, parent):
        super().__init__(parent, fg_color="transparent")
        self.parent = parent
        self._create_widgets()
    
    def _create_widgets(self):
        ctk.CTkLabel(
            self,
            text="Settings",
            font=ctk.CTkFont(family=FONT_FAMILY, size=28, weight="bold"),
            text_color=THEME['text_primary']
        ).pack(anchor="w", pady=(0, 20))
        
        # General settings
        gen_card = ctk.CTkFrame(self, fg_color=THEME['bg_card'], corner_radius=15)
        gen_card.pack(fill='x', pady=(0, 15))
        
        gen_inner = ctk.CTkFrame(gen_card, fg_color="transparent")
        gen_inner.pack(padx=25, pady=20, fill='x')
        
        # Voice toggle
        row1 = ctk.CTkFrame(gen_inner, fg_color="transparent")
        row1.pack(fill='x', pady=8)
        
        ctk.CTkLabel(row1, text="Voice Alerts", font=ctk.CTkFont(size=13)).pack(side='left')
        self.voice_switch = ctk.CTkSwitch(row1, text="", command=self._toggle_voice)
        self.voice_switch.pack(side='right')
        if VoiceAlert.is_available():
            self.voice_switch.select()
        
        # Tray toggle
        row2 = ctk.CTkFrame(gen_inner, fg_color="transparent")
        row2.pack(fill='x', pady=8)
        
        ctk.CTkLabel(row2, text="Minimize to Tray", font=ctk.CTkFont(size=13)).pack(side='left')
        self.tray_switch = ctk.CTkSwitch(row2, text="", command=self._toggle_tray)
        self.tray_switch.pack(side='right')
        
        # VirusTotal API
        vt_card = ctk.CTkFrame(self, fg_color=THEME['bg_card'], corner_radius=15)
        vt_card.pack(fill='x', pady=(0, 15))
        
        vt_inner = ctk.CTkFrame(vt_card, fg_color="transparent")
        vt_inner.pack(padx=25, pady=20, fill='x')
        
        ctk.CTkLabel(
            vt_inner,
            text="VirusTotal API Key",
            font=ctk.CTkFont(size=13, weight="bold")
        ).pack(anchor="w")
        
        api_row = ctk.CTkFrame(vt_inner, fg_color="transparent")
        api_row.pack(fill='x', pady=(10, 0))
        
        self.api_entry = ctk.CTkEntry(
            api_row,
            placeholder_text="Enter your API key",
            font=ctk.CTkFont(size=12),
            height=40,
            corner_radius=10,
            fg_color=THEME['bg_input']
        )
        self.api_entry.pack(side='left', fill='x', expand=True, padx=(0, 10))
        
        ctk.CTkButton(
            api_row,
            text="Save",
            font=ctk.CTkFont(size=12),
            width=80,
            height=40,
            corner_radius=10,
            fg_color=THEME['accent_primary'],
            command=self._save_api
        ).pack(side='right')
        
        # Whitelist
        wl_card = ctk.CTkFrame(self, fg_color=THEME['bg_card'], corner_radius=15)
        wl_card.pack(fill='x', pady=(0, 15))
        
        wl_inner = ctk.CTkFrame(wl_card, fg_color="transparent")
        wl_inner.pack(padx=25, pady=20, fill='x')
        
        ctk.CTkLabel(
            wl_inner,
            text="Whitelist (Exclusions)",
            font=ctk.CTkFont(size=13, weight="bold")
        ).pack(anchor="w")
        
        wl_btn_row = ctk.CTkFrame(wl_inner, fg_color="transparent")
        wl_btn_row.pack(fill='x', pady=(10, 0))
        
        ctk.CTkButton(
            wl_btn_row,
            text="Add File",
            font=ctk.CTkFont(size=11),
            height=35,
            corner_radius=8,
            fg_color=THEME['bg_elevated'],
            command=self._add_whitelist
        ).pack(side='left', padx=(0, 10))
        
        self.wl_count = ctk.CTkLabel(
            wl_btn_row,
            text=f"{self.parent.whitelist.count()} items",
            font=ctk.CTkFont(size=11),
            text_color=THEME['text_muted']
        )
        self.wl_count.pack(side='left')
        
        # About / Updates
        about_card = ctk.CTkFrame(self, fg_color=THEME['bg_card'], corner_radius=15)
        about_card.pack(fill='x')
        
        about_inner = ctk.CTkFrame(about_card, fg_color="transparent")
        about_inner.pack(padx=25, pady=20, fill='x')
        
        ctk.CTkLabel(
            about_inner,
            text=f"RafSec Security Suite v{RafSecApp.VERSION}",
            font=ctk.CTkFont(size=13, weight="bold")
        ).pack(anchor="w")
        
        ctk.CTkButton(
            about_inner,
            text="Check for Updates",
            font=ctk.CTkFont(size=11),
            height=35,
            corner_radius=8,
            fg_color=THEME['bg_elevated'],
            command=lambda: webbrowser.open("https://github.com/yourusername/RafSec/releases")
        ).pack(anchor="w", pady=(10, 0))
    
    def _toggle_voice(self):
        VoiceAlert.set_enabled(self.voice_switch.get())
    
    def _toggle_tray(self):
        self.parent.minimize_to_tray = self.tray_switch.get()
    
    def _save_api(self):
        key = self.api_entry.get().strip()
        if key:
            if CLOUD_AVAILABLE:
                CloudScanner.save_api_key(key)
                messagebox.showinfo("Success", "API key saved")
            else:
                messagebox.showerror("Error", "Cloud module not available")
    
    def _add_whitelist(self):
        path = filedialog.askopenfilename(title="Select file to whitelist")
        if path:
            self.parent.whitelist.add(path)
            self.wl_count.configure(text=f"{self.parent.whitelist.count()} items")
            messagebox.showinfo("Whitelist", f"Added: {os.path.basename(path)}")


# ============================================================
# ENTRY POINT
# ============================================================
def main():
    """Main entry point with optional splash screen."""
    # Try to show splash
    try:
        from gui_splash import SplashScreen
        
        # Create root for splash
        root = ctk.CTk()
        root.withdraw()
        
        splash = SplashScreen(root, duration=3.0)
        splash.wait()
        
        root.destroy()
    except:
        pass
    
    # Launch main app
    app = RafSecApp()
    app.mainloop()


if __name__ == "__main__":
    main()
