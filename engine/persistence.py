"""
RafSec Engine - Persistence Monitor
=====================================
Monitor startup entries for malware persistence.

Author: RafSec Team
"""

import os
import platform
import threading
import time
from typing import Dict, List, Set, Callable, Optional

# Windows Registry
if platform.system() == "Windows":
    try:
        import winreg
        WINREG_AVAILABLE = True
    except ImportError:
        WINREG_AVAILABLE = False
else:
    WINREG_AVAILABLE = False


class PersistenceMonitor:
    """
    Monitor system startup entries for unauthorized changes.
    
    Detects when malware adds itself to autostart locations
    (Registry Run keys, Startup folder).
    """
    
    # Windows Registry keys for startup
    REG_KEYS = [
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ] if WINREG_AVAILABLE else []
    
    def __init__(self, alert_callback: Callable = None,
                 config_manager = None):
        """
        Initialize persistence monitor.
        
        Args:
            alert_callback: Function(entry_name, entry_value) for alerts
            config_manager: ConfigManager for saving known entries
        """
        self.alert_callback = alert_callback
        self.config_manager = config_manager
        
        self.known_entries = {}  # name -> value
        self.is_running = False
        self._thread = None
        self._stop_event = threading.Event()
    
    def _get_startup_folder(self) -> str:
        """Get startup folder path."""
        if platform.system() == "Windows":
            return os.path.join(
                os.environ.get('APPDATA', ''),
                r"Microsoft\Windows\Start Menu\Programs\Startup"
            )
        elif platform.system() == "Linux":
            return os.path.expanduser("~/.config/autostart")
        else:
            return ""
    
    def get_registry_entries(self) -> Dict[str, str]:
        """Get all registry startup entries."""
        entries = {}
        
        if not WINREG_AVAILABLE:
            return entries
        
        for hive, key_path in self.REG_KEYS:
            try:
                key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
                
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        entries[f"[REG] {name}"] = str(value)
                        i += 1
                    except OSError:
                        break
                
                winreg.CloseKey(key)
            except (FileNotFoundError, PermissionError):
                continue
        
        return entries
    
    def get_startup_folder_entries(self) -> Dict[str, str]:
        """Get startup folder entries."""
        entries = {}
        startup_path = self._get_startup_folder()
        
        if startup_path and os.path.isdir(startup_path):
            for filename in os.listdir(startup_path):
                filepath = os.path.join(startup_path, filename)
                if os.path.isfile(filepath):
                    entries[f"[FOLDER] {filename}"] = filepath
        
        return entries
    
    def get_linux_autostart(self) -> Dict[str, str]:
        """Get Linux autostart entries."""
        entries = {}
        
        autostart_dir = os.path.expanduser("~/.config/autostart")
        
        if os.path.isdir(autostart_dir):
            for filename in os.listdir(autostart_dir):
                if filename.endswith('.desktop'):
                    entries[f"[AUTOSTART] {filename}"] = os.path.join(autostart_dir, filename)
        
        return entries
    
    def check_startup_entries(self) -> Dict[str, str]:
        """
        Get all startup entries.
        
        Returns:
            Dict of name -> value for all startup items
        """
        entries = {}
        
        if platform.system() == "Windows":
            entries.update(self.get_registry_entries())
            entries.update(self.get_startup_folder_entries())
        elif platform.system() == "Linux":
            entries.update(self.get_linux_autostart())
        
        return entries
    
    def load_known_entries(self):
        """Load known entries from config."""
        if self.config_manager:
            try:
                self.known_entries = self.config_manager.get_config('startup_entries', {})
            except:
                self.known_entries = {}
        
        if not self.known_entries:
            # Initialize with current entries
            self.known_entries = self.check_startup_entries()
            self._save_known()
    
    def _save_known(self):
        """Save known entries to config."""
        if self.config_manager:
            try:
                self.config_manager.save_config('startup_entries', self.known_entries)
            except:
                pass
    
    def find_new_entries(self) -> List[tuple]:
        """
        Find new startup entries.
        
        Returns:
            List of (name, value) for new entries
        """
        current = self.check_startup_entries()
        new_entries = []
        
        for name, value in current.items():
            if name not in self.known_entries:
                new_entries.append((name, value))
        
        return new_entries
    
    def start_monitoring(self, interval: int = 60) -> bool:
        """
        Start monitoring for new startup entries.
        
        Args:
            interval: Check interval in seconds
            
        Returns:
            True if started
        """
        if self.is_running:
            return True
        
        self.load_known_entries()
        
        self._stop_event.clear()
        self.is_running = True
        
        self._thread = threading.Thread(
            target=self._monitor_loop,
            args=(interval,),
            daemon=True
        )
        self._thread.start()
        
        return True
    
    def stop_monitoring(self):
        """Stop monitoring."""
        self._stop_event.set()
        self.is_running = False
    
    def _monitor_loop(self, interval: int):
        """Main monitoring loop."""
        while not self._stop_event.is_set():
            try:
                new_entries = self.find_new_entries()
                
                for name, value in new_entries:
                    # Alert
                    if self.alert_callback:
                        self.alert_callback(name, value)
                    
                    # Add to known
                    self.known_entries[name] = value
                
                if new_entries:
                    self._save_known()
                    
            except Exception as e:
                print(f"[Persistence] Monitor error: {e}")
            
            self._stop_event.wait(interval)
    
    def whitelist_entry(self, name: str, value: str):
        """Add entry to known (whitelist)."""
        self.known_entries[name] = value
        self._save_known()
    
    def get_status(self) -> dict:
        """Get monitor status."""
        return {
            'running': self.is_running,
            'known_entries': len(self.known_entries),
            'platform': platform.system()
        }
    
    def scan_now(self) -> Dict:
        """
        Perform immediate scan.
        
        Returns:
            Dict with scan results
        """
        current = self.check_startup_entries()
        new_entries = self.find_new_entries()
        
        return {
            'total_entries': len(current),
            'new_entries': new_entries,
            'all_entries': current
        }
