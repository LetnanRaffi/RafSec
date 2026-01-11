"""
RafSec Engine - Ransomware Honeypot
====================================
Creates decoy files to detect ransomware activity.

Author: RafSec Team
"""

import os
import platform
import threading
from typing import Callable, Optional
from datetime import datetime

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False


class HoneypotEventHandler(FileSystemEventHandler):
    """Handle honeypot file events."""
    
    def __init__(self, trap_file: str, callback: Callable):
        super().__init__()
        self.trap_file = trap_file
        self.callback = callback
        self.triggered = False
    
    def on_modified(self, event):
        if event.src_path == self.trap_file and not self.triggered:
            self.triggered = True
            self.callback("MODIFIED", event.src_path)
    
    def on_deleted(self, event):
        if event.src_path == self.trap_file and not self.triggered:
            self.triggered = True
            self.callback("DELETED", event.src_path)


class RansomwareHoneypot:
    """
    Ransomware detection using honeypot (canary) files.
    
    Creates decoy files in strategic locations. When ransomware
    encrypts these files, we detect it immediately.
    
    Strategy:
    - Create files with names that sort early (!, 0, A)
    - Place in Documents, Desktop, and other common targets
    - Monitor for any modification or deletion
    """
    
    TRAP_FILENAME = "!_IMPORTANT_DO_NOT_DELETE.docx"
    TRAP_CONTENT = b"""This is a RafSec honeypot file.
If you see this warning, ransomware may have encrypted your files.
Contact your IT administrator immediately.

DO NOT DELETE THIS FILE.
"""
    
    def __init__(self, alert_callback: Callable):
        """
        Initialize honeypot.
        
        Args:
            alert_callback: Function to call when trap is triggered
                           callback(event_type, file_path)
        """
        self.alert_callback = alert_callback
        self.observer: Optional[Observer] = None
        self.trap_files: list = []
        self.is_active = False
    
    def _get_trap_locations(self) -> list:
        """Get strategic locations for honeypot files."""
        home = os.path.expanduser("~")
        locations = []
        
        if platform.system() == "Windows":
            locations = [
                os.path.join(home, "Documents"),
                os.path.join(home, "Desktop"),
                os.path.join(home, "Downloads"),
            ]
        else:  # Linux/Mac
            locations = [
                os.path.join(home, "Documents"),
                os.path.join(home, "Desktop"),
                home,  # Home folder itself
            ]
        
        # Only use existing directories
        return [loc for loc in locations if os.path.isdir(loc)]
    
    def create_traps(self) -> list:
        """
        Create honeypot files in strategic locations.
        
        Returns:
            List of created trap file paths
        """
        locations = self._get_trap_locations()
        created = []
        
        for location in locations:
            trap_path = os.path.join(location, self.TRAP_FILENAME)
            
            try:
                # Create trap file
                with open(trap_path, 'wb') as f:
                    f.write(self.TRAP_CONTENT)
                
                # Make it hidden on Windows
                if platform.system() == "Windows":
                    try:
                        import ctypes
                        ctypes.windll.kernel32.SetFileAttributesW(
                            trap_path, 0x02  # FILE_ATTRIBUTE_HIDDEN
                        )
                    except:
                        pass
                
                created.append(trap_path)
                
            except Exception as e:
                print(f"[WARNING] Failed to create trap at {location}: {e}")
        
        self.trap_files = created
        return created
    
    def start_monitoring(self) -> bool:
        """
        Start monitoring honeypot files.
        
        Returns:
            True if monitoring started successfully
        """
        if not WATCHDOG_AVAILABLE:
            return False
        
        if not self.trap_files:
            self.create_traps()
        
        if not self.trap_files:
            return False
        
        try:
            self.observer = Observer()
            
            for trap_path in self.trap_files:
                trap_dir = os.path.dirname(trap_path)
                handler = HoneypotEventHandler(trap_path, self._on_trap_triggered)
                self.observer.schedule(handler, trap_dir, recursive=False)
            
            self.observer.start()
            self.is_active = True
            return True
            
        except Exception as e:
            print(f"[ERROR] Failed to start honeypot: {e}")
            return False
    
    def stop_monitoring(self):
        """Stop monitoring honeypot files."""
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None
        self.is_active = False
    
    def remove_traps(self):
        """Remove all honeypot files."""
        for trap_path in self.trap_files:
            try:
                if os.path.exists(trap_path):
                    os.remove(trap_path)
            except:
                pass
        self.trap_files = []
    
    def _on_trap_triggered(self, event_type: str, file_path: str):
        """Handle honeypot trigger event."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Try to identify responsible process (basic attempt)
        pid = None
        process_name = None
        
        # Call the alert callback
        self.alert_callback(event_type, file_path)
        
        # Log to file
        log_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            'ransomware_alert.log'
        )
        
        try:
            with open(log_path, 'a') as f:
                f.write(f"[{timestamp}] RANSOMWARE ALERT: {event_type} on {file_path}\n")
        except:
            pass
    
    def check_trap_integrity(self) -> list:
        """
        Check if honeypot files have been tampered with.
        
        Returns:
            List of compromised trap files
        """
        compromised = []
        
        for trap_path in self.trap_files:
            if not os.path.exists(trap_path):
                compromised.append(trap_path)
                continue
            
            try:
                with open(trap_path, 'rb') as f:
                    content = f.read()
                
                if content != self.TRAP_CONTENT:
                    compromised.append(trap_path)
            except:
                compromised.append(trap_path)
        
        return compromised
