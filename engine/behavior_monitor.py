"""
RafSec Engine - Behavioral Analysis Monitor
=============================================
Real-time detection of malicious BEHAVIORS.

Author: RafSec Team
"""

import os
import time
import platform
import threading
from typing import Callable, Optional, List
from collections import defaultdict
from datetime import datetime

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


class RansomwareBehaviorHandler(FileSystemEventHandler):
    """Detect rapid file encryption behavior."""
    
    def __init__(self, threshold: int = 5, window_seconds: float = 2.0, 
                 alert_callback: Callable = None):
        super().__init__()
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.alert_callback = alert_callback
        
        # Track file modifications by process
        self.process_activity = defaultdict(list)
        self.blocked_pids = set()
        self._lock = threading.Lock()
    
    def _get_modifying_process(self, path: str) -> Optional[int]:
        """Try to identify which process is modifying a file."""
        if not PSUTIL_AVAILABLE:
            return None
        
        try:
            for proc in psutil.process_iter(['pid', 'open_files']):
                try:
                    open_files = proc.info.get('open_files') or []
                    for f in open_files:
                        if f.path == path:
                            return proc.pid
                except:
                    continue
        except:
            pass
        
        return None
    
    def on_modified(self, event):
        if event.is_directory:
            return
        
        self._record_activity(event.src_path, "modified")
    
    def on_created(self, event):
        if event.is_directory:
            return
        
        self._record_activity(event.src_path, "created")
    
    def _record_activity(self, path: str, action: str):
        """Record file activity and check for ransomware behavior."""
        current_time = time.time()
        pid = self._get_modifying_process(path) or 0
        
        with self._lock:
            # Add activity
            self.process_activity[pid].append(current_time)
            
            # Clean old entries
            cutoff = current_time - self.window_seconds
            self.process_activity[pid] = [
                t for t in self.process_activity[pid] if t > cutoff
            ]
            
            # Check threshold
            if len(self.process_activity[pid]) >= self.threshold:
                if pid not in self.blocked_pids and pid > 0:
                    self._trigger_alert(pid, len(self.process_activity[pid]))
    
    def _trigger_alert(self, pid: int, count: int):
        """Handle ransomware detection."""
        self.blocked_pids.add(pid)
        
        # Try to get process info
        proc_name = "Unknown"
        if PSUTIL_AVAILABLE:
            try:
                proc = psutil.Process(pid)
                proc_name = proc.name()
            except:
                pass
        
        # Kill the process
        kill_success = False
        if PSUTIL_AVAILABLE and pid > 0:
            try:
                proc = psutil.Process(pid)
                proc.terminate()
                kill_success = True
            except:
                pass
        
        # Alert
        if self.alert_callback:
            self.alert_callback(
                "RANSOMWARE",
                pid,
                proc_name,
                f"Rapid encryption behavior detected! {count} files in {self.window_seconds}s",
                kill_success
            )


class ProcessInjectionMonitor:
    """Detect suspicious process spawning patterns."""
    
    # Suspicious parent-child relationships
    SUSPICIOUS_CHAINS = [
        # Parent process -> suspicious children
        ("WINWORD.EXE", ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"]),
        ("EXCEL.EXE", ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"]),
        ("OUTLOOK.EXE", ["cmd.exe", "powershell.exe"]),
        ("POWERPNT.EXE", ["cmd.exe", "powershell.exe"]),
        ("ACROBAT.EXE", ["cmd.exe", "powershell.exe"]),
        ("ACRORD32.EXE", ["cmd.exe", "powershell.exe"]),
        ("MSHTA.EXE", ["powershell.exe", "cmd.exe"]),
        ("WSCRIPT.EXE", ["powershell.exe", "cmd.exe"]),
    ]
    
    def __init__(self, alert_callback: Callable = None):
        self.alert_callback = alert_callback
        self.known_processes = {}
        self._running = False
        self._thread = None
    
    def start(self):
        """Start monitoring."""
        if not PSUTIL_AVAILABLE:
            return False
        
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        return True
    
    def stop(self):
        """Stop monitoring."""
        self._running = False
    
    def _monitor_loop(self):
        """Main monitoring loop."""
        while self._running:
            try:
                self._scan_processes()
            except:
                pass
            time.sleep(2)  # Check every 2 seconds
    
    def _scan_processes(self):
        """Scan for suspicious process relationships."""
        current_pids = set()
        
        for proc in psutil.process_iter(['pid', 'name', 'ppid']):
            try:
                pid = proc.info['pid']
                name = (proc.info['name'] or "").upper()
                ppid = proc.info['ppid']
                
                current_pids.add(pid)
                
                # Skip if already known
                if pid in self.known_processes:
                    continue
                
                self.known_processes[pid] = name
                
                # Check parent
                if ppid and ppid > 0:
                    try:
                        parent = psutil.Process(ppid)
                        parent_name = parent.name().upper()
                        
                        # Check suspicious chains
                        for suspicious_parent, suspicious_children in self.SUSPICIOUS_CHAINS:
                            if suspicious_parent in parent_name:
                                for child in suspicious_children:
                                    if child.upper() in name:
                                        self._trigger_alert(pid, name, ppid, parent_name)
                                        break
                    except:
                        pass
                        
            except:
                continue
        
        # Clean up dead processes
        dead = set(self.known_processes.keys()) - current_pids
        for pid in dead:
            del self.known_processes[pid]
    
    def _trigger_alert(self, pid: int, name: str, ppid: int, parent_name: str):
        """Handle suspicious process detection."""
        if self.alert_callback:
            self.alert_callback(
                "PROCESS_INJECTION",
                pid,
                name,
                f"Suspicious spawn: {parent_name} → {name} (Possible Macro Attack)",
                False
            )


class BehaviorMonitor:
    """
    Main behavioral analysis engine.
    
    Combines multiple behavior detectors for real-time threat detection.
    """
    
    def __init__(self, alert_callback: Callable = None):
        """
        Initialize behavior monitor.
        
        Args:
            alert_callback: Function(threat_type, pid, proc_name, message, killed)
        """
        self.alert_callback = alert_callback
        self.ransomware_handler = None
        self.injection_monitor = None
        self.observer = None
        self.is_running = False
    
    def start(self) -> bool:
        """Start all behavioral monitors."""
        if not WATCHDOG_AVAILABLE or not PSUTIL_AVAILABLE:
            return False
        
        # Start ransomware detector
        docs_path = os.path.expanduser("~/Documents")
        if os.path.isdir(docs_path):
            self.ransomware_handler = RansomwareBehaviorHandler(
                threshold=5,
                window_seconds=2.0,
                alert_callback=self.alert_callback
            )
            
            self.observer = Observer()
            self.observer.schedule(self.ransomware_handler, docs_path, recursive=True)
            self.observer.start()
        
        # Start injection monitor
        self.injection_monitor = ProcessInjectionMonitor(alert_callback=self.alert_callback)
        self.injection_monitor.start()
        
        self.is_running = True
        return True
    
    def stop(self):
        """Stop all monitors."""
        if self.observer:
            self.observer.stop()
            self.observer.join()
        
        if self.injection_monitor:
            self.injection_monitor.stop()
        
        self.is_running = False
    
    def get_status(self) -> dict:
        """Get monitor status."""
        return {
            'running': self.is_running,
            'ransomware_detector': self.observer is not None,
            'injection_monitor': self.injection_monitor is not None
        }
