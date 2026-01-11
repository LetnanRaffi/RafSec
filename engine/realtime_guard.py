"""
RafSec Engine - Real-Time Guard (On-Access Scanner)
=====================================================
Active file protection with instant threat response.

Author: RafSec Team
"""

import os
import time
import hashlib
import threading
from typing import Callable, Optional, List, Set
from datetime import datetime

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileSystemEvent
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False

try:
    from plyer import notification
    NOTIFICATION_AVAILABLE = True
except ImportError:
    NOTIFICATION_AVAILABLE = False


class MalwareHandler(FileSystemEventHandler):
    """
    Real-time malware detection handler.
    
    Scans files immediately when created or modified
    in monitored directories.
    """
    
    # Skip these extensions
    SKIP_EXTENSIONS = {
        '.tmp', '.log', '.lock', '.swp', '.crdownload',
        '.part', '.partial', '.downloading'
    }
    
    # Skip these paths
    SKIP_PATHS = {'quarantine', '.git', '__pycache__', 'node_modules'}
    
    def __init__(self, scan_callback: Callable, 
                 threat_callback: Callable = None,
                 whitelist: Set[str] = None):
        """
        Initialize malware handler.
        
        Args:
            scan_callback: Function(path) -> (is_threat, score, threat_name)
            threat_callback: Function(path, score, threat_name) called on detection
            whitelist: Set of paths to skip
        """
        super().__init__()
        self.scan_callback = scan_callback
        self.threat_callback = threat_callback
        self.whitelist = whitelist or set()
        
        # Track recently scanned files to avoid duplicates
        self.recent_scans = {}  # path -> timestamp
        self.scan_cooldown = 5  # seconds
        self._lock = threading.Lock()
    
    def _should_skip(self, path: str) -> bool:
        """Check if file should be skipped."""
        # Skip directories
        if os.path.isdir(path):
            return True
        
        # Skip by extension
        _, ext = os.path.splitext(path)
        if ext.lower() in self.SKIP_EXTENSIONS:
            return True
        
        # Skip by path component
        path_lower = path.lower()
        for skip in self.SKIP_PATHS:
            if skip in path_lower:
                return True
        
        # Skip whitelisted
        if path in self.whitelist:
            return True
        
        # Skip if recently scanned
        current_time = time.time()
        with self._lock:
            if path in self.recent_scans:
                if current_time - self.recent_scans[path] < self.scan_cooldown:
                    return True
            self.recent_scans[path] = current_time
        
        return False
    
    def _scan_file(self, path: str):
        """Scan a file for threats."""
        if not os.path.exists(path):
            return
        
        try:
            # Wait a moment for file to be fully written
            time.sleep(0.5)
            
            if not os.path.exists(path):
                return
            
            # Call scan function
            is_threat, score, threat_name = self.scan_callback(path)
            
            if is_threat and self.threat_callback:
                self.threat_callback(path, score, threat_name)
                
        except Exception as e:
            print(f"[RealTime] Scan error: {e}")
    
    def on_created(self, event: FileSystemEvent):
        """Handle file creation."""
        if event.is_directory:
            return
        
        if not self._should_skip(event.src_path):
            # Run scan in thread to not block
            threading.Thread(
                target=self._scan_file,
                args=(event.src_path,),
                daemon=True
            ).start()
    
    def on_modified(self, event: FileSystemEvent):
        """Handle file modification."""
        if event.is_directory:
            return
        
        if not self._should_skip(event.src_path):
            threading.Thread(
                target=self._scan_file,
                args=(event.src_path,),
                daemon=True
            ).start()


class RealTimeGuard:
    """
    Real-time file protection engine.
    
    Monitors critical directories and instantly scans
    new or modified files for threats.
    """
    
    def __init__(self, scan_function: Callable = None,
                 threat_callback: Callable = None,
                 quarantine_callback: Callable = None):
        """
        Initialize real-time guard.
        
        Args:
            scan_function: (path) -> (is_threat, score, threat_name)
            threat_callback: Called when threat detected
            quarantine_callback: (path) -> bool, quarantines a file
        """
        self.scan_function = scan_function or self._default_scan
        self.threat_callback = threat_callback
        self.quarantine_callback = quarantine_callback
        
        self.observer = None
        self.handler = None
        self.is_running = False
        self.monitored_paths = []
        self.whitelist = set()
        
        # Statistics
        self.files_scanned = 0
        self.threats_blocked = 0
    
    def _default_scan(self, path: str) -> tuple:
        """Default scan function using engine."""
        try:
            from engine.analyzer import MalwareAnalyzer
            from engine.extractor import PEExtractor
            from utils.helpers import FileValidator
            
            # Validate
            valid, _ = FileValidator.validate_for_analysis(path)
            if not valid:
                return (False, 0, None)
            
            # Extract & analyze
            extractor = PEExtractor(path)
            features = extractor.extract_all()
            
            analyzer = MalwareAnalyzer(features)
            result = analyzer.analyze(path)
            
            extractor.close()
            
            # Determine threat
            is_threat = result.suspicion_score >= 70
            return (is_threat, result.suspicion_score, result.threat_level.value)
            
        except Exception:
            return (False, 0, None)
    
    def _on_threat(self, path: str, score: float, threat_name: str):
        """Handle detected threat."""
        self.threats_blocked += 1
        
        # Show notification
        self._show_notification(
            "⚠️ Threat Blocked!",
            f"Malware detected: {os.path.basename(path)}\nScore: {score:.1f}"
        )
        
        # Quarantine if callback provided
        if self.quarantine_callback:
            try:
                self.quarantine_callback(path)
            except:
                pass
        
        # Call user callback
        if self.threat_callback:
            self.threat_callback(path, score, threat_name)
    
    def _show_notification(self, title: str, message: str):
        """Show desktop notification."""
        if NOTIFICATION_AVAILABLE:
            try:
                notification.notify(
                    title=title,
                    message=message,
                    app_name="RafSec",
                    timeout=10
                )
            except:
                pass
    
    def get_default_paths(self) -> List[str]:
        """Get default paths to monitor."""
        home = os.path.expanduser("~")
        
        paths = []
        
        # Common user folders
        for folder in ['Downloads', 'Desktop', 'Documents']:
            path = os.path.join(home, folder)
            if os.path.isdir(path):
                paths.append(path)
        
        # Temp folder
        temp = os.environ.get('TEMP') or os.environ.get('TMP') or '/tmp'
        if os.path.isdir(temp):
            paths.append(temp)
        
        return paths
    
    def add_path(self, path: str) -> bool:
        """Add a path to monitor."""
        if os.path.isdir(path) and path not in self.monitored_paths:
            self.monitored_paths.append(path)
            return True
        return False
    
    def add_to_whitelist(self, path: str):
        """Add path to whitelist."""
        self.whitelist.add(path)
    
    def start(self, paths: List[str] = None) -> bool:
        """
        Start real-time protection.
        
        Args:
            paths: Paths to monitor (default: Downloads, Desktop, etc.)
            
        Returns:
            True if started successfully
        """
        if not WATCHDOG_AVAILABLE:
            return False
        
        if self.is_running:
            return True
        
        # Use default paths if not specified
        if paths is None:
            paths = self.get_default_paths()
        
        self.monitored_paths = [p for p in paths if os.path.isdir(p)]
        
        if not self.monitored_paths:
            return False
        
        # Create handler
        self.handler = MalwareHandler(
            scan_callback=self._do_scan,
            threat_callback=self._on_threat,
            whitelist=self.whitelist
        )
        
        # Create observer
        self.observer = Observer()
        
        for path in self.monitored_paths:
            try:
                self.observer.schedule(self.handler, path, recursive=True)
            except Exception as e:
                print(f"[RealTime] Cannot monitor {path}: {e}")
        
        try:
            self.observer.start()
            self.is_running = True
            return True
        except Exception as e:
            print(f"[RealTime] Start failed: {e}")
            return False
    
    def _do_scan(self, path: str) -> tuple:
        """Perform scan and track statistics."""
        self.files_scanned += 1
        return self.scan_function(path)
    
    def stop(self):
        """Stop real-time protection."""
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=5)
            self.observer = None
        
        self.is_running = False
    
    def get_status(self) -> dict:
        """Get protection status."""
        return {
            'running': self.is_running,
            'monitored_paths': self.monitored_paths,
            'files_scanned': self.files_scanned,
            'threats_blocked': self.threats_blocked
        }
    
    @staticmethod
    def is_available() -> bool:
        """Check if real-time protection is available."""
        return WATCHDOG_AVAILABLE
