"""
RafSec Engine - EDR Core (LOLBins & Process Monitor)
=====================================================
Detect Living Off The Land attacks via command line analysis.

Author: RafSec Team
Requires: WMI, pywin32 (Windows only), psutil
"""

import platform
import threading
import time
from typing import Callable, Optional, List, Dict
from dataclasses import dataclass
from datetime import datetime

# Windows-only imports
if platform.system() == "Windows":
    try:
        import wmi
        WMI_AVAILABLE = True
    except ImportError:
        WMI_AVAILABLE = False
else:
    WMI_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


@dataclass
class ProcessEvent:
    """Process creation event."""
    pid: int
    name: str
    command_line: str
    parent_pid: int
    parent_name: str
    timestamp: datetime


@dataclass
class ThreatEvent:
    """Detected threat event."""
    event_type: str  # "LOLBIN", "MACRO_ATTACK", "SUSPICIOUS_SPAWN"
    process_event: ProcessEvent
    severity: str  # "CRITICAL", "HIGH", "MEDIUM"
    description: str
    mitre_id: str  # e.g., "T1059.001"
    blocked: bool


class ProcessMonitor:
    """
    EDR-level process monitoring.
    
    Monitors process creation via WMI and detects:
    - LOLBins misuse (PowerShell obfuscation, etc.)
    - Parent-child anomalies (Office spawning shells)
    - Suspicious command line patterns
    """
    
    # LOLBins - Legitimate binaries often abused
    LOLBINS = {
        'powershell.exe', 'powershell_ise.exe', 'pwsh.exe',
        'cmd.exe', 'wscript.exe', 'cscript.exe',
        'mshta.exe', 'rundll32.exe', 'regsvr32.exe',
        'certutil.exe', 'bitsadmin.exe', 'msiexec.exe',
        'wmic.exe', 'installutil.exe', 'regasm.exe',
        'regsvcs.exe', 'msconfig.exe', 'msbuild.exe',
    }
    
    # Suspicious command line arguments
    SUSPICIOUS_ARGS = [
        '-enc', '-encodedcommand', '-e ', '-ec ',
        'bypass', 'hidden', '-nop', '-noprofile',
        'downloadstring', 'downloadfile', 'webclient',
        'invoke-expression', 'iex', 'invoke-webrequest',
        'frombase64string', 'base64',
        'http://', 'https://', 'ftp://',
        '/urlcache', '/transfer', '/format:',
        'regsvr32 /s /n /u',
    ]
    
    # Office applications (macro attack sources)
    OFFICE_APPS = {
        'winword.exe', 'excel.exe', 'powerpnt.exe',
        'outlook.exe', 'msaccess.exe', 'mspub.exe',
        'onenote.exe',
    }
    
    # Shell processes (targets of macro attacks)
    SHELLS = {
        'cmd.exe', 'powershell.exe', 'pwsh.exe',
        'wscript.exe', 'cscript.exe', 'mshta.exe',
    }
    
    # MITRE ATT&CK IDs
    MITRE_MAP = {
        'powershell': 'T1059.001',
        'cmd': 'T1059.003',
        'wscript': 'T1059.005',
        'mshta': 'T1218.005',
        'rundll32': 'T1218.011',
        'certutil': 'T1140',
        'bitsadmin': 'T1197',
        'macro': 'T1204.002',
    }
    
    def __init__(self, 
                 threat_callback: Callable[[ThreatEvent], None] = None,
                 log_callback: Callable[[ProcessEvent, str], None] = None,
                 auto_kill: bool = True):
        """
        Initialize process monitor.
        
        Args:
            threat_callback: Called on threat detection
            log_callback: Called for each process (for live feed)
            auto_kill: Automatically kill malicious processes
        """
        self.threat_callback = threat_callback
        self.log_callback = log_callback
        self.auto_kill = auto_kill
        
        self.is_running = False
        self._thread = None
        self._stop_event = threading.Event()
        
        # Statistics
        self.processes_inspected = 0
        self.threats_blocked = 0
    
    def _get_parent_name(self, ppid: int) -> str:
        """Get parent process name."""
        if not PSUTIL_AVAILABLE or ppid <= 0:
            return "Unknown"
        
        try:
            parent = psutil.Process(ppid)
            return parent.name()
        except:
            return "Unknown"
    
    def analyze_process(self, event: ProcessEvent) -> Optional[ThreatEvent]:
        """
        Analyze a process for malicious behavior.
        
        Returns:
            ThreatEvent if malicious, None otherwise
        """
        self.processes_inspected += 1
        
        name_lower = event.name.lower()
        cmd_lower = event.command_line.lower() if event.command_line else ""
        parent_lower = event.parent_name.lower()
        
        # Detection 1: LOLBins with suspicious arguments
        if name_lower in self.LOLBINS:
            for sus_arg in self.SUSPICIOUS_ARGS:
                if sus_arg.lower() in cmd_lower:
                    mitre_id = self._get_mitre_id(name_lower)
                    return ThreatEvent(
                        event_type="LOLBIN_ABUSE",
                        process_event=event,
                        severity="HIGH",
                        description=f"LOLBin misuse: {event.name} with suspicious args",
                        mitre_id=mitre_id,
                        blocked=False
                    )
        
        # Detection 2: Office app spawning shell (Macro Attack)
        if parent_lower in self.OFFICE_APPS:
            if name_lower in self.SHELLS:
                return ThreatEvent(
                    event_type="MACRO_ATTACK",
                    process_event=event,
                    severity="CRITICAL",
                    description=f"Macro Attack: {event.parent_name} → {event.name}",
                    mitre_id=self.MITRE_MAP.get('macro', 'T1204.002'),
                    blocked=False
                )
        
        # Detection 3: Encoded PowerShell (very suspicious)
        if 'powershell' in name_lower:
            if '-enc' in cmd_lower or 'frombase64' in cmd_lower:
                return ThreatEvent(
                    event_type="OBFUSCATED_COMMAND",
                    process_event=event,
                    severity="CRITICAL",
                    description="Encoded PowerShell command detected",
                    mitre_id="T1059.001",
                    blocked=False
                )
        
        # Detection 4: Network download via LOLBin
        if name_lower in {'certutil.exe', 'bitsadmin.exe'}:
            if any(x in cmd_lower for x in ['http://', 'https://', 'urlcache', 'transfer']):
                return ThreatEvent(
                    event_type="LOLBIN_DOWNLOAD",
                    process_event=event,
                    severity="HIGH",
                    description=f"File download via {event.name}",
                    mitre_id=self._get_mitre_id(name_lower),
                    blocked=False
                )
        
        return None
    
    def _get_mitre_id(self, process_name: str) -> str:
        """Get MITRE ATT&CK ID for process."""
        for key, mitre_id in self.MITRE_MAP.items():
            if key in process_name:
                return mitre_id
        return "T1059"
    
    def _kill_process(self, pid: int) -> bool:
        """Kill a malicious process."""
        if not PSUTIL_AVAILABLE:
            return False
        
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            proc.wait(timeout=5)
            return True
        except:
            return False
    
    def start(self) -> bool:
        """Start process monitoring."""
        if not WMI_AVAILABLE:
            return False
        
        if self.is_running:
            return True
        
        self._stop_event.clear()
        self.is_running = True
        
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        
        return True
    
    def stop(self):
        """Stop process monitoring."""
        self._stop_event.set()
        self.is_running = False
    
    def _monitor_loop(self):
        """Main WMI monitoring loop."""
        try:
            c = wmi.WMI()
            
            # Watch for process creation
            process_watcher = c.Win32_Process.watch_for("creation")
            
            while not self._stop_event.is_set():
                try:
                    # Wait for process with timeout
                    new_process = process_watcher(timeout_ms=1000)
                    
                    if new_process and not self._stop_event.is_set():
                        self._handle_process(new_process)
                        
                except wmi.x_wmi_timed_out:
                    continue
                except Exception as e:
                    time.sleep(1)
                    
        except Exception as e:
            print(f"[EDR] WMI error: {e}")
            self.is_running = False
    
    def _handle_process(self, wmi_process):
        """Handle a new process event."""
        try:
            # Extract info
            pid = wmi_process.ProcessId
            name = wmi_process.Name or "Unknown"
            cmd = getattr(wmi_process, 'CommandLine', '') or ''
            ppid = wmi_process.ParentProcessId or 0
            parent_name = self._get_parent_name(ppid)
            
            event = ProcessEvent(
                pid=pid,
                name=name,
                command_line=cmd,
                parent_pid=ppid,
                parent_name=parent_name,
                timestamp=datetime.now()
            )
            
            # Log for live feed
            if self.log_callback:
                self.log_callback(event, "INSPECTED")
            
            # Analyze
            threat = self.analyze_process(event)
            
            if threat:
                # Kill if enabled
                if self.auto_kill:
                    threat.blocked = self._kill_process(pid)
                    if threat.blocked:
                        self.threats_blocked += 1
                
                # Update log
                if self.log_callback:
                    status = "BLOCKED" if threat.blocked else "DETECTED"
                    self.log_callback(event, status)
                
                # Alert
                if self.threat_callback:
                    self.threat_callback(threat)
                    
        except Exception as e:
            print(f"[EDR] Handle error: {e}")
    
    def get_status(self) -> dict:
        """Get monitor status."""
        return {
            'running': self.is_running,
            'wmi_available': WMI_AVAILABLE,
            'processes_inspected': self.processes_inspected,
            'threats_blocked': self.threats_blocked
        }
    
    @staticmethod
    def is_available() -> bool:
        """Check if EDR is available."""
        return WMI_AVAILABLE and PSUTIL_AVAILABLE


# Linux alternative using /proc monitoring
class LinuxProcessMonitor:
    """
    Process monitor for Linux systems.
    Uses /proc filesystem polling as WMI alternative.
    """
    
    def __init__(self, 
                 threat_callback: Callable = None,
                 log_callback: Callable = None):
        self.threat_callback = threat_callback
        self.log_callback = log_callback
        self.is_running = False
        self._known_pids = set()
        self._thread = None
        self._stop_event = threading.Event()
    
    def start(self) -> bool:
        """Start monitoring."""
        if not PSUTIL_AVAILABLE:
            return False
        
        self._known_pids = set(psutil.pids())
        self._stop_event.clear()
        self.is_running = True
        
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        
        return True
    
    def stop(self):
        """Stop monitoring."""
        self._stop_event.set()
        self.is_running = False
    
    def _monitor_loop(self):
        """Poll for new processes."""
        while not self._stop_event.is_set():
            try:
                current_pids = set(psutil.pids())
                new_pids = current_pids - self._known_pids
                
                for pid in new_pids:
                    try:
                        proc = psutil.Process(pid)
                        cmdline = ' '.join(proc.cmdline())
                        
                        event = ProcessEvent(
                            pid=pid,
                            name=proc.name(),
                            command_line=cmdline,
                            parent_pid=proc.ppid(),
                            parent_name=self._get_parent_name(proc.ppid()),
                            timestamp=datetime.now()
                        )
                        
                        if self.log_callback:
                            self.log_callback(event, "INSPECTED")
                            
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                self._known_pids = current_pids
                
            except Exception as e:
                pass
            
            self._stop_event.wait(0.5)  # Poll every 500ms
    
    def _get_parent_name(self, ppid: int) -> str:
        try:
            return psutil.Process(ppid).name()
        except:
            return "Unknown"
