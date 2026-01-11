"""
RafSec Engine - Memory Scanner (Fileless Malware Detection)
=============================================================
Scan process memory for in-memory threats.

Author: RafSec Team
"""

import os
from typing import List, Dict, Optional
from dataclasses import dataclass

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


@dataclass
class MemoryMatch:
    """Memory scan match result."""
    pid: int
    process_name: str
    rule_name: str
    description: str
    severity: str


class MemoryScanner:
    """
    Scan process memory for fileless malware.
    
    Uses YARA's PID scanning capability to detect
    threats that exist only in RAM.
    """
    
    # Skip these system processes
    SKIP_PROCESSES = {
        'System', 'Registry', 'Memory Compression', 'smss.exe',
        'csrss.exe', 'wininit.exe', 'winlogon.exe', 'lsass.exe',
        'services.exe', 'svchost.exe', 'lsaiso.exe'
    }
    
    def __init__(self, rules_path: str = None):
        """
        Initialize memory scanner.
        
        Args:
            rules_path: Path to memory YARA rules file
        """
        self.rules = None
        
        if rules_path is None:
            rules_path = os.path.join(
                os.path.dirname(os.path.dirname(__file__)),
                'rules', 'memory_threats.yar'
            )
        
        if YARA_AVAILABLE and os.path.exists(rules_path):
            try:
                self.rules = yara.compile(filepath=rules_path)
            except Exception as e:
                print(f"[WARNING] Failed to compile memory rules: {e}")
    
    def is_available(self) -> bool:
        """Check if memory scanning is available."""
        return YARA_AVAILABLE and PSUTIL_AVAILABLE and self.rules is not None
    
    def get_scannable_processes(self) -> List[Dict]:
        """Get list of processes that can be scanned."""
        if not PSUTIL_AVAILABLE:
            return []
        
        processes = []
        
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pid = proc.info['pid']
                name = proc.info['name'] or "Unknown"
                
                # Skip system processes and PID 0/4
                if pid <= 4:
                    continue
                if name in self.SKIP_PROCESSES:
                    continue
                
                processes.append({
                    'pid': pid,
                    'name': name
                })
            except:
                continue
        
        return processes
    
    def scan_process(self, pid: int) -> List[MemoryMatch]:
        """
        Scan a single process memory.
        
        Args:
            pid: Process ID to scan
            
        Returns:
            List of MemoryMatch findings
        """
        if not self.is_available():
            return []
        
        matches = []
        
        try:
            # Get process name
            proc_name = "Unknown"
            try:
                proc = psutil.Process(pid)
                proc_name = proc.name()
            except:
                pass
            
            # Scan memory
            yara_matches = self.rules.match(pid=pid)
            
            for match in yara_matches:
                # Get severity from rule metadata
                severity = "HIGH"
                description = match.rule
                
                if hasattr(match, 'meta'):
                    severity = match.meta.get('severity', 'HIGH')
                    description = match.meta.get('description', match.rule)
                
                matches.append(MemoryMatch(
                    pid=pid,
                    process_name=proc_name,
                    rule_name=match.rule,
                    description=description,
                    severity=severity
                ))
                
        except yara.Error:
            # Access denied or process terminated
            pass
        except Exception:
            pass
        
        return matches
    
    def scan_all_processes(self, progress_callback=None) -> List[MemoryMatch]:
        """
        Scan all running processes.
        
        Args:
            progress_callback: Optional callback(current, total, process_name)
            
        Returns:
            List of all MemoryMatch findings
        """
        all_matches = []
        processes = self.get_scannable_processes()
        total = len(processes)
        
        for i, proc in enumerate(processes):
            if progress_callback:
                progress_callback(i + 1, total, proc['name'])
            
            matches = self.scan_process(proc['pid'])
            all_matches.extend(matches)
        
        return all_matches
    
    @staticmethod
    def kill_process(pid: int) -> bool:
        """Kill a process by PID."""
        if not PSUTIL_AVAILABLE:
            return False
        
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            proc.wait(timeout=5)
            return True
        except:
            return False
