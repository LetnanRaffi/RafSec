"""
RafSec Engine - Rootkit Hunter
===============================
Detect hidden processes and rootkits.

Author: RafSec Team
"""

import os
import platform
from typing import List, Dict

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


class RootkitHunter:
    """
    Detect hidden processes that may indicate rootkit presence.
    
    Compares visible PIDs against raw system data to find
    processes that are hiding from standard APIs.
    """
    
    @staticmethod
    def get_visible_pids() -> set:
        """Get PIDs visible through psutil."""
        if not PSUTIL_AVAILABLE:
            return set()
        
        return set(psutil.pids())
    
    @staticmethod
    def get_raw_pids_linux() -> set:
        """Get PIDs from /proc filesystem on Linux."""
        pids = set()
        
        try:
            for entry in os.listdir('/proc'):
                if entry.isdigit():
                    pids.add(int(entry))
        except:
            pass
        
        return pids
    
    @staticmethod
    def scan_for_hidden_processes() -> List[Dict]:
        """
        Scan for hidden (rootkit) processes.
        
        Returns:
            List of dicts with hidden process info
        """
        hidden = []
        
        if platform.system() == "Linux":
            visible = RootkitHunter.get_visible_pids()
            raw = RootkitHunter.get_raw_pids_linux()
            
            # Find PIDs in /proc but not visible to psutil
            ghost_pids = raw - visible
            
            for pid in ghost_pids:
                hidden.append({
                    'pid': pid,
                    'type': 'HIDDEN_PROCESS',
                    'detection_method': '/proc enumeration',
                    'risk': 'CRITICAL'
                })
        
        elif platform.system() == "Windows":
            # On Windows, check for suspicious process attributes
            if PSUTIL_AVAILABLE:
                for proc in psutil.process_iter(['pid', 'name', 'exe']):
                    try:
                        pid = proc.info['pid']
                        name = proc.info['name']
                        exe = proc.info['exe']
                        
                        # Suspicious: No name
                        if not name or name == "":
                            hidden.append({
                                'pid': pid,
                                'type': 'UNNAMED_PROCESS',
                                'detection_method': 'Missing process name',
                                'risk': 'HIGH'
                            })
                            continue
                        
                        # Suspicious: No executable path
                        if not exe and pid > 4:
                            hidden.append({
                                'pid': pid,
                                'name': name,
                                'type': 'NO_EXECUTABLE',
                                'detection_method': 'Missing executable path',
                                'risk': 'MEDIUM'
                            })
                        
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
        
        return hidden
    
    @staticmethod
    def check_kernel_integrity() -> Dict:
        """
        Basic kernel integrity check.
        
        Returns:
            Dict with check results
        """
        results = {
            'status': 'OK',
            'warnings': []
        }
        
        if platform.system() == "Linux":
            # Check for loaded kernel modules
            try:
                with open('/proc/modules', 'r') as f:
                    modules = f.read()
                
                # Known suspicious module patterns
                suspicious = ['hide', 'rootkit', 'stealth', 'diamorphine']
                for s in suspicious:
                    if s.lower() in modules.lower():
                        results['warnings'].append(f"Suspicious kernel module: {s}")
                        results['status'] = 'WARNING'
            except:
                pass
        
        return results
    
    @staticmethod
    def full_scan() -> Dict:
        """
        Perform full rootkit scan.
        
        Returns:
            Dict with all scan results
        """
        return {
            'hidden_processes': RootkitHunter.scan_for_hidden_processes(),
            'kernel_check': RootkitHunter.check_kernel_integrity(),
            'platform': platform.system()
        }
