"""
RafSec Engine - Network Monitor
================================
Monitor active network connections using psutil.

Author: RafSec Team
"""

import os
import platform
from typing import List, Dict, Optional
from dataclasses import dataclass

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


@dataclass
class NetConnection:
    """Network connection information."""
    pid: int
    process_name: str
    process_path: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    status: str
    family: str  # IPv4 or IPv6


class NetworkMonitor:
    """
    Monitor active network connections.
    
    Detects potentially suspicious outbound connections
    that could indicate malware C2 communication.
    """
    
    # Known suspicious ports
    SUSPICIOUS_PORTS = {
        4444, 5555, 6666, 7777, 8888, 9999,  # Common RAT ports
        31337,  # Elite/Back Orifice
        12345, 12346,  # NetBus
        27374,  # SubSeven
        1080, 9050,  # SOCKS proxy (Tor)
    }
    
    @staticmethod
    def get_connections(include_listen: bool = False) -> List[NetConnection]:
        """
        Get all active network connections.
        
        Args:
            include_listen: Include LISTEN sockets
            
        Returns:
            List of NetConnection objects
        """
        if not PSUTIL_AVAILABLE:
            return []
        
        connections = []
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                # Filter by status
                if not include_listen and conn.status == 'LISTEN':
                    continue
                
                # Get process info
                pid = conn.pid or 0
                process_name = "Unknown"
                process_path = ""
                
                if pid > 0:
                    try:
                        proc = psutil.Process(pid)
                        process_name = proc.name()
                        try:
                            process_path = proc.exe()
                        except:
                            process_path = ""
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                # Parse addresses
                local_addr = conn.laddr.ip if conn.laddr else ""
                local_port = conn.laddr.port if conn.laddr else 0
                remote_addr = conn.raddr.ip if conn.raddr else ""
                remote_port = conn.raddr.port if conn.raddr else 0
                
                # Determine family
                family = "IPv4" if conn.family.name == 'AF_INET' else "IPv6"
                
                connections.append(NetConnection(
                    pid=pid,
                    process_name=process_name,
                    process_path=process_path,
                    local_addr=local_addr,
                    local_port=local_port,
                    remote_addr=remote_addr,
                    remote_port=remote_port,
                    status=conn.status,
                    family=family
                ))
        
        except (psutil.AccessDenied, Exception) as e:
            print(f"[WARNING] Network scan error: {e}")
        
        # Sort by PID
        connections.sort(key=lambda c: c.pid)
        
        return connections
    
    @staticmethod
    def get_established_connections() -> List[NetConnection]:
        """Get only ESTABLISHED connections (active data transfer)."""
        return [c for c in NetworkMonitor.get_connections() 
                if c.status == 'ESTABLISHED']
    
    @staticmethod
    def is_suspicious_port(port: int) -> bool:
        """Check if a port is commonly used by malware."""
        return port in NetworkMonitor.SUSPICIOUS_PORTS
    
    @staticmethod
    def kill_process(pid: int) -> bool:
        """
        Terminate a process by PID.
        
        Args:
            pid: Process ID to kill
            
        Returns:
            True if successful
        """
        if not PSUTIL_AVAILABLE:
            return False
        
        if pid <= 0:
            return False
        
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            proc.wait(timeout=5)
            return True
        except psutil.NoSuchProcess:
            return True  # Already dead
        except psutil.AccessDenied:
            # Try harder on Windows
            if platform.system() == "Windows":
                try:
                    import subprocess
                    subprocess.run(['taskkill', '/F', '/PID', str(pid)], 
                                   capture_output=True)
                    return True
                except:
                    pass
            return False
        except Exception:
            return False
    
    @staticmethod
    def get_process_path(pid: int) -> Optional[str]:
        """Get executable path for a process."""
        if not PSUTIL_AVAILABLE:
            return None
        
        try:
            proc = psutil.Process(pid)
            return proc.exe()
        except:
            return None
    
    @staticmethod
    def get_listening_ports() -> List[Dict]:
        """Get all listening ports and their processes."""
        if not PSUTIL_AVAILABLE:
            return []
        
        listeners = []
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN':
                    pid = conn.pid or 0
                    name = "Unknown"
                    
                    if pid > 0:
                        try:
                            name = psutil.Process(pid).name()
                        except:
                            pass
                    
                    listeners.append({
                        'port': conn.laddr.port,
                        'address': conn.laddr.ip,
                        'pid': pid,
                        'process': name
                    })
        except:
            pass
        
        return listeners
