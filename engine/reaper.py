"""
RafSec Engine - Reaper (Kill-Chain Automation)
===============================================
Automated incident response and process termination.

Author: RafSec Team
"""

import os
import platform
import subprocess
from typing import List, Tuple, Set

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


class Reaper:
    """
    Kill-chain automation for incident response.
    
    Provides capabilities to:
    - Kill entire process trees (children + parent)
    - Isolate the host by disabling network
    - Protect critical system processes
    """
    
    # Protected processes - NEVER kill these
    PROTECTED = {
        'system', 'registry', 'smss.exe', 'csrss.exe',
        'wininit.exe', 'winlogon.exe', 'lsass.exe',
        'services.exe', 'explorer.exe', 'dwm.exe',
        'taskmgr.exe', 'svchost.exe', 'lsaiso.exe',
        'fontdrvhost.exe', 'sihost.exe', 'ctfmon.exe',
        # Linux
        'init', 'systemd', 'kthreadd', 'ksoftirqd',
    }
    
    # Suspicious parent processes (might be part of attack chain)
    SUSPICIOUS_PARENTS = {
        'cmd.exe', 'powershell.exe', 'pwsh.exe',
        'wscript.exe', 'cscript.exe', 'mshta.exe',
    }
    
    @staticmethod
    def is_protected(name: str) -> bool:
        """Check if process is protected."""
        return name.lower() in Reaper.PROTECTED
    
    @staticmethod
    def get_children(pid: int) -> List[int]:
        """Get all child process PIDs recursively."""
        if not PSUTIL_AVAILABLE:
            return []
        
        children = []
        
        try:
            proc = psutil.Process(pid)
            for child in proc.children(recursive=True):
                children.append(child.pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        
        return children
    
    @staticmethod
    def get_parent_chain(pid: int, depth: int = 3) -> List[Tuple[int, str]]:
        """Get parent process chain up to depth levels."""
        if not PSUTIL_AVAILABLE:
            return []
        
        chain = []
        current_pid = pid
        
        for _ in range(depth):
            try:
                proc = psutil.Process(current_pid)
                ppid = proc.ppid()
                
                if ppid <= 1:
                    break
                
                parent = psutil.Process(ppid)
                chain.append((ppid, parent.name()))
                current_pid = ppid
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break
        
        return chain
    
    @staticmethod
    def kill_process(pid: int, force: bool = False) -> Tuple[bool, str]:
        """
        Kill a single process.
        
        Args:
            pid: Process ID
            force: Use SIGKILL instead of SIGTERM
            
        Returns:
            Tuple of (success, message)
        """
        if not PSUTIL_AVAILABLE:
            return (False, "psutil not available")
        
        try:
            proc = psutil.Process(pid)
            name = proc.name()
            
            # Check protection
            if Reaper.is_protected(name):
                return (False, f"Protected process: {name}")
            
            # Kill
            if force:
                proc.kill()
            else:
                proc.terminate()
            
            proc.wait(timeout=5)
            return (True, f"Killed: {name} (PID {pid})")
            
        except psutil.NoSuchProcess:
            return (True, "Process already terminated")
        except psutil.AccessDenied:
            return (False, "Access denied - run as administrator")
        except psutil.TimeoutExpired:
            # Force kill
            try:
                psutil.Process(pid).kill()
                return (True, f"Force killed PID {pid}")
            except:
                return (False, "Timeout and force kill failed")
        except Exception as e:
            return (False, str(e))
    
    @staticmethod
    def kill_process_tree(pid: int, kill_parent: bool = False) -> dict:
        """
        Kill entire process tree.
        
        Args:
            pid: Target process ID
            kill_parent: Also kill suspicious parent
            
        Returns:
            Dict with results
        """
        results = {
            'target_pid': pid,
            'children_killed': [],
            'target_killed': False,
            'parent_killed': False,
            'errors': []
        }
        
        if not PSUTIL_AVAILABLE:
            results['errors'].append("psutil not available")
            return results
        
        # Step 1: Kill children first
        children = Reaper.get_children(pid)
        for child_pid in reversed(children):  # Kill deepest first
            success, msg = Reaper.kill_process(child_pid)
            if success:
                results['children_killed'].append(child_pid)
            else:
                results['errors'].append(f"Child {child_pid}: {msg}")
        
        # Step 2: Kill target
        success, msg = Reaper.kill_process(pid)
        results['target_killed'] = success
        if not success:
            results['errors'].append(f"Target: {msg}")
        
        # Step 3: Optionally kill suspicious parent
        if kill_parent:
            parent_chain = Reaper.get_parent_chain(pid)
            for ppid, pname in parent_chain:
                if pname.lower() in Reaper.SUSPICIOUS_PARENTS:
                    success, msg = Reaper.kill_process(ppid)
                    if success:
                        results['parent_killed'] = True
                        break
        
        return results
    
    @staticmethod
    def isolate_host() -> Tuple[bool, str]:
        """
        Isolate host by disabling network.
        
        Returns:
            Tuple of (success, message)
        """
        if platform.system() == "Windows":
            return Reaper._isolate_windows()
        else:
            return Reaper._isolate_linux()
    
    @staticmethod
    def _isolate_windows() -> Tuple[bool, str]:
        """Disable Windows network adapters."""
        try:
            # Disable all network adapters via netsh
            result = subprocess.run(
                ["netsh", "interface", "set", "interface", "name=*", "admin=disable"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                return (True, "Network isolated - all adapters disabled")
            
            # Fallback: Add firewall block
            block_cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                "name=RAFSEC_ISOLATE", "dir=out", "action=block", "enable=yes"
            ]
            subprocess.run(block_cmd, capture_output=True, timeout=30)
            
            block_in = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                "name=RAFSEC_ISOLATE_IN", "dir=in", "action=block", "enable=yes"
            ]
            subprocess.run(block_in, capture_output=True, timeout=30)
            
            return (True, "Network isolated via firewall rules")
            
        except PermissionError:
            return (False, "Administrator privileges required")
        except Exception as e:
            return (False, str(e))
    
    @staticmethod
    def _isolate_linux() -> Tuple[bool, str]:
        """Disable Linux network."""
        try:
            # Use iptables to block all traffic
            subprocess.run(
                ["iptables", "-A", "OUTPUT", "-j", "DROP"],
                capture_output=True,
                timeout=10
            )
            subprocess.run(
                ["iptables", "-A", "INPUT", "-j", "DROP"],
                capture_output=True,
                timeout=10
            )
            
            return (True, "Network isolated via iptables")
            
        except FileNotFoundError:
            # Try ip command
            try:
                subprocess.run(["ip", "link", "set", "eth0", "down"], timeout=10)
                return (True, "Network interface disabled")
            except:
                pass
        except PermissionError:
            return (False, "Root privileges required")
        except Exception as e:
            return (False, str(e))
    
    @staticmethod
    def restore_network() -> Tuple[bool, str]:
        """Restore network connectivity."""
        if platform.system() == "Windows":
            try:
                # Enable adapters
                subprocess.run(
                    ["netsh", "interface", "set", "interface", "name=*", "admin=enable"],
                    capture_output=True,
                    timeout=30
                )
                
                # Remove firewall rules
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "delete", "rule", "name=RAFSEC_ISOLATE"],
                    capture_output=True,
                    timeout=30
                )
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "delete", "rule", "name=RAFSEC_ISOLATE_IN"],
                    capture_output=True,
                    timeout=30
                )
                
                return (True, "Network restored")
            except:
                return (False, "Failed to restore network")
        else:
            try:
                subprocess.run(["iptables", "-F"], capture_output=True, timeout=10)
                subprocess.run(["ip", "link", "set", "eth0", "up"], capture_output=True, timeout=10)
                return (True, "Network restored")
            except:
                return (False, "Failed to restore network")
    
    @staticmethod
    def emergency_response(pid: int, severity: str) -> dict:
        """
        Full emergency response.
        
        Args:
            pid: Malicious process ID
            severity: "CRITICAL", "HIGH", "MEDIUM"
            
        Returns:
            Response results
        """
        results = {
            'kill_tree': None,
            'isolated': False,
            'severity': severity
        }
        
        # Kill process tree
        results['kill_tree'] = Reaper.kill_process_tree(pid, kill_parent=True)
        
        # Isolate on critical severity
        if severity == "CRITICAL":
            success, msg = Reaper.isolate_host()
            results['isolated'] = success
            results['isolation_message'] = msg
        
        return results
