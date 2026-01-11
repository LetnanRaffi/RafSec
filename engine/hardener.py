"""
RafSec Engine - System Hardener
================================
Harden Windows security settings.

Author: RafSec Team
"""

import platform
import subprocess
from typing import Dict, Tuple, List

# Windows Registry
if platform.system() == "Windows":
    try:
        import winreg
        WINREG_AVAILABLE = True
    except ImportError:
        WINREG_AVAILABLE = False
else:
    WINREG_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


class SystemHardener:
    """
    Scan and fix Windows security vulnerabilities.
    
    Checks for common misconfigurations and applies
    security hardening settings.
    """
    
    @staticmethod
    def is_windows() -> bool:
        return platform.system() == "Windows"
    
    @staticmethod
    def check_rdp_enabled() -> bool:
        """Check if Remote Desktop is enabled."""
        if not SystemHardener.is_windows() or not WINREG_AVAILABLE:
            return False
        
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Terminal Server",
                0,
                winreg.KEY_READ
            )
            value, _ = winreg.QueryValueEx(key, "fDenyTSConnections")
            winreg.CloseKey(key)
            return value == 0  # 0 = RDP enabled
        except:
            return False
    
    @staticmethod
    def check_smb1_enabled() -> bool:
        """Check if SMBv1 (vulnerable) is enabled."""
        if not SystemHardener.is_windows():
            return False
        
        try:
            result = subprocess.run(
                ["powershell", "-Command", "Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"],
                capture_output=True,
                text=True,
                timeout=30
            )
            return "Enabled" in result.stdout
        except:
            return False
    
    @staticmethod
    def check_defender_active() -> bool:
        """Check if Windows Defender is active."""
        if not SystemHardener.is_windows():
            return True  # Assume OK on non-Windows
        
        try:
            result = subprocess.run(
                ["powershell", "-Command", "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled"],
                capture_output=True,
                text=True,
                timeout=30
            )
            return "True" in result.stdout
        except:
            return False
    
    @staticmethod
    def check_port_3389_open() -> bool:
        """Check if RDP port is listening."""
        if not PSUTIL_AVAILABLE:
            return False
        
        for conn in psutil.net_connections(kind='inet'):
            if conn.laddr.port == 3389 and conn.status == 'LISTEN':
                return True
        return False
    
    @staticmethod
    def scan_vulnerabilities() -> Dict:
        """
        Scan for security vulnerabilities.
        
        Returns:
            Dict of vulnerability findings
        """
        vulns = {
            'rdp_enabled': False,
            'rdp_port_open': False,
            'smb1_enabled': False,
            'defender_disabled': False,
            'total_issues': 0,
            'items': []
        }
        
        if not SystemHardener.is_windows():
            vulns['note'] = "Windows-only checks"
            return vulns
        
        # RDP Check
        if SystemHardener.check_rdp_enabled():
            vulns['rdp_enabled'] = True
            vulns['items'].append({
                'name': 'Remote Desktop (RDP)',
                'status': 'EXPOSED',
                'risk': 'HIGH',
                'fix': 'Disable RDP in System Settings'
            })
            vulns['total_issues'] += 1
        
        if SystemHardener.check_port_3389_open():
            vulns['rdp_port_open'] = True
            vulns['items'].append({
                'name': 'RDP Port 3389',
                'status': 'LISTENING',
                'risk': 'HIGH',
                'fix': 'Firewall should block port 3389'
            })
            vulns['total_issues'] += 1
        
        # SMBv1 Check
        if SystemHardener.check_smb1_enabled():
            vulns['smb1_enabled'] = True
            vulns['items'].append({
                'name': 'SMBv1 Protocol',
                'status': 'ENABLED',
                'risk': 'CRITICAL',
                'fix': 'Disable SMBv1 (WannaCry vector)'
            })
            vulns['total_issues'] += 1
        
        # Defender Check
        if not SystemHardener.check_defender_active():
            vulns['defender_disabled'] = True
            vulns['items'].append({
                'name': 'Windows Defender',
                'status': 'DISABLED',
                'risk': 'HIGH',
                'fix': 'Enable Real-time Protection'
            })
            vulns['total_issues'] += 1
        
        return vulns
    
    @staticmethod
    def disable_rdp() -> Tuple[bool, str]:
        """Disable Remote Desktop."""
        if not SystemHardener.is_windows() or not WINREG_AVAILABLE:
            return (False, "Windows only")
        
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Terminal Server",
                0,
                winreg.KEY_SET_VALUE
            )
            winreg.SetValueEx(key, "fDenyTSConnections", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)
            return (True, "RDP disabled")
        except PermissionError:
            return (False, "Administrator required")
        except Exception as e:
            return (False, str(e))
    
    @staticmethod
    def disable_smb1() -> Tuple[bool, str]:
        """Disable SMBv1 protocol."""
        if not SystemHardener.is_windows():
            return (False, "Windows only")
        
        try:
            result = subprocess.run(
                ["powershell", "-Command", 
                 "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart"],
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode == 0:
                return (True, "SMBv1 disabled (restart required)")
            else:
                return (False, result.stderr)
        except Exception as e:
            return (False, str(e))
    
    @staticmethod
    def disable_telemetry() -> Tuple[bool, str]:
        """Disable Windows telemetry."""
        if not SystemHardener.is_windows() or not WINREG_AVAILABLE:
            return (False, "Windows only")
        
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
                0,
                winreg.KEY_SET_VALUE | winreg.KEY_CREATE_SUB_KEY
            )
            winreg.SetValueEx(key, "AllowTelemetry", 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(key)
            return (True, "Telemetry disabled")
        except PermissionError:
            return (False, "Administrator required")
        except Exception as e:
            return (False, str(e))
    
    @staticmethod
    def apply_hardening() -> List[Tuple[str, bool, str]]:
        """
        Apply all hardening fixes.
        
        Returns:
            List of (setting, success, message) tuples
        """
        results = []
        
        results.append(("RDP", *SystemHardener.disable_rdp()))
        results.append(("SMBv1", *SystemHardener.disable_smb1()))
        results.append(("Telemetry", *SystemHardener.disable_telemetry()))
        
        return results
