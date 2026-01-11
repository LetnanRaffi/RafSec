"""
RafSec Engine - Firewall Manager
=================================
Control Windows Firewall to block malicious apps.

Author: RafSec Team
"""

import os
import platform
import subprocess
from typing import Tuple


class FirewallManager:
    """
    Windows Firewall management using netsh.
    
    Allows blocking/unblocking specific applications
    from making network connections.
    
    Note: Requires administrator privileges.
    """
    
    @staticmethod
    def is_windows() -> bool:
        """Check if running on Windows."""
        return platform.system() == "Windows"
    
    @staticmethod
    def block_app(exe_path: str, rule_name: str = None) -> Tuple[bool, str]:
        """
        Block an application from making network connections.
        
        Args:
            exe_path: Full path to the executable
            rule_name: Optional custom rule name
            
        Returns:
            Tuple of (success, message)
        """
        if not FirewallManager.is_windows():
            return (False, "Firewall control only available on Windows")
        
        if not os.path.exists(exe_path):
            return (False, "Executable not found")
        
        # Generate rule name
        if not rule_name:
            app_name = os.path.basename(exe_path)
            rule_name = f"RafSec_Block_{app_name}"
        
        try:
            # Block outbound
            cmd_out = [
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={rule_name}_OUT',
                'dir=out',
                'action=block',
                f'program={exe_path}',
                'enable=yes'
            ]
            
            result = subprocess.run(
                cmd_out,
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            )
            
            if result.returncode != 0:
                return (False, f"Failed to add outbound rule: {result.stderr}")
            
            # Block inbound
            cmd_in = [
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={rule_name}_IN',
                'dir=in',
                'action=block',
                f'program={exe_path}',
                'enable=yes'
            ]
            
            result = subprocess.run(
                cmd_in,
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            )
            
            if result.returncode != 0:
                return (False, f"Failed to add inbound rule: {result.stderr}")
            
            return (True, f"Blocked: {os.path.basename(exe_path)}")
            
        except PermissionError:
            return (False, "Administrator privileges required")
        except Exception as e:
            return (False, f"Error: {str(e)}")
    
    @staticmethod
    def unblock_app(exe_path: str, rule_name: str = None) -> Tuple[bool, str]:
        """
        Remove firewall block for an application.
        
        Args:
            exe_path: Full path to the executable
            rule_name: Optional custom rule name
            
        Returns:
            Tuple of (success, message)
        """
        if not FirewallManager.is_windows():
            return (False, "Firewall control only available on Windows")
        
        if not rule_name:
            app_name = os.path.basename(exe_path)
            rule_name = f"RafSec_Block_{app_name}"
        
        try:
            errors = []
            
            # Remove outbound rule
            cmd_out = [
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                f'name={rule_name}_OUT'
            ]
            
            result = subprocess.run(
                cmd_out,
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            )
            
            if result.returncode != 0 and "No rules match" not in result.stderr:
                errors.append("outbound")
            
            # Remove inbound rule
            cmd_in = [
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                f'name={rule_name}_IN'
            ]
            
            result = subprocess.run(
                cmd_in,
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            )
            
            if result.returncode != 0 and "No rules match" not in result.stderr:
                errors.append("inbound")
            
            if errors:
                return (False, f"Failed to remove {', '.join(errors)} rule(s)")
            
            return (True, f"Unblocked: {os.path.basename(exe_path)}")
            
        except PermissionError:
            return (False, "Administrator privileges required")
        except Exception as e:
            return (False, f"Error: {str(e)}")
    
    @staticmethod
    def list_rafsec_rules() -> list:
        """
        List all RafSec-created firewall rules.
        
        Returns:
            List of rule names
        """
        if not FirewallManager.is_windows():
            return []
        
        try:
            cmd = [
                'netsh', 'advfirewall', 'firewall', 'show', 'rule',
                'name=all', 'dir=out'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            )
            
            rules = []
            for line in result.stdout.split('\n'):
                if 'Rule Name:' in line and 'RafSec_Block_' in line:
                    rule_name = line.split(':')[1].strip()
                    rules.append(rule_name)
            
            return rules
            
        except:
            return []
    
    @staticmethod
    def is_app_blocked(exe_path: str) -> bool:
        """Check if an application is blocked."""
        if not FirewallManager.is_windows():
            return False
        
        app_name = os.path.basename(exe_path)
        rule_name = f"RafSec_Block_{app_name}_OUT"
        
        rules = FirewallManager.list_rafsec_rules()
        return rule_name in rules
