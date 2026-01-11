"""
RafSec Engine - Privacy Shield
===============================
Hardware privacy controls (Webcam/Microphone).

Author: RafSec Team
"""

import platform
from typing import Tuple

# Windows Registry (only on Windows)
if platform.system() == "Windows":
    try:
        import winreg
        WINREG_AVAILABLE = True
    except ImportError:
        WINREG_AVAILABLE = False
else:
    WINREG_AVAILABLE = False


class PrivacyShield:
    """
    Control hardware privacy settings.
    
    Provides ability to block webcam and microphone
    at the system level (Windows Registry).
    """
    
    # Windows Registry paths for privacy
    WEBCAM_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam"
    MIC_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone"
    
    @staticmethod
    def is_windows() -> bool:
        """Check if running on Windows."""
        return platform.system() == "Windows"
    
    @staticmethod
    def toggle_webcam(enable: bool = True) -> Tuple[bool, str]:
        """
        Toggle webcam access.
        
        Args:
            enable: True to allow, False to block
            
        Returns:
            Tuple of (success, message)
        """
        if not PrivacyShield.is_windows():
            return (False, "Only supported on Windows")
        
        if not WINREG_AVAILABLE:
            return (False, "winreg not available")
        
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                PrivacyShield.WEBCAM_KEY,
                0,
                winreg.KEY_SET_VALUE
            )
            
            value = "Allow" if enable else "Deny"
            winreg.SetValueEx(key, "Value", 0, winreg.REG_SZ, value)
            winreg.CloseKey(key)
            
            action = "enabled" if enable else "blocked"
            return (True, f"Webcam {action}")
            
        except PermissionError:
            return (False, "Administrator privileges required")
        except FileNotFoundError:
            return (False, "Registry key not found")
        except Exception as e:
            return (False, str(e))
    
    @staticmethod
    def toggle_microphone(enable: bool = True) -> Tuple[bool, str]:
        """
        Toggle microphone access.
        
        Args:
            enable: True to allow, False to block
            
        Returns:
            Tuple of (success, message)
        """
        if not PrivacyShield.is_windows():
            return (False, "Only supported on Windows")
        
        if not WINREG_AVAILABLE:
            return (False, "winreg not available")
        
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                PrivacyShield.MIC_KEY,
                0,
                winreg.KEY_SET_VALUE
            )
            
            value = "Allow" if enable else "Deny"
            winreg.SetValueEx(key, "Value", 0, winreg.REG_SZ, value)
            winreg.CloseKey(key)
            
            action = "enabled" if enable else "blocked"
            return (True, f"Microphone {action}")
            
        except PermissionError:
            return (False, "Administrator privileges required")
        except FileNotFoundError:
            return (False, "Registry key not found")
        except Exception as e:
            return (False, str(e))
    
    @staticmethod
    def get_webcam_status() -> str:
        """Get current webcam status."""
        if not PrivacyShield.is_windows() or not WINREG_AVAILABLE:
            return "Unknown"
        
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                PrivacyShield.WEBCAM_KEY,
                0,
                winreg.KEY_READ
            )
            value, _ = winreg.QueryValueEx(key, "Value")
            winreg.CloseKey(key)
            return value
        except:
            return "Unknown"
    
    @staticmethod
    def get_microphone_status() -> str:
        """Get current microphone status."""
        if not PrivacyShield.is_windows() or not WINREG_AVAILABLE:
            return "Unknown"
        
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                PrivacyShield.MIC_KEY,
                0,
                winreg.KEY_READ
            )
            value, _ = winreg.QueryValueEx(key, "Value")
            winreg.CloseKey(key)
            return value
        except:
            return "Unknown"
    
    @staticmethod
    def get_all_status() -> dict:
        """Get all privacy statuses."""
        return {
            'webcam': PrivacyShield.get_webcam_status(),
            'microphone': PrivacyShield.get_microphone_status(),
            'platform': platform.system()
        }
