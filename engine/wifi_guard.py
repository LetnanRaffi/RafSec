"""
RafSec Engine - WiFi Guard (Anti-MITM)
=======================================
Detect ARP spoofing and MITM attacks.

Author: RafSec Team
"""

import subprocess
import platform
import threading
import time
import re
from typing import Callable, Optional, Tuple


class WiFiGuard:
    """
    Detect Man-in-the-Middle attacks on local network.
    
    Monitors ARP table for gateway MAC address changes,
    which indicate ARP spoofing attacks.
    """
    
    def __init__(self, alert_callback: Callable = None):
        """
        Initialize WiFi Guard.
        
        Args:
            alert_callback: Function(message) called on attack detection
        """
        self.alert_callback = alert_callback
        self.gateway_ip = None
        self.gateway_mac = None
        self.is_running = False
        self._thread = None
    
    @staticmethod
    def get_gateway_info() -> Tuple[Optional[str], Optional[str]]:
        """
        Get default gateway IP and MAC.
        
        Returns:
            Tuple of (gateway_ip, gateway_mac)
        """
        gateway_ip = None
        gateway_mac = None
        
        try:
            if platform.system() == "Windows":
                # Get gateway IP
                result = subprocess.run(
                    ["ipconfig"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                # Find "Default Gateway" line
                for line in result.stdout.split('\n'):
                    if "Default Gateway" in line:
                        match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if match:
                            gateway_ip = match.group(1)
                            break
                
            else:  # Linux/Mac
                result = subprocess.run(
                    ["ip", "route", "show", "default"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', result.stdout)
                if match:
                    gateway_ip = match.group(1)
            
            # Get MAC from ARP table
            if gateway_ip:
                gateway_mac = WiFiGuard.get_mac_for_ip(gateway_ip)
                
        except Exception:
            pass
        
        return (gateway_ip, gateway_mac)
    
    @staticmethod
    def get_mac_for_ip(ip: str) -> Optional[str]:
        """Get MAC address for an IP from ARP table."""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(
                    ["arp", "-a", ip],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
            else:
                result = subprocess.run(
                    ["arp", "-n", ip],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
            
            # Extract MAC address (format: xx-xx-xx-xx-xx-xx or xx:xx:xx:xx:xx:xx)
            mac_pattern = r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}'
            match = re.search(mac_pattern, result.stdout)
            
            if match:
                return match.group(0).upper().replace('-', ':')
                
        except Exception:
            pass
        
        return None
    
    def start_monitoring(self, interval: int = 5) -> bool:
        """
        Start monitoring for MITM attacks.
        
        Args:
            interval: Check interval in seconds
            
        Returns:
            True if monitoring started
        """
        # Get initial gateway info
        self.gateway_ip, self.gateway_mac = self.get_gateway_info()
        
        if not self.gateway_ip or not self.gateway_mac:
            return False
        
        self.is_running = True
        self._thread = threading.Thread(
            target=self._monitor_loop,
            args=(interval,),
            daemon=True
        )
        self._thread.start()
        
        return True
    
    def stop_monitoring(self):
        """Stop monitoring."""
        self.is_running = False
    
    def _monitor_loop(self, interval: int):
        """Main monitoring loop."""
        while self.is_running:
            try:
                current_mac = self.get_mac_for_ip(self.gateway_ip)
                
                if current_mac and current_mac != self.gateway_mac:
                    # MAC changed! Possible MITM attack
                    self._trigger_alert(current_mac)
                    
            except Exception:
                pass
            
            time.sleep(interval)
    
    def _trigger_alert(self, new_mac: str):
        """Handle MITM detection."""
        message = (
            f"⚠️ CRITICAL: ARP SPOOFING DETECTED!\n\n"
            f"Gateway IP: {self.gateway_ip}\n"
            f"Expected MAC: {self.gateway_mac}\n"
            f"Current MAC: {new_mac}\n\n"
            f"This indicates a Man-in-the-Middle attack!"
        )
        
        if self.alert_callback:
            self.alert_callback(message)
        
        # Update stored MAC to prevent repeated alerts
        # (or keep alerting by not updating)
    
    def get_status(self) -> dict:
        """Get monitoring status."""
        return {
            'running': self.is_running,
            'gateway_ip': self.gateway_ip,
            'gateway_mac': self.gateway_mac
        }
    
    @staticmethod
    def quick_check() -> dict:
        """
        Quick network security check.
        
        Returns:
            Dict with gateway info and basic checks
        """
        ip, mac = WiFiGuard.get_gateway_info()
        
        return {
            'gateway_ip': ip,
            'gateway_mac': mac,
            'status': 'OK' if ip and mac else 'Unknown'
        }
