"""
RafSec Engine - Threat Intelligence
=====================================
Sync with public threat feeds.

Author: RafSec Team
"""

import os
from typing import Tuple, List
from datetime import datetime

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class ThreatIntel:
    """
    Threat intelligence feed synchronization.
    
    Downloads and parses malicious IP/domain lists
    from public threat feeds.
    """
    
    # Public threat feeds
    FEEDS = {
        'emerging_threats': 'https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt',
        'feodo_tracker': 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
    }
    
    def __init__(self, cache_dir: str = None):
        """
        Initialize threat intel.
        
        Args:
            cache_dir: Directory to cache downloaded feeds
        """
        if cache_dir is None:
            cache_dir = os.path.join(
                os.path.dirname(os.path.dirname(__file__)),
                'threat_intel'
            )
        
        self.cache_dir = cache_dir
        self.malicious_ips = set()
        
        if not os.path.exists(cache_dir):
            os.makedirs(cache_dir)
    
    def sync_feeds(self) -> Tuple[bool, str, int]:
        """
        Download and sync threat feeds.
        
        Returns:
            Tuple of (success, message, ip_count)
        """
        if not REQUESTS_AVAILABLE:
            return (False, "requests library not installed", 0)
        
        total_ips = 0
        errors = []
        
        for name, url in self.FEEDS.items():
            try:
                response = requests.get(url, timeout=30)
                
                if response.status_code == 200:
                    # Parse IPs (one per line, skip comments)
                    for line in response.text.split('\n'):
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # Basic IP validation
                            if self._is_valid_ip(line):
                                self.malicious_ips.add(line)
                                total_ips += 1
                    
                    # Cache the feed
                    cache_path = os.path.join(self.cache_dir, f"{name}.txt")
                    with open(cache_path, 'w') as f:
                        f.write(response.text)
                else:
                    errors.append(f"{name}: HTTP {response.status_code}")
                    
            except requests.exceptions.Timeout:
                errors.append(f"{name}: Timeout")
            except Exception as e:
                errors.append(f"{name}: {str(e)}")
        
        # Save metadata
        meta_path = os.path.join(self.cache_dir, "last_sync.txt")
        with open(meta_path, 'w') as f:
            f.write(datetime.now().isoformat())
        
        if errors:
            return (True, f"Database updated with {total_ips:,} malicious IPs ({len(errors)} feed errors)", total_ips)
        else:
            return (True, f"Database updated with {total_ips:,} malicious IPs", total_ips)
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Basic IP validation."""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False
    
    def is_malicious(self, ip: str) -> bool:
        """Check if an IP is in the threat database."""
        return ip in self.malicious_ips
    
    def get_last_sync(self) -> str:
        """Get last sync timestamp."""
        meta_path = os.path.join(self.cache_dir, "last_sync.txt")
        
        if os.path.exists(meta_path):
            with open(meta_path, 'r') as f:
                return f.read().strip()
        
        return "Never"
    
    def load_cached(self) -> int:
        """Load cached threat data."""
        count = 0
        
        for name in self.FEEDS.keys():
            cache_path = os.path.join(self.cache_dir, f"{name}.txt")
            
            if os.path.exists(cache_path):
                try:
                    with open(cache_path, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                if self._is_valid_ip(line):
                                    self.malicious_ips.add(line)
                                    count += 1
                except:
                    pass
        
        return count
    
    def get_count(self) -> int:
        """Get number of known malicious IPs."""
        return len(self.malicious_ips)
