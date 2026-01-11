"""
RafSec Engine - VirusTotal Cloud Scanner
==========================================
Check file hashes against VirusTotal's global malware database.

Author: RafSec Team
"""

import os
import json
from typing import Optional, Dict, Any
from dataclasses import dataclass

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


@dataclass
class CloudResult:
    """VirusTotal scan result."""
    queried: bool = False
    found: bool = False
    malicious_count: int = 0
    suspicious_count: int = 0
    harmless_count: int = 0
    total_engines: int = 0
    threat_names: list = None
    permalink: str = ""
    error: str = ""
    
    def __post_init__(self):
        if self.threat_names is None:
            self.threat_names = []


class CloudScanner:
    """
    VirusTotal API integration for cloud-based threat intelligence.
    
    Usage:
        scanner = CloudScanner(api_key="your_api_key")
        result = scanner.check_hash("d41d8cd98f00b204e9800998ecf8427e")
    """
    
    API_BASE = "https://www.virustotal.com/api/v3"
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize cloud scanner.
        
        Args:
            api_key: VirusTotal API key (get free at virustotal.com)
        """
        self.api_key = api_key or self._load_api_key()
    
    def _load_api_key(self) -> Optional[str]:
        """Load API key from config file."""
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            'config.json'
        )
        
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    config = json.load(f)
                    return config.get('virustotal_api_key')
            except:
                pass
        
        return None
    
    @staticmethod
    def save_api_key(api_key: str) -> bool:
        """Save API key to config file."""
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            'config.json'
        )
        
        config = {}
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    config = json.load(f)
            except:
                pass
        
        config['virustotal_api_key'] = api_key
        
        try:
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=2)
            return True
        except:
            return False
    
    def is_configured(self) -> bool:
        """Check if API key is configured."""
        return bool(self.api_key)
    
    def check_hash(self, file_hash: str) -> CloudResult:
        """
        Query VirusTotal for a file hash.
        
        Args:
            file_hash: MD5, SHA1, or SHA256 hash
            
        Returns:
            CloudResult with detection statistics
        """
        if not REQUESTS_AVAILABLE:
            return CloudResult(error="requests library not installed")
        
        if not self.api_key:
            return CloudResult(error="No API key configured")
        
        result = CloudResult(queried=True)
        
        try:
            headers = {
                "x-apikey": self.api_key,
                "Accept": "application/json"
            }
            
            url = f"{self.API_BASE}/files/{file_hash}"
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 404:
                result.found = False
                return result
            
            if response.status_code == 401:
                result.error = "Invalid API key"
                return result
            
            if response.status_code == 429:
                result.error = "API rate limit exceeded"
                return result
            
            if response.status_code != 200:
                result.error = f"API error: {response.status_code}"
                return result
            
            data = response.json()
            result.found = True
            
            # Parse analysis stats
            attrs = data.get('data', {}).get('attributes', {})
            stats = attrs.get('last_analysis_stats', {})
            
            result.malicious_count = stats.get('malicious', 0)
            result.suspicious_count = stats.get('suspicious', 0)
            result.harmless_count = stats.get('harmless', 0)
            result.total_engines = sum(stats.values())
            
            # Get threat names from analysis results
            analysis_results = attrs.get('last_analysis_results', {})
            for engine, result_data in analysis_results.items():
                if result_data.get('category') == 'malicious':
                    name = result_data.get('result')
                    if name and name not in result.threat_names:
                        result.threat_names.append(name)
            
            # Limit threat names
            result.threat_names = result.threat_names[:10]
            
            # Get permalink
            result.permalink = f"https://www.virustotal.com/gui/file/{file_hash}"
            
        except requests.exceptions.Timeout:
            result.error = "Request timeout"
        except requests.exceptions.ConnectionError:
            result.error = "Connection failed"
        except Exception as e:
            result.error = str(e)
        
        return result
    
    def check_file(self, file_path: str) -> CloudResult:
        """
        Check a file by computing its hash first.
        
        Args:
            file_path: Path to file
            
        Returns:
            CloudResult
        """
        import hashlib
        
        try:
            with open(file_path, 'rb') as f:
                sha256 = hashlib.sha256(f.read()).hexdigest()
            return self.check_hash(sha256)
        except Exception as e:
            return CloudResult(error=f"Failed to hash file: {e}")
