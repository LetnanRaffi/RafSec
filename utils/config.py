"""
RafSec Utils - Configuration Manager
======================================
Persistent settings storage using JSON.

Author: RafSec Team
"""

import os
import json
from typing import Any, Dict, Optional


class ConfigManager:
    """
    Manage application settings with JSON persistence.
    
    Settings are automatically saved to config.json and
    loaded on startup. This gives the app "memory".
    """
    
    CONFIG_FILE = "config.json"
    
    # Default configuration
    DEFAULTS = {
        'theme': 'Dark',
        'vt_api_key': '',
        'voice_enabled': True,
        'live_protection': False,
        'honeypot_enabled': False,
        'minimize_to_tray': False,
        'yara_enabled': True,
        'ml_enabled': True,
        'whitelist': [],
        'quarantine_log': {},  # Maps quarantined filename to original path
        'last_scan': None,
        'files_scanned': 0,
        'threats_found': 0,
    }
    
    _instance: Optional['ConfigManager'] = None
    _config: Dict[str, Any] = {}
    
    def __new__(cls, config_dir: str = None):
        """Singleton pattern - only one config manager."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self, config_dir: str = None):
        """
        Initialize config manager.
        
        Args:
            config_dir: Directory for config.json (default: project root)
        """
        if self._initialized:
            return
        
        if config_dir is None:
            config_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        self.config_path = os.path.join(config_dir, self.CONFIG_FILE)
        self._config = self.load_config()
        self._initialized = True
    
    def load_config(self) -> Dict[str, Any]:
        """
        Load configuration from disk.
        
        Returns:
            Configuration dictionary (uses defaults if file missing)
        """
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    loaded = json.load(f)
                
                # Merge with defaults (in case new settings added)
                config = self.DEFAULTS.copy()
                config.update(loaded)
                return config
                
            except (json.JSONDecodeError, Exception) as e:
                print(f"[WARNING] Failed to load config: {e}")
                return self.DEFAULTS.copy()
        else:
            # Create default config file
            self._save_to_disk(self.DEFAULTS.copy())
            return self.DEFAULTS.copy()
    
    def _save_to_disk(self, config: Dict[str, Any]) -> bool:
        """Write config to disk."""
        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"[ERROR] Failed to save config: {e}")
            return False
    
    def save_config(self, key: str, value: Any) -> bool:
        """
        Update a specific setting.
        
        Args:
            key: Setting name
            value: New value
            
        Returns:
            True if saved successfully
        """
        self._config[key] = value
        return self._save_to_disk(self._config)
    
    def get_config(self, key: str, default: Any = None) -> Any:
        """
        Get a setting value.
        
        Args:
            key: Setting name
            default: Default value if not found
            
        Returns:
            Setting value
        """
        return self._config.get(key, default)
    
    def get_all(self) -> Dict[str, Any]:
        """Get all settings."""
        return self._config.copy()
    
    def reset_to_defaults(self) -> bool:
        """Reset all settings to defaults."""
        self._config = self.DEFAULTS.copy()
        return self._save_to_disk(self._config)
    
    # Convenience methods
    def get_api_key(self) -> str:
        """Get VirusTotal API key."""
        return self.get_config('vt_api_key', '')
    
    def set_api_key(self, key: str) -> bool:
        """Set VirusTotal API key."""
        return self.save_config('vt_api_key', key)
    
    def get_whitelist(self) -> list:
        """Get whitelist paths."""
        return self.get_config('whitelist', [])
    
    def add_to_whitelist(self, path: str) -> bool:
        """Add path to whitelist."""
        wl = self.get_whitelist()
        if path not in wl:
            wl.append(path)
            return self.save_config('whitelist', wl)
        return True
    
    def remove_from_whitelist(self, path: str) -> bool:
        """Remove path from whitelist."""
        wl = self.get_whitelist()
        if path in wl:
            wl.remove(path)
            return self.save_config('whitelist', wl)
        return True
    
    def add_to_quarantine_log(self, quarantine_name: str, original_path: str) -> bool:
        """Log original path for quarantined file."""
        log = self.get_config('quarantine_log', {})
        log[quarantine_name] = original_path
        return self.save_config('quarantine_log', log)
    
    def get_original_path(self, quarantine_name: str) -> Optional[str]:
        """Get original path of quarantined file."""
        log = self.get_config('quarantine_log', {})
        return log.get(quarantine_name)
    
    def remove_from_quarantine_log(self, quarantine_name: str) -> bool:
        """Remove entry from quarantine log."""
        log = self.get_config('quarantine_log', {})
        if quarantine_name in log:
            del log[quarantine_name]
            return self.save_config('quarantine_log', log)
        return True
