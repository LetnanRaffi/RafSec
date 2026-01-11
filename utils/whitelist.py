"""
RafSec Utils - Whitelist Manager
=================================
Manage file/folder exclusions from scanning.

Author: RafSec Team
"""

import os
import json
from typing import List, Set


class Whitelist:
    """
    Manage scan exclusions (whitelist).
    
    Files and folders in the whitelist are skipped during scans.
    Useful for excluding known safe files that trigger false positives.
    """
    
    CONFIG_FILE = "whitelist.json"
    
    def __init__(self, config_dir: str = None):
        """
        Initialize whitelist.
        
        Args:
            config_dir: Directory to store whitelist config
        """
        if config_dir is None:
            config_dir = os.path.dirname(os.path.dirname(__file__))
        
        self.config_path = os.path.join(config_dir, self.CONFIG_FILE)
        self._whitelist: Set[str] = set()
        self._load()
    
    def _load(self):
        """Load whitelist from disk."""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    data = json.load(f)
                    self._whitelist = set(data.get('paths', []))
            except:
                self._whitelist = set()
        else:
            self._whitelist = set()
    
    def _save(self):
        """Save whitelist to disk."""
        try:
            with open(self.config_path, 'w') as f:
                json.dump({'paths': list(self._whitelist)}, f, indent=2)
        except:
            pass
    
    def add(self, path: str) -> bool:
        """
        Add a path to whitelist.
        
        Args:
            path: File or folder path to exclude
            
        Returns:
            True if added (wasn't already in list)
        """
        normalized = os.path.normpath(os.path.abspath(path))
        
        if normalized not in self._whitelist:
            self._whitelist.add(normalized)
            self._save()
            return True
        return False
    
    def remove(self, path: str) -> bool:
        """
        Remove a path from whitelist.
        
        Args:
            path: Path to remove
            
        Returns:
            True if removed (was in list)
        """
        normalized = os.path.normpath(os.path.abspath(path))
        
        if normalized in self._whitelist:
            self._whitelist.discard(normalized)
            self._save()
            return True
        return False
    
    def is_whitelisted(self, path: str) -> bool:
        """
        Check if a path is whitelisted.
        
        Also checks if any parent directory is whitelisted.
        
        Args:
            path: Path to check
            
        Returns:
            True if path or parent is whitelisted
        """
        normalized = os.path.normpath(os.path.abspath(path))
        
        # Direct match
        if normalized in self._whitelist:
            return True
        
        # Check if any parent directory is whitelisted
        for whitelisted in self._whitelist:
            if os.path.isdir(whitelisted):
                # Check if path is inside whitelisted directory
                try:
                    rel = os.path.relpath(normalized, whitelisted)
                    if not rel.startswith('..'):
                        return True
                except ValueError:
                    # Different drives on Windows
                    pass
        
        return False
    
    def get_all(self) -> List[str]:
        """Get all whitelisted paths."""
        return sorted(list(self._whitelist))
    
    def clear(self):
        """Clear all whitelisted paths."""
        self._whitelist.clear()
        self._save()
    
    def count(self) -> int:
        """Get number of whitelisted paths."""
        return len(self._whitelist)
