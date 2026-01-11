"""
RafSec Engine - System Cleaner
===============================
Clean temporary files and browser caches.

Author: RafSec Team
"""

import os
import platform
import shutil
from typing import Dict, List, Tuple
from dataclasses import dataclass


@dataclass
class JunkScanResult:
    """Results from junk file scan."""
    total_size: int = 0  # Bytes
    temp_files: int = 0
    cache_files: int = 0
    log_files: int = 0
    locations: Dict[str, int] = None
    
    def __post_init__(self):
        if self.locations is None:
            self.locations = {}
    
    @property
    def size_mb(self) -> float:
        return self.total_size / (1024 * 1024)
    
    @property
    def size_formatted(self) -> str:
        if self.total_size < 1024:
            return f"{self.total_size} B"
        elif self.total_size < 1024 * 1024:
            return f"{self.total_size / 1024:.1f} KB"
        elif self.total_size < 1024 * 1024 * 1024:
            return f"{self.total_size / (1024 * 1024):.1f} MB"
        else:
            return f"{self.total_size / (1024 * 1024 * 1024):.2f} GB"


class SystemCleaner:
    """
    Scan and clean system junk files.
    
    Targets:
    - System temp folders
    - User temp folders
    - Browser caches
    - Thumbnail caches
    - Log files
    """
    
    # File extensions to clean
    JUNK_EXTENSIONS = {
        '.tmp', '.temp', '.bak', '.old', '.log',
        '.dmp', '.chk', '.gid', '.fts',
    }
    
    @staticmethod
    def _get_temp_locations() -> List[str]:
        """Get temporary file locations based on OS."""
        locations = []
        
        if platform.system() == "Windows":
            # Windows temp folders
            temp_dirs = [
                os.environ.get('TEMP', ''),
                os.environ.get('TMP', ''),
                os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Temp'),
                os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'Temp'),
            ]
            locations.extend([d for d in temp_dirs if d and os.path.isdir(d)])
            
        else:  # Linux/Mac
            locations = [
                '/tmp',
                '/var/tmp',
                os.path.expanduser('~/.cache'),
            ]
            locations = [d for d in locations if os.path.isdir(d)]
        
        return list(set(locations))  # Remove duplicates
    
    @staticmethod
    def _get_browser_cache_locations() -> List[str]:
        """Get browser cache locations."""
        home = os.path.expanduser("~")
        locations = []
        
        if platform.system() == "Windows":
            appdata = os.environ.get('LOCALAPPDATA', '')
            
            browser_caches = [
                os.path.join(appdata, 'Google', 'Chrome', 'User Data', 'Default', 'Cache'),
                os.path.join(appdata, 'Mozilla', 'Firefox', 'Profiles'),
                os.path.join(appdata, 'Microsoft', 'Edge', 'User Data', 'Default', 'Cache'),
                os.path.join(appdata, 'BraveSoftware', 'Brave-Browser', 'User Data', 'Default', 'Cache'),
            ]
            
        else:  # Linux/Mac
            if platform.system() == "Darwin":  # macOS
                base = os.path.join(home, 'Library', 'Caches')
            else:  # Linux
                base = os.path.join(home, '.cache')
            
            browser_caches = [
                os.path.join(base, 'google-chrome'),
                os.path.join(base, 'chromium'),
                os.path.join(base, 'mozilla'),
                os.path.join(base, 'BraveSoftware'),
            ]
        
        locations = [d for d in browser_caches if os.path.isdir(d)]
        return locations
    
    @staticmethod
    def _get_folder_size(path: str) -> int:
        """Calculate total size of a folder."""
        total = 0
        try:
            for dirpath, dirnames, filenames in os.walk(path):
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    try:
                        total += os.path.getsize(filepath)
                    except:
                        pass
        except:
            pass
        return total
    
    @staticmethod
    def scan_junk() -> JunkScanResult:
        """
        Scan for junk files.
        
        Returns:
            JunkScanResult with details about found junk
        """
        result = JunkScanResult()
        
        # Scan temp folders
        for temp_dir in SystemCleaner._get_temp_locations():
            size = SystemCleaner._get_folder_size(temp_dir)
            if size > 0:
                result.locations[temp_dir] = size
                result.total_size += size
                result.temp_files += 1
        
        # Scan browser caches
        for cache_dir in SystemCleaner._get_browser_cache_locations():
            size = SystemCleaner._get_folder_size(cache_dir)
            if size > 0:
                result.locations[cache_dir] = size
                result.total_size += size
                result.cache_files += 1
        
        # Scan thumbnail cache (Linux)
        if platform.system() != "Windows":
            thumb_cache = os.path.expanduser("~/.cache/thumbnails")
            if os.path.isdir(thumb_cache):
                size = SystemCleaner._get_folder_size(thumb_cache)
                if size > 0:
                    result.locations[thumb_cache] = size
                    result.total_size += size
        
        return result
    
    @staticmethod
    def clean_junk(progress_callback=None) -> Tuple[bool, str, int]:
        """
        Clean junk files.
        
        Args:
            progress_callback: Optional callback(current, total, message)
            
        Returns:
            Tuple of (success, message, bytes_freed)
        """
        scan_result = SystemCleaner.scan_junk()
        bytes_freed = 0
        errors = []
        
        locations = list(scan_result.locations.keys())
        total = len(locations)
        
        for i, location in enumerate(locations):
            if progress_callback:
                progress_callback(i, total, f"Cleaning {os.path.basename(location)}...")
            
            try:
                # For temp folders, delete contents but not the folder itself
                if 'Temp' in location or 'tmp' in location.lower():
                    for item in os.listdir(location):
                        item_path = os.path.join(location, item)
                        try:
                            if os.path.isfile(item_path):
                                size = os.path.getsize(item_path)
                                os.remove(item_path)
                                bytes_freed += size
                            elif os.path.isdir(item_path):
                                size = SystemCleaner._get_folder_size(item_path)
                                shutil.rmtree(item_path, ignore_errors=True)
                                bytes_freed += size
                        except:
                            pass
                
                # For cache folders, try to clear contents
                elif 'cache' in location.lower() or 'Cache' in location:
                    for item in os.listdir(location):
                        item_path = os.path.join(location, item)
                        try:
                            if os.path.isfile(item_path):
                                size = os.path.getsize(item_path)
                                os.remove(item_path)
                                bytes_freed += size
                            elif os.path.isdir(item_path):
                                size = SystemCleaner._get_folder_size(item_path)
                                shutil.rmtree(item_path, ignore_errors=True)
                                bytes_freed += size
                        except:
                            pass
                            
            except PermissionError:
                errors.append(f"Access denied: {location}")
            except Exception as e:
                errors.append(f"{location}: {str(e)}")
        
        if progress_callback:
            progress_callback(total, total, "Cleanup complete!")
        
        # Format freed space
        if bytes_freed < 1024:
            freed_str = f"{bytes_freed} B"
        elif bytes_freed < 1024 * 1024:
            freed_str = f"{bytes_freed / 1024:.1f} KB"
        elif bytes_freed < 1024 * 1024 * 1024:
            freed_str = f"{bytes_freed / (1024 * 1024):.1f} MB"
        else:
            freed_str = f"{bytes_freed / (1024 * 1024 * 1024):.2f} GB"
        
        if errors:
            return (True, f"Cleaned {freed_str} ({len(errors)} errors)", bytes_freed)
        else:
            return (True, f"Cleaned {freed_str}", bytes_freed)
    
    @staticmethod
    def get_disk_usage() -> Dict[str, float]:
        """Get disk usage statistics."""
        try:
            if platform.system() == "Windows":
                path = "C:\\"
            else:
                path = "/"
            
            usage = shutil.disk_usage(path)
            
            return {
                'total_gb': usage.total / (1024 ** 3),
                'used_gb': usage.used / (1024 ** 3),
                'free_gb': usage.free / (1024 ** 3),
                'percent_used': (usage.used / usage.total) * 100
            }
        except:
            return {}
