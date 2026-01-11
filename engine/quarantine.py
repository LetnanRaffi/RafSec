"""
RafSec Engine - Quarantine Manager
===================================
Isolate suspicious files safely.

Author: RafSec Team
"""

import os
import shutil
from typing import List, Tuple, Optional
from datetime import datetime


class QuarantineManager:
    """
    Manage quarantined (isolated) files.
    
    Files are moved to a secure quarantine folder and
    can be restored or permanently deleted.
    """
    
    QUARANTINE_DIR = "quarantine"
    
    def __init__(self, base_dir: str = None):
        """
        Initialize quarantine manager.
        
        Args:
            base_dir: Base directory for quarantine folder
        """
        if base_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        self.quarantine_path = os.path.join(base_dir, self.QUARANTINE_DIR)
        self._ensure_dir()
    
    def _ensure_dir(self):
        """Ensure quarantine directory exists."""
        if not os.path.exists(self.quarantine_path):
            os.makedirs(self.quarantine_path)
    
    def quarantine_file(self, file_path: str, config_manager=None) -> Tuple[bool, str]:
        """
        Move a file to quarantine.
        
        Args:
            file_path: Path to file to quarantine
            config_manager: Optional ConfigManager to log original path
            
        Returns:
            Tuple of (success, message)
        """
        if not os.path.exists(file_path):
            return (False, "File not found")
        
        try:
            # Generate unique quarantine name
            original_name = os.path.basename(file_path)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            quarantine_name = f"{timestamp}_{original_name}.quarantine"
            quarantine_dest = os.path.join(self.quarantine_path, quarantine_name)
            
            # Move file
            shutil.move(file_path, quarantine_dest)
            
            # Log original path if config manager provided
            if config_manager:
                config_manager.add_to_quarantine_log(quarantine_name, file_path)
            
            return (True, f"Quarantined: {quarantine_name}")
            
        except PermissionError:
            return (False, "Access denied - file may be in use")
        except Exception as e:
            return (False, f"Failed: {str(e)}")
    
    def restore_file(self, quarantine_name: str, config_manager=None) -> Tuple[bool, str]:
        """
        Restore a quarantined file to its original location.
        
        Args:
            quarantine_name: Name of quarantined file
            config_manager: Optional ConfigManager to get original path
            
        Returns:
            Tuple of (success, message)
        """
        quarantine_path = os.path.join(self.quarantine_path, quarantine_name)
        
        if not os.path.exists(quarantine_path):
            return (False, "Quarantined file not found")
        
        # Get original path
        original_path = None
        if config_manager:
            original_path = config_manager.get_original_path(quarantine_name)
        
        if not original_path:
            # Try to extract from filename
            # Format: YYYYMMDD_HHMMSS_originalname.quarantine
            parts = quarantine_name.split('_', 2)
            if len(parts) >= 3:
                original_name = parts[2].replace('.quarantine', '')
                original_path = os.path.join(os.path.expanduser("~"), "Desktop", original_name)
            else:
                return (False, "Cannot determine original path")
        
        try:
            # Ensure destination directory exists
            dest_dir = os.path.dirname(original_path)
            if not os.path.exists(dest_dir):
                os.makedirs(dest_dir)
            
            # Handle name collision
            if os.path.exists(original_path):
                base, ext = os.path.splitext(original_path)
                counter = 1
                while os.path.exists(original_path):
                    original_path = f"{base}_restored_{counter}{ext}"
                    counter += 1
            
            # Move file back
            shutil.move(quarantine_path, original_path)
            
            # Clean up log
            if config_manager:
                config_manager.remove_from_quarantine_log(quarantine_name)
            
            return (True, f"Restored to: {original_path}")
            
        except Exception as e:
            return (False, f"Restore failed: {str(e)}")
    
    def delete_permanently(self, quarantine_name: str, config_manager=None) -> Tuple[bool, str]:
        """
        Permanently delete a quarantined file.
        
        Args:
            quarantine_name: Name of quarantined file
            config_manager: Optional ConfigManager to clean up log
            
        Returns:
            Tuple of (success, message)
        """
        quarantine_path = os.path.join(self.quarantine_path, quarantine_name)
        
        if not os.path.exists(quarantine_path):
            return (False, "File not found")
        
        try:
            os.remove(quarantine_path)
            
            if config_manager:
                config_manager.remove_from_quarantine_log(quarantine_name)
            
            return (True, "Permanently deleted")
            
        except Exception as e:
            return (False, f"Delete failed: {str(e)}")
    
    def list_quarantined(self) -> List[dict]:
        """
        List all quarantined files.
        
        Returns:
            List of dicts with file info
        """
        self._ensure_dir()
        files = []
        
        for filename in os.listdir(self.quarantine_path):
            filepath = os.path.join(self.quarantine_path, filename)
            
            if os.path.isfile(filepath):
                # Parse info from filename
                parts = filename.split('_', 2)
                
                if len(parts) >= 3:
                    date_str = parts[0]
                    time_str = parts[1]
                    original = parts[2].replace('.quarantine', '')
                    
                    try:
                        quarantine_date = datetime.strptime(
                            f"{date_str}_{time_str}", "%Y%m%d_%H%M%S"
                        ).strftime("%Y-%m-%d %H:%M")
                    except:
                        quarantine_date = "Unknown"
                else:
                    original = filename
                    quarantine_date = "Unknown"
                
                files.append({
                    'name': filename,
                    'original_name': original,
                    'date': quarantine_date,
                    'size': os.path.getsize(filepath),
                    'path': filepath
                })
        
        # Sort by date (newest first)
        files.sort(key=lambda x: x['name'], reverse=True)
        
        return files
    
    def get_count(self) -> int:
        """Get number of quarantined files."""
        return len(self.list_quarantined())
    
    def get_total_size(self) -> int:
        """Get total size of quarantined files in bytes."""
        return sum(f['size'] for f in self.list_quarantined())
    
    def clear_all(self, config_manager=None) -> Tuple[bool, int]:
        """
        Delete all quarantined files.
        
        Returns:
            Tuple of (success, count_deleted)
        """
        files = self.list_quarantined()
        count = 0
        
        for f in files:
            success, _ = self.delete_permanently(f['name'], config_manager)
            if success:
                count += 1
        
        return (True, count)
