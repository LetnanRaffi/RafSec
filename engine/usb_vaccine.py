"""
RafSec Engine - USB Vaccine
============================
Immunize USB drives against AutoRun malware.

Author: RafSec Team
"""

import os
import platform
import stat
from typing import Tuple, List

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


class USBVaccine:
    """
    Vaccinate USB drives against AutoRun viruses.
    
    Creates protected autorun.inf folder that prevents
    malware from creating malicious autorun files.
    """
    
    @staticmethod
    def get_removable_drives() -> List[str]:
        """
        Get list of removable drives.
        
        Returns:
            List of drive paths (e.g., ["E:/", "F:/"])
        """
        if not PSUTIL_AVAILABLE:
            return []
        
        drives = []
        
        for partition in psutil.disk_partitions(all=False):
            try:
                # Check if removable
                opts = partition.opts.lower() if partition.opts else ""
                
                if platform.system() == "Windows":
                    # On Windows, check fstype and opts
                    if 'removable' in opts or partition.fstype.lower() in ['fat32', 'exfat', 'fat']:
                        # Additional check: drive letter pattern
                        if partition.mountpoint and partition.mountpoint[0] not in ['C', 'c']:
                            drives.append(partition.mountpoint)
                else:
                    # On Linux, check mount point
                    if '/media/' in partition.mountpoint or '/mnt/usb' in partition.mountpoint:
                        drives.append(partition.mountpoint)
                        
            except:
                continue
        
        return drives
    
    @staticmethod
    def vaccinate_drive(drive_path: str) -> Tuple[bool, str]:
        """
        Vaccinate a drive against AutoRun malware.
        
        Creates a protected autorun.inf folder that cannot
        be replaced by a malicious autorun.inf file.
        
        Args:
            drive_path: Root path of drive (e.g., "E:/")
            
        Returns:
            Tuple of (success, message)
        """
        if not os.path.exists(drive_path):
            return (False, "Drive not found")
        
        # Target: autorun.inf folder
        autorun_path = os.path.join(drive_path, "autorun.inf")
        
        # If file exists, try to remove it
        if os.path.isfile(autorun_path):
            try:
                os.remove(autorun_path)
            except PermissionError:
                return (False, "Cannot remove existing autorun.inf file (access denied)")
            except Exception as e:
                return (False, f"Cannot remove existing file: {e}")
        
        # If already a folder, check protection
        if os.path.isdir(autorun_path):
            return (True, "Drive already vaccinated")
        
        try:
            # Create the folder
            os.makedirs(autorun_path)
            
            # Create protected file inside
            protected_file = os.path.join(autorun_path, "protected_by_rafsec.txt")
            with open(protected_file, 'w') as f:
                f.write("This folder protects your drive against AutoRun viruses.\n")
                f.write("Created by RafSec Total Security.\n")
                f.write("DO NOT DELETE.\n")
            
            # Set read-only attributes
            if platform.system() == "Windows":
                try:
                    import ctypes
                    FILE_ATTRIBUTE_READONLY = 0x01
                    FILE_ATTRIBUTE_HIDDEN = 0x02
                    FILE_ATTRIBUTE_SYSTEM = 0x04
                    
                    attrs = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM
                    ctypes.windll.kernel32.SetFileAttributesW(autorun_path, attrs)
                except:
                    pass
            else:
                # Linux: set permissions
                try:
                    os.chmod(autorun_path, stat.S_IRUSR | stat.S_IXUSR)
                except:
                    pass
            
            return (True, f"Drive {drive_path} immunized!")
            
        except PermissionError:
            return (False, "Access denied - try running as administrator")
        except Exception as e:
            return (False, f"Vaccination failed: {e}")
    
    @staticmethod
    def is_vaccinated(drive_path: str) -> bool:
        """Check if drive is already vaccinated."""
        autorun_path = os.path.join(drive_path, "autorun.inf")
        return os.path.isdir(autorun_path)
    
    @staticmethod
    def vaccinate_all() -> List[Tuple[str, bool, str]]:
        """
        Vaccinate all removable drives.
        
        Returns:
            List of (drive, success, message) tuples
        """
        results = []
        
        for drive in USBVaccine.get_removable_drives():
            success, msg = USBVaccine.vaccinate_drive(drive)
            results.append((drive, success, msg))
        
        return results
