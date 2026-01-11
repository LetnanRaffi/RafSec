"""
RafSec Engine - Secure File Shredder
=====================================
Securely delete files beyond recovery.

Author: RafSec Team
"""

import os
import random
from typing import Tuple


class FileShredder:
    """
    Securely delete files by overwriting with random data.
    
    Uses multiple overwrite passes to prevent data recovery
    through forensic tools. Based on Gutmann method principles.
    """
    
    @staticmethod
    def secure_delete(file_path: str, passes: int = 3, 
                      progress_callback=None) -> Tuple[bool, str]:
        """
        Securely delete a file.
        
        Args:
            file_path: Path to file to shred
            passes: Number of overwrite passes (default 3)
            progress_callback: Optional callback(pass_number, total_passes)
            
        Returns:
            Tuple of (success, message)
        """
        if not os.path.exists(file_path):
            return (False, "File not found")
        
        if os.path.isdir(file_path):
            return (False, "Cannot shred directories (use shred_folder)")
        
        try:
            file_size = os.path.getsize(file_path)
            
            # Open file for writing
            with open(file_path, 'r+b') as f:
                for pass_num in range(passes):
                    if progress_callback:
                        progress_callback(pass_num + 1, passes)
                    
                    # Move to beginning
                    f.seek(0)
                    
                    # Overwrite with random data
                    # Process in chunks for large files
                    chunk_size = 1024 * 1024  # 1MB chunks
                    bytes_written = 0
                    
                    while bytes_written < file_size:
                        remaining = file_size - bytes_written
                        size = min(chunk_size, remaining)
                        
                        # Generate random data
                        random_data = os.urandom(size)
                        f.write(random_data)
                        bytes_written += size
                    
                    # Flush to disk
                    f.flush()
                    os.fsync(f.fileno())
            
            # Rename file to obscure original name
            temp_name = os.path.join(
                os.path.dirname(file_path),
                ''.join(random.choices('0123456789abcdef', k=16))
            )
            os.rename(file_path, temp_name)
            
            # Finally delete
            os.remove(temp_name)
            
            return (True, f"File securely deleted ({passes} passes)")
            
        except PermissionError:
            return (False, "Access denied - file may be in use")
        except Exception as e:
            return (False, f"Shred failed: {str(e)}")
    
    @staticmethod
    def shred_folder(folder_path: str, passes: int = 3,
                     progress_callback=None) -> Tuple[bool, str, int]:
        """
        Securely delete all files in a folder.
        
        Args:
            folder_path: Path to folder
            passes: Overwrite passes per file
            progress_callback: Optional callback(current_file, total_files, filename)
            
        Returns:
            Tuple of (success, message, files_shredded)
        """
        if not os.path.exists(folder_path):
            return (False, "Folder not found", 0)
        
        if not os.path.isdir(folder_path):
            return (False, "Not a directory", 0)
        
        # Collect all files
        files = []
        for root, dirs, filenames in os.walk(folder_path):
            for filename in filenames:
                files.append(os.path.join(root, filename))
        
        if not files:
            return (True, "No files to shred", 0)
        
        shredded = 0
        errors = 0
        
        for i, file_path in enumerate(files):
            if progress_callback:
                progress_callback(i + 1, len(files), os.path.basename(file_path))
            
            success, _ = FileShredder.secure_delete(file_path, passes)
            if success:
                shredded += 1
            else:
                errors += 1
        
        # Remove empty directories
        for root, dirs, _ in os.walk(folder_path, topdown=False):
            for dir_name in dirs:
                try:
                    os.rmdir(os.path.join(root, dir_name))
                except:
                    pass
        
        try:
            os.rmdir(folder_path)
        except:
            pass
        
        if errors > 0:
            return (True, f"Shredded {shredded} files ({errors} errors)", shredded)
        else:
            return (True, f"Shredded {shredded} files", shredded)
    
    @staticmethod
    def quick_delete(file_path: str) -> Tuple[bool, str]:
        """
        Quick secure delete with 1 pass.
        
        Args:
            file_path: Path to file
            
        Returns:
            Tuple of (success, message)
        """
        return FileShredder.secure_delete(file_path, passes=1)
    
    @staticmethod
    def dod_delete(file_path: str) -> Tuple[bool, str]:
        """
        DoD 5220.22-M standard delete (7 passes).
        
        Args:
            file_path: Path to file
            
        Returns:
            Tuple of (success, message)
        """
        return FileShredder.secure_delete(file_path, passes=7)
