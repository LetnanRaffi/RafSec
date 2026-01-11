"""
RafSec Utilities - Helper Functions
====================================
File handling, hashing, entropy calculation, and validation utilities.

Author: RafSec Team
"""

import hashlib
import math
import os
from typing import Optional, Dict, Tuple
from collections import Counter


class FileHasher:
    """
    Compute cryptographic hashes for malware identification.
    
    WHY HASHING IS CRUCIAL FOR MALWARE DETECTION:
    - MD5/SHA256: Creates unique "fingerprints" for files. Malware databases
      store these hashes, so we can instantly identify known threats.
    - Imphash: Hash of the Import Address Table. Malware families often share
      the same imports, so files with matching imphash are likely related.
    """
    
    @staticmethod
    def calculate_md5(file_path: str) -> str:
        """
        Calculate MD5 hash of a file.
        
        MD5 is fast but collision-prone. Used for quick lookups in
        legacy malware databases (VirusTotal, etc).
        """
        hash_md5 = hashlib.md5()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    
    @staticmethod
    def calculate_sha256(file_path: str) -> str:
        """
        Calculate SHA256 hash of a file.
        
        SHA256 is the industry standard for malware identification.
        Collision-resistant and used by all modern AV databases.
        """
        hash_sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    
    @staticmethod
    def calculate_sha1(file_path: str) -> str:
        """Calculate SHA1 hash (legacy, still used by some databases)."""
        hash_sha1 = hashlib.sha1()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hash_sha1.update(chunk)
        return hash_sha1.hexdigest()
    
    @staticmethod
    def calculate_imphash(pe_object) -> Optional[str]:
        """
        Calculate Import Hash (Imphash) from a pefile PE object.
        
        WHY IMPHASH IS POWERFUL:
        - Two completely different looking executables can have the same imphash
          if they use the same DLLs/functions in the same order.
        - This reveals MALWARE FAMILIES: variants of the same malware often
          have identical imphash even if packed differently.
        - Used by threat intelligence teams to link malware campaigns.
        
        Args:
            pe_object: A pefile.PE instance
            
        Returns:
            Imphash string or None if no imports exist
        """
        try:
            return pe_object.get_imphash()
        except Exception:
            return None
    
    @classmethod
    def get_all_hashes(cls, file_path: str, pe_object=None) -> Dict[str, str]:
        """Get all hashes for a file in one call."""
        hashes = {
            'md5': cls.calculate_md5(file_path),
            'sha1': cls.calculate_sha1(file_path),
            'sha256': cls.calculate_sha256(file_path),
        }
        if pe_object:
            hashes['imphash'] = cls.calculate_imphash(pe_object) or 'N/A'
        return hashes


class EntropyCalculator:
    """
    Calculate Shannon entropy to detect packed/encrypted malware.
    
    WHY ENTROPY MATTERS:
    - Normal executables have entropy around 4.5-6.5 (readable strings, 
      structured code, predictable patterns).
    - Packed/encrypted malware has entropy > 7.0 (appears random).
    - Packers like UPX, Themida, VMProtect compress code, raising entropy.
    - If a section has very high entropy, it's likely encrypted payload
      that will be decrypted at runtime (common evasion technique).
    """
    
    @staticmethod
    def calculate(data: bytes) -> float:
        """
        Calculate Shannon entropy of byte data.
        
        Entropy formula: H = -Σ(p(x) * log2(p(x)))
        
        Returns:
            Entropy value from 0 (all same byte) to 8 (perfectly random)
        """
        if not data:
            return 0.0
        
        # Count byte occurrences
        byte_counts = Counter(data)
        total_bytes = len(data)
        
        # Calculate entropy
        entropy = 0.0
        for count in byte_counts.values():
            if count > 0:
                probability = count / total_bytes
                entropy -= probability * math.log2(probability)
        
        return round(entropy, 4)
    
    @staticmethod
    def get_entropy_rating(entropy: float) -> Tuple[str, str]:
        """
        Convert entropy value to human-readable rating.
        
        Returns:
            Tuple of (rating, description)
        """
        if entropy < 1.0:
            return ("VERY_LOW", "Nearly uniform data (suspicious - could be padding)")
        elif entropy < 4.5:
            return ("LOW", "Normal text/code patterns")
        elif entropy < 6.0:
            return ("NORMAL", "Standard executable entropy")
        elif entropy < 7.0:
            return ("ELEVATED", "Could indicate light compression/obfuscation")
        elif entropy < 7.5:
            return ("HIGH", "Likely packed or encrypted content")
        else:
            return ("CRITICAL", "Almost random - strongly indicates encryption/packing")


class FileValidator:
    """Validate files before analysis."""
    
    # Magic bytes for PE files (MZ header)
    PE_MAGIC = b'MZ'
    
    @staticmethod
    def exists(file_path: str) -> bool:
        """Check if file exists."""
        return os.path.exists(file_path)
    
    @staticmethod
    def is_readable(file_path: str) -> bool:
        """Check if file is readable."""
        return os.access(file_path, os.R_OK)
    
    @staticmethod
    def get_file_size(file_path: str) -> int:
        """Get file size in bytes."""
        return os.path.getsize(file_path)
    
    @staticmethod
    def is_pe_file(file_path: str) -> bool:
        """
        Check if file is a valid PE (Portable Executable) file.
        
        PE files start with 'MZ' (0x4D 0x5A) - the DOS header signature.
        This dates back to Mark Zbikowski who designed the DOS executable format.
        """
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(2)
                return magic == FileValidator.PE_MAGIC
        except Exception:
            return False
    
    @classmethod
    def validate_for_analysis(cls, file_path: str) -> Tuple[bool, str]:
        """
        Full validation before analysis.
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not cls.exists(file_path):
            return (False, f"File not found: {file_path}")
        
        if not cls.is_readable(file_path):
            return (False, f"File not readable: {file_path}")
        
        file_size = cls.get_file_size(file_path)
        if file_size == 0:
            return (False, "File is empty")
        
        if file_size < 64:
            return (False, "File too small to be valid PE (< 64 bytes)")
        
        if not cls.is_pe_file(file_path):
            return (False, "Not a valid PE file (missing MZ header)")
        
        return (True, "Validation passed")


class ColorPrinter:
    """ANSI color codes for terminal output (Linux compatible)."""
    
    COLORS = {
        'RED': '\033[91m',
        'GREEN': '\033[92m',
        'YELLOW': '\033[93m',
        'BLUE': '\033[94m',
        'MAGENTA': '\033[95m',
        'CYAN': '\033[96m',
        'WHITE': '\033[97m',
        'BOLD': '\033[1m',
        'RESET': '\033[0m'
    }
    
    @classmethod
    def print_colored(cls, text: str, color: str) -> None:
        """Print colored text to terminal."""
        color_code = cls.COLORS.get(color.upper(), cls.COLORS['WHITE'])
        print(f"{color_code}{text}{cls.COLORS['RESET']}")
    
    @classmethod
    def print_status(cls, status: str, message: str) -> None:
        """Print formatted status message."""
        if status.upper() in ['ERROR', 'CRITICAL', 'DANGER']:
            color = 'RED'
        elif status.upper() in ['WARNING', 'SUSPICIOUS', 'ELEVATED']:
            color = 'YELLOW'
        elif status.upper() in ['OK', 'SAFE', 'CLEAN']:
            color = 'GREEN'
        else:
            color = 'CYAN'
        
        cls.print_colored(f"[{status.upper()}] {message}", color)
