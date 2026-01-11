"""
RafSec Engine - Steganography Hunter
=====================================
Detect hidden data in images.

Author: RafSec Team
"""

import os
from typing import Tuple, Dict


class StegoHunter:
    """
    Detect steganography (hidden data) in image files.
    
    Checks for trailing data after image EOF markers,
    which is a common steganography technique.
    """
    
    # End-of-file markers for different formats
    EOF_MARKERS = {
        'jpeg': b'\xff\xd9',
        'png': b'\x49\x45\x4e\x44\xae\x42\x60\x82',  # IEND chunk
        'gif': b'\x00\x3b',  # GIF trailer
    }
    
    # Magic bytes for format detection
    MAGIC_BYTES = {
        'jpeg': [b'\xff\xd8\xff'],
        'png': [b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a'],
        'gif': [b'\x47\x49\x46\x38\x37\x61', b'\x47\x49\x46\x38\x39\x61'],
    }
    
    @staticmethod
    def detect_format(data: bytes) -> str:
        """Detect image format from magic bytes."""
        for fmt, patterns in StegoHunter.MAGIC_BYTES.items():
            for pattern in patterns:
                if data.startswith(pattern):
                    return fmt
        return 'unknown'
    
    @staticmethod
    def scan_image(image_path: str) -> Tuple[bool, Dict]:
        """
        Scan an image for hidden data.
        
        Args:
            image_path: Path to image file
            
        Returns:
            Tuple of (suspicious, details_dict)
        """
        if not os.path.exists(image_path):
            return (False, {'error': 'File not found'})
        
        try:
            with open(image_path, 'rb') as f:
                data = f.read()
        except Exception as e:
            return (False, {'error': str(e)})
        
        # Detect format
        fmt = StegoHunter.detect_format(data)
        
        if fmt == 'unknown':
            return (False, {'error': 'Unknown image format'})
        
        # Find EOF marker
        eof_marker = StegoHunter.EOF_MARKERS.get(fmt)
        
        if not eof_marker:
            return (False, {'format': fmt, 'error': 'No EOF marker defined'})
        
        # Find last occurrence of EOF marker
        eof_pos = data.rfind(eof_marker)
        
        if eof_pos == -1:
            return (False, {
                'format': fmt,
                'suspicious': False,
                'note': 'EOF marker not found (corrupted?)'
            })
        
        # Check for trailing data after EOF
        eof_end = eof_pos + len(eof_marker)
        trailing_data = data[eof_end:]
        trailing_size = len(trailing_data)
        
        # Ignore small trailing (padding, metadata)
        if trailing_size <= 16:
            return (False, {
                'format': fmt,
                'eof_position': eof_end,
                'file_size': len(data),
                'trailing_bytes': trailing_size,
                'suspicious': False
            })
        
        # Suspicious if significant trailing data
        return (True, {
            'format': fmt,
            'eof_position': eof_end,
            'file_size': len(data),
            'trailing_bytes': trailing_size,
            'suspicious': True,
            'message': f'Found {trailing_size} bytes after EOF marker!',
            'preview': trailing_data[:64].hex() if trailing_data else ''
        })
    
    @staticmethod
    def extract_hidden_data(image_path: str, output_path: str) -> Tuple[bool, str]:
        """
        Extract hidden data from an image.
        
        Args:
            image_path: Path to suspicious image
            output_path: Path to save extracted data
            
        Returns:
            Tuple of (success, message)
        """
        suspicious, details = StegoHunter.scan_image(image_path)
        
        if not suspicious:
            return (False, "No hidden data detected")
        
        eof_end = details.get('eof_position', 0)
        
        try:
            with open(image_path, 'rb') as f:
                f.seek(eof_end)
                hidden = f.read()
            
            with open(output_path, 'wb') as f:
                f.write(hidden)
            
            return (True, f"Extracted {len(hidden)} bytes to {output_path}")
            
        except Exception as e:
            return (False, str(e))
    
    @staticmethod
    def is_supported(filename: str) -> bool:
        """Check if file type is supported."""
        ext = os.path.splitext(filename)[1].lower()
        return ext in ['.jpg', '.jpeg', '.png', '.gif']
