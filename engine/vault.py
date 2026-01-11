"""
RafSec Engine - File Vault (Encryption)
========================================
Secure file encryption using AES-256 via Fernet.

Author: RafSec Team
"""

import os
import base64
import hashlib
from typing import Tuple

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


class FileVault:
    """
    Encrypt and decrypt files with password protection.
    
    Uses AES-256 encryption via Fernet (symmetric encryption).
    Password is converted to key using PBKDF2 with SHA256.
    
    Encrypted files have .rafenc extension.
    """
    
    EXTENSION = ".rafenc"
    SALT_SIZE = 16
    ITERATIONS = 480000  # OWASP recommended
    
    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        """
        Derive encryption key from password using PBKDF2.
        
        Args:
            password: User password
            salt: Random salt
            
        Returns:
            32-byte key suitable for Fernet
        """
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography library not installed")
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=FileVault.ITERATIONS
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    @staticmethod
    def encrypt_file(file_path: str, password: str, 
                     delete_original: bool = True) -> Tuple[bool, str]:
        """
        Encrypt a file with password.
        
        Args:
            file_path: Path to file to encrypt
            password: Encryption password
            delete_original: Delete original file after encryption
            
        Returns:
            Tuple of (success, message or encrypted_path)
        """
        if not CRYPTO_AVAILABLE:
            return (False, "cryptography library not installed")
        
        if not os.path.exists(file_path):
            return (False, "File not found")
        
        if file_path.endswith(FileVault.EXTENSION):
            return (False, "File is already encrypted")
        
        if len(password) < 4:
            return (False, "Password must be at least 4 characters")
        
        try:
            # Generate random salt
            salt = os.urandom(FileVault.SALT_SIZE)
            
            # Derive key from password
            key = FileVault._derive_key(password, salt)
            fernet = Fernet(key)
            
            # Read original file
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Encrypt data
            encrypted = fernet.encrypt(data)
            
            # Store original filename for decryption
            original_name = os.path.basename(file_path).encode()
            name_length = len(original_name).to_bytes(2, 'big')
            
            # Build encrypted file: [salt(16)] + [name_len(2)] + [name] + [encrypted_data]
            encrypted_path = file_path + FileVault.EXTENSION
            with open(encrypted_path, 'wb') as f:
                f.write(salt)
                f.write(name_length)
                f.write(original_name)
                f.write(encrypted)
            
            # Delete original
            if delete_original:
                os.remove(file_path)
            
            return (True, encrypted_path)
            
        except Exception as e:
            return (False, f"Encryption failed: {str(e)}")
    
    @staticmethod
    def decrypt_file(encrypted_path: str, password: str,
                     delete_encrypted: bool = True) -> Tuple[bool, str]:
        """
        Decrypt an encrypted file.
        
        Args:
            encrypted_path: Path to .rafenc file
            password: Decryption password
            delete_encrypted: Delete encrypted file after decryption
            
        Returns:
            Tuple of (success, message or decrypted_path)
        """
        if not CRYPTO_AVAILABLE:
            return (False, "cryptography library not installed")
        
        if not os.path.exists(encrypted_path):
            return (False, "Encrypted file not found")
        
        if not encrypted_path.endswith(FileVault.EXTENSION):
            return (False, "Not a RafSec encrypted file")
        
        try:
            with open(encrypted_path, 'rb') as f:
                # Read salt
                salt = f.read(FileVault.SALT_SIZE)
                
                # Read original filename
                name_length = int.from_bytes(f.read(2), 'big')
                original_name = f.read(name_length).decode()
                
                # Read encrypted data
                encrypted = f.read()
            
            # Derive key
            key = FileVault._derive_key(password, salt)
            fernet = Fernet(key)
            
            # Decrypt
            try:
                decrypted = fernet.decrypt(encrypted)
            except Exception:
                return (False, "Invalid password")
            
            # Write decrypted file
            output_dir = os.path.dirname(encrypted_path)
            decrypted_path = os.path.join(output_dir, original_name)
            
            # Handle name collision
            if os.path.exists(decrypted_path):
                base, ext = os.path.splitext(original_name)
                counter = 1
                while os.path.exists(decrypted_path):
                    decrypted_path = os.path.join(output_dir, f"{base}_{counter}{ext}")
                    counter += 1
            
            with open(decrypted_path, 'wb') as f:
                f.write(decrypted)
            
            # Delete encrypted file
            if delete_encrypted:
                os.remove(encrypted_path)
            
            return (True, decrypted_path)
            
        except Exception as e:
            return (False, f"Decryption failed: {str(e)}")
    
    @staticmethod
    def is_encrypted(file_path: str) -> bool:
        """Check if file is RafSec encrypted."""
        return file_path.endswith(FileVault.EXTENSION)
    
    @staticmethod
    def get_encrypted_info(encrypted_path: str) -> dict:
        """Get metadata about encrypted file without decrypting."""
        if not os.path.exists(encrypted_path):
            return {}
        
        try:
            with open(encrypted_path, 'rb') as f:
                f.read(FileVault.SALT_SIZE)  # Skip salt
                name_length = int.from_bytes(f.read(2), 'big')
                original_name = f.read(name_length).decode()
            
            return {
                'original_name': original_name,
                'encrypted_size': os.path.getsize(encrypted_path),
                'path': encrypted_path
            }
        except:
            return {}
