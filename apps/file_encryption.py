"""
File Encryption Service Application

Simulates a file encryption service that encrypts files before storage.
Demonstrates misuse patterns:
- Uses a single key for all files
- Encrypts files in batch operations (excessive usage spikes)
- Never rotates keys even after many operations
"""

import logging
from datetime import datetime
from typing import Dict, Optional
from crypto_core.key_manager import KeyManager, KeyAlgorithm


logger = logging.getLogger(__name__)


class FileEncryptionService:
    """
    Simulated file encryption service.
    
    Misuse patterns:
    - Uses one key for ALL files
    - Performs batch operations that cause usage spikes
    - Never checks key age before encrypting many files
    """
    
    def __init__(self, key_manager: KeyManager, service_name: str = "file-encryption"):
        self.key_manager = key_manager
        self.service_name = service_name
        self.encryption_key_id: Optional[str] = None
        self.encrypted_files: Dict[str, tuple] = {}  # filename -> (ciphertext, nonce)
        self.operation_count = 0
        
        # MISUSE PATTERN: Static key ID
        self._static_key_id = f"{service_name}-file-key-v1"
        
        logger.info(f"[{self.service_name}] Initializing file encryption service")
        self._initialize_key()
    
    def _initialize_key(self):
        """Initialize the encryption key (only called once at startup)."""
        # MISUSE PATTERN: Create key once, use forever
        try:
            metadata = self.key_manager.get_key_metadata(self._static_key_id)
            if metadata and not metadata.is_revoked:
                self.encryption_key_id = self._static_key_id
                logger.info(f"[{self.service_name}] Reusing existing encryption key: {self.encryption_key_id}")
                return
        except:
            pass
        
        self.encryption_key_id = self.key_manager.generate_key(
            KeyAlgorithm.AES_GCM,
            key_id=self._static_key_id
        )
        logger.info(f"[{self.service_name}] Created new encryption key: {self.encryption_key_id}")
    
    def encrypt_file(self, filename: str, file_content: bytes) -> bool:
        """
        Encrypt a file.
        
        Args:
            filename: Name of the file
            file_content: Plaintext file content
        
        Returns:
            True if successful
        """
        self.operation_count += 1
        
        # MISUSE PATTERN: Use same key for all files
        ciphertext, nonce = self.key_manager.encrypt(
            self.encryption_key_id,
            file_content,
            associated_data=filename.encode('utf-8')
        )
        
        self.encrypted_files[filename] = (ciphertext, nonce)
        
        logger.info(
            f"[{self.service_name}] Encrypted file {filename} "
            f"(operation #{self.operation_count}, key: {self.encryption_key_id})"
        )
        
        return True
    
    def decrypt_file(self, filename: str) -> Optional[bytes]:
        """
        Decrypt a file.
        
        Args:
            filename: Name of the file
        
        Returns:
            Decrypted file content, or None if not found
        """
        if filename not in self.encrypted_files:
            logger.warning(f"[{self.service_name}] File {filename} not found")
            return None
        
        self.operation_count += 1
        
        ciphertext, nonce = self.encrypted_files[filename]
        
        try:
            plaintext = self.key_manager.decrypt(
                self.encryption_key_id,
                ciphertext,
                nonce,
                associated_data=filename.encode('utf-8')
            )
            
            logger.info(
                f"[{self.service_name}] Decrypted file {filename} "
                f"(operation #{self.operation_count}, key: {self.encryption_key_id})"
            )
            
            return plaintext
        except Exception as e:
            logger.error(f"[{self.service_name}] Failed to decrypt file {filename}: {e}")
            return None
    
    def encrypt_files_batch(self, files: Dict[str, bytes]) -> int:
        """
        Encrypt multiple files in a batch operation.
        
        MISUSE PATTERN: This causes a spike in key usage without any checks.
        
        Args:
            files: Dictionary of filename -> content
        
        Returns:
            Number of files successfully encrypted
        """
        success_count = 0
        
        logger.info(f"[{self.service_name}] Starting batch encryption of {len(files)} files")
        
        for filename, content in files.items():
            if self.encrypt_file(filename, content):
                success_count += 1
        
        logger.info(
            f"[{self.service_name}] Batch encryption complete: "
            f"{success_count}/{len(files)} files encrypted "
            f"(key usage spike: {len(files)} operations on key {self.encryption_key_id})"
        )
        
        return success_count
    
    def list_files(self) -> list:
        """List all encrypted filenames."""
        return list(self.encrypted_files.keys())
    
    def get_stats(self) -> dict:
        """Get service statistics."""
        metadata = self.key_manager.get_key_metadata(self.encryption_key_id)
        return {
            'service_name': self.service_name,
            'key_id': self.encryption_key_id,
            'operation_count': self.operation_count,
            'encrypted_files': len(self.encrypted_files),
            'key_usage_count': metadata.usage_count if metadata else 0,
            'key_created_at': metadata.created_at.isoformat() if metadata else None,
            'key_age_days': (
                (datetime.now() - metadata.created_at).days if metadata else None
            )
        }

