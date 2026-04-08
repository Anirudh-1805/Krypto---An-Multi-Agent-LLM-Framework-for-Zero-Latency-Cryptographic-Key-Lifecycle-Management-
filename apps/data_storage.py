"""
Data Storage Service Application

Simulates a data storage service that encrypts sensitive data at rest.
Demonstrates misuse patterns:
- Uses a single encryption key for all data
- Excessive repeated encryption/decryption operations
- Never checks key age or usage patterns
"""

import logging
from datetime import datetime
from typing import Dict, Optional
from crypto_core.key_manager import KeyManager, KeyAlgorithm


logger = logging.getLogger(__name__)


class DataStorageService:
    """
    Simulated data storage service that encrypts data at rest.
    
    Misuse patterns:
    - Uses one encryption key for ALL data (no key per record/table)
    - Encrypts/decrypts frequently without considering key rotation
    - Hardcoded key ID (static configuration)
    """
    
    def __init__(self, key_manager: KeyManager, service_name: str = "data-storage"):
        self.key_manager = key_manager
        self.service_name = service_name
        self.encryption_key_id: Optional[str] = None
        self.stored_data: Dict[str, tuple] = {}  # record_id -> (ciphertext, nonce)
        self.operation_count = 0
        
        # MISUSE PATTERN: Static key ID - same key for everything
        self._static_key_id = f"{service_name}-encryption-key-v1"
        
        logger.info(f"[{self.service_name}] Initializing data storage service")
        self._initialize_key()
    
    def _initialize_key(self):
        """Initialize the encryption key (only called once at startup)."""
        # MISUSE PATTERN: Create key once, use forever for all data
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
    
    def store_data(self, record_id: str, data: bytes) -> bool:
        """
        Store encrypted data.
        
        Args:
            record_id: Unique identifier for the record
            data: Plaintext data to encrypt and store
        
        Returns:
            True if successful
        """
        self.operation_count += 1
        
        # MISUSE PATTERN: Use same key for all records, no matter how many
        ciphertext, nonce = self.key_manager.encrypt(
            self.encryption_key_id,
            data,
            associated_data=record_id.encode('utf-8')
        )
        
        self.stored_data[record_id] = (ciphertext, nonce)
        
        logger.info(
            f"[{self.service_name}] Stored record {record_id} "
            f"(operation #{self.operation_count}, key: {self.encryption_key_id})"
        )
        
        return True
    
    def retrieve_data(self, record_id: str) -> Optional[bytes]:
        """
        Retrieve and decrypt data.
        
        Args:
            record_id: Unique identifier for the record
        
        Returns:
            Decrypted plaintext data, or None if not found
        """
        if record_id not in self.stored_data:
            logger.warning(f"[{self.service_name}] Record {record_id} not found")
            return None
        
        self.operation_count += 1
        
        ciphertext, nonce = self.stored_data[record_id]
        
        # MISUSE PATTERN: Decrypt using same old key, never checks if key should be rotated
        try:
            plaintext = self.key_manager.decrypt(
                self.encryption_key_id,
                ciphertext,
                nonce,
                associated_data=record_id.encode('utf-8')
            )
            
            logger.info(
                f"[{self.service_name}] Retrieved record {record_id} "
                f"(operation #{self.operation_count}, key: {self.encryption_key_id})"
            )
            
            return plaintext
        except Exception as e:
            logger.error(f"[{self.service_name}] Failed to decrypt record {record_id}: {e}")
            return None
    
    def list_records(self) -> list:
        """List all stored record IDs."""
        return list(self.stored_data.keys())
    
    def get_stats(self) -> dict:
        """Get service statistics."""
        metadata = self.key_manager.get_key_metadata(self.encryption_key_id)
        return {
            'service_name': self.service_name,
            'key_id': self.encryption_key_id,
            'operation_count': self.operation_count,
            'stored_records': len(self.stored_data),
            'key_usage_count': metadata.usage_count if metadata else 0,
            'key_created_at': metadata.created_at.isoformat() if metadata else None,
            'key_age_days': (
                (datetime.now() - metadata.created_at).days if metadata else None
            )
        }

