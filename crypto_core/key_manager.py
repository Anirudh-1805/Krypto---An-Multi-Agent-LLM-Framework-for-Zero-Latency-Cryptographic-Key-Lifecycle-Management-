"""
Key Manager Module

Central Key Management API that applications use to request cryptographic operations.
This is the ONLY interface applications should use for cryptography.

Key principles:
- Private keys NEVER leave this module
- Applications only receive operation results, never key material
- All operations are logged for monitoring
"""

import uuid
from datetime import datetime
from typing import Optional, Dict, Any, Tuple
from enum import Enum
from .crypto_operations import CryptoOperations
from .kms_backend import KMSBackend, InMemoryBackend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec


class KeyAlgorithm(Enum):
    """Supported key algorithms."""
    AES_GCM = "AES-GCM"
    RSA = "RSA"
    ECDSA = "ECDSA"


class KeyMetadata:
    """Metadata about a cryptographic key (no private material)."""
    
    def __init__(self, key_id: str, algorithm: KeyAlgorithm, created_at: datetime):
        self.key_id = key_id
        self.algorithm = algorithm
        self.created_at = created_at
        self.usage_count = 0
        self.last_used = None
        self.is_revoked = False
        self.is_rotated = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to dictionary for logging/monitoring."""
        return {
            'key_id': self.key_id,
            'algorithm': self.algorithm.value,
            'created_at': self.created_at.isoformat(),
            'usage_count': self.usage_count,
            'last_used': self.last_used.isoformat() if self.last_used else None,
            'is_revoked': self.is_revoked,
            'is_rotated': self.is_rotated
        }


class KeyManager:
    """
    Central Key Management API.
    
    Applications request cryptographic operations through this interface.
    Private keys are stored internally and never exposed.
    """
    
    def __init__(self, backend: Optional[KMSBackend] = None):
        # Use dependency injection for backend, default to InMemoryBackend
        self._backend = backend if backend else InMemoryBackend()
        
        # Metadata cache: key_id -> KeyMetadata
        self._metadata_cache: Dict[str, KeyMetadata] = {}
        self._operation_log: list = []
    
    def generate_key(self, algorithm: KeyAlgorithm, key_id: Optional[str] = None) -> str:
        """
        Generate a new cryptographic key.
        
        Args:
            algorithm: The algorithm to use (AES_GCM, RSA, or ECDSA)
            key_id: Optional custom key ID. If None, a UUID is generated.
        
        Returns:
            The key ID (for future operations)
        """
        if key_id is None:
            key_id = str(uuid.uuid4())
        
        if key_id in self._metadata_cache:
            raise ValueError(f"Key ID {key_id} already exists")
        
        created_at = datetime.now()
        
        if algorithm == KeyAlgorithm.AES_GCM:
            key_material = CryptoOperations.generate_aes_key()
        elif algorithm == KeyAlgorithm.RSA:
            private_key, public_key = CryptoOperations.generate_rsa_key_pair()
            key_material = (private_key, public_key)
        elif algorithm == KeyAlgorithm.ECDSA:
            private_key, public_key = CryptoOperations.generate_ecdsa_key_pair()
            key_material = (private_key, public_key)
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        metadata = KeyMetadata(key_id, algorithm, created_at)
        
        # Serialize key material for storage
        if algorithm == KeyAlgorithm.AES_GCM:
            # AES keys are already bytes
            key_data = key_material
        else:
            # Asymmetric keys: serialize to PEM format
            private_key, public_key = key_material
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            # Store as tuple of (private_pem, public_pem, algorithm_name)
            key_data = (private_pem, public_pem, algorithm.value)
        
        self._backend.store_key(key_id, key_data, metadata.to_dict())
        self._metadata_cache[key_id] = metadata
        
        self._log_operation('key_generated', {
            'key_id': key_id,
            'algorithm': algorithm.value
        })
        
        return key_id
    
    def encrypt(self, key_id: str, plaintext: bytes, associated_data: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Encrypt plaintext using the specified key.
        
        Args:
            key_id: The key to use
            plaintext: Data to encrypt
            associated_data: Optional associated data for AES-GCM
        
        Returns:
            Tuple of (ciphertext, nonce)
        """
        if key_id not in self._metadata_cache:
            raise ValueError(f"Key {key_id} not found")
        
        metadata = self._metadata_cache[key_id]
        key_data = self._backend.retrieve_key(key_id)
        if not key_data:
            raise ValueError(f"Key material for {key_id} not found in backend")
        
        # AES keys are stored as raw bytes
        key_material = key_data
        
        if metadata.is_revoked:
            raise ValueError(f"Key {key_id} is revoked")
        
        if metadata.algorithm != KeyAlgorithm.AES_GCM:
            raise ValueError(f"Key {key_id} is not an AES-GCM key")
        
        ciphertext, nonce = CryptoOperations.aes_encrypt(key_material, plaintext, associated_data)
        
        metadata.usage_count += 1
        metadata.last_used = datetime.now()
        
        self._log_operation('encrypt', {
            'key_id': key_id,
            'plaintext_length': len(plaintext),
            'success': True
        })
        
        return ciphertext, nonce
    
    def decrypt(self, key_id: str, ciphertext: bytes, nonce: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """
        Decrypt ciphertext using the specified key.
        
        Args:
            key_id: The key to use
            ciphertext: Encrypted data
            nonce: Nonce used during encryption
            associated_data: Optional associated data for AES-GCM
        
        Returns:
            Decrypted plaintext
        """
        if key_id not in self._metadata_cache:
            raise ValueError(f"Key {key_id} not found")
        
        metadata = self._metadata_cache[key_id]
        key_data = self._backend.retrieve_key(key_id)
        if not key_data:
            raise ValueError(f"Key material for {key_id} not found in backend")
        
        # AES keys are stored as raw bytes
        key_material = key_data
        
        if metadata.is_revoked:
            raise ValueError(f"Key {key_id} is revoked")
        
        if metadata.algorithm != KeyAlgorithm.AES_GCM:
            raise ValueError(f"Key {key_id} is not an AES-GCM key")
        
        try:
            plaintext = CryptoOperations.aes_decrypt(key_material, ciphertext, nonce, associated_data)
            
            metadata.usage_count += 1
            metadata.last_used = datetime.now()
            
            self._log_operation('decrypt', {
                'key_id': key_id,
                'ciphertext_length': len(ciphertext),
                'success': True
            })
            
            return plaintext
        except Exception as e:
            self._log_operation('decrypt', {
                'key_id': key_id,
                'ciphertext_length': len(ciphertext),
                'success': False,
                'error': str(e)
            })
            raise
    
    def sign(self, key_id: str, message: bytes) -> bytes:
        """
        Sign a message using the specified key.
        
        Args:
            key_id: The key to use
            message: Message to sign
        
        Returns:
            Signature bytes
        """
        if key_id not in self._metadata_cache:
            raise ValueError(f"Key {key_id} not found")
        
        metadata = self._metadata_cache[key_id]
        key_data = self._backend.retrieve_key(key_id)
        if not key_data:
            raise ValueError(f"Key material for {key_id} not found in backend")
        
        # Deserialize asymmetric key from PEM
        private_pem, public_pem, alg_name = key_data
        private_key = serialization.load_pem_private_key(
            private_pem, password=None, backend=default_backend()
        )
        public_key = serialization.load_pem_public_key(
            public_pem, backend=default_backend()
        )
        key_material = (private_key, public_key)
        
        if metadata.is_revoked:
            raise ValueError(f"Key {key_id} is revoked")
        
        if metadata.algorithm not in (KeyAlgorithm.RSA, KeyAlgorithm.ECDSA):
            raise ValueError(f"Key {key_id} is not a signing key")
        
        private_key, _ = key_material
        
        if metadata.algorithm == KeyAlgorithm.RSA:
            signature = CryptoOperations.rsa_sign(private_key, message)
        else:  # ECDSA
            signature = CryptoOperations.ecdsa_sign(private_key, message)
        
        metadata.usage_count += 1
        metadata.last_used = datetime.now()
        
        self._log_operation('sign', {
            'key_id': key_id,
            'message_length': len(message),
            'success': True
        })
        
        return signature
    
    def verify(self, key_id: str, message: bytes, signature: bytes) -> bool:
        """
        Verify a signature using the specified key.
        
        Args:
            key_id: The key to use
            message: Original message
            signature: Signature to verify
        
        Returns:
            True if signature is valid, False otherwise
        """
        if key_id not in self._metadata_cache:
            raise ValueError(f"Key {key_id} not found")
        
        metadata = self._metadata_cache[key_id]
        key_data = self._backend.retrieve_key(key_id)
        if not key_data:
            raise ValueError(f"Key material for {key_id} not found in backend")
        
        # Deserialize asymmetric key from PEM
        private_pem, public_pem, alg_name = key_data
        private_key = serialization.load_pem_private_key(
            private_pem, password=None, backend=default_backend()
        )
        public_key = serialization.load_pem_public_key(
            public_pem, backend=default_backend()
        )
        key_material = (private_key, public_key)
        
        if metadata.is_revoked:
            return False
        
        if metadata.algorithm not in (KeyAlgorithm.RSA, KeyAlgorithm.ECDSA):
            raise ValueError(f"Key {key_id} is not a signing key")
        
        _, public_key = key_material
        
        if metadata.algorithm == KeyAlgorithm.RSA:
            result = CryptoOperations.rsa_verify(public_key, message, signature)
        else:  # ECDSA
            result = CryptoOperations.ecdsa_verify(public_key, message, signature)
        
        metadata.usage_count += 1
        metadata.last_used = datetime.now()
        
        self._log_operation('verify', {
            'key_id': key_id,
            'message_length': len(message),
            'success': result
        })
        
        return result
    
    def get_key_metadata(self, key_id: str) -> Optional[KeyMetadata]:
        """Get metadata for a key (no private material)."""
        return self._metadata_cache.get(key_id)
    
    def get_all_key_metadata(self) -> list:
        """Get metadata for all keys (for monitoring)."""
        return [metadata.to_dict() for metadata in self._metadata_cache.values()]
    
    def get_operation_log(self) -> list:
        """Get the operation log (for monitoring)."""
        return self._operation_log.copy()
    
    def _log_operation(self, operation: str, details: Dict[str, Any]):
        """Internal method to log operations."""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'operation': operation,
            **details
        }
        self._operation_log.append(log_entry)
    
    # Internal methods for future key lifecycle management (not exposed to applications)
    def _revoke_key(self, key_id: str):
        """Revoke a key (internal use only, for Key Action Agent)."""
        if key_id in self._metadata_cache:
            metadata = self._metadata_cache[key_id]
            metadata.is_revoked = True
            self._log_operation('key_revoked', {'key_id': key_id})
    
    def _rotate_key(self, key_id: str, new_key_id: str):
        """Rotate a key (internal use only, for Key Action Agent)."""
        if key_id in self._metadata_cache:
            metadata = self._metadata_cache[key_id]
            metadata.is_rotated = True
            self._log_operation('key_rotated', {
                'old_key_id': key_id,
                'new_key_id': new_key_id
            })

