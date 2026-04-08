"""
Cryptographic Operations Module

Provides standard cryptographic primitives:
- AES-GCM for symmetric encryption
- RSA or ECDSA for asymmetric signing
- HMAC-SHA256 for message authentication
- SHA-256 for hashing

All operations use the cryptography library (standard Python crypto library).
"""

import hashlib
from datetime import datetime
from typing import Optional, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.padding import PSS, MGF1
from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.backends import default_backend
import os


class CryptoOperations:
    """
    Provides cryptographic operations using standard primitives.
    
    This class handles the actual cryptographic work but does NOT store keys.
    Key storage is handled by KeyManager.
    """
    
    @staticmethod
    def generate_aes_key() -> bytes:
        """Generate a 256-bit AES key for AES-GCM."""
        return AESGCM.generate_key(bit_length=256)
    
    @staticmethod
    def generate_rsa_key_pair() -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """Generate an RSA key pair (2048-bit)."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        return private_key, private_key.public_key()
    
    @staticmethod
    def generate_ecdsa_key_pair() -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
        """Generate an ECDSA key pair (P-256 curve)."""
        private_key = ec.generate_private_key(
            ec.SECP256R1(),
            backend=default_backend()
        )
        return private_key, private_key.public_key()
    
    @staticmethod
    def aes_encrypt(key: bytes, plaintext: bytes, associated_data: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Encrypt plaintext using AES-GCM.
        
        Returns:
            Tuple of (ciphertext, nonce)
        """
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)  # 96-bit nonce for GCM
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
        return ciphertext, nonce
    
    @staticmethod
    def aes_decrypt(key: bytes, ciphertext: bytes, nonce: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """Decrypt ciphertext using AES-GCM."""
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, associated_data)
    
    @staticmethod
    def rsa_sign(private_key: rsa.RSAPrivateKey, message: bytes) -> bytes:
        """Sign a message using RSA with PSS padding and SHA-256."""
        return private_key.sign(
            message,
            PSS(
                mgf=MGF1(hashes.SHA256()),
                salt_length=PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    
    @staticmethod
    def rsa_verify(public_key: rsa.RSAPublicKey, message: bytes, signature: bytes) -> bool:
        """Verify an RSA signature."""
        try:
            public_key.verify(
                signature,
                message,
                PSS(
                    mgf=MGF1(hashes.SHA256()),
                    salt_length=PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    @staticmethod
    def ecdsa_sign(private_key: ec.EllipticCurvePrivateKey, message: bytes) -> bytes:
        """Sign a message using ECDSA with SHA-256."""
        return private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    
    @staticmethod
    def ecdsa_verify(public_key: ec.EllipticCurvePublicKey, message: bytes, signature: bytes) -> bool:
        """Verify an ECDSA signature."""
        try:
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False
    
    @staticmethod
    def sha256_hash(data: bytes) -> bytes:
        """Compute SHA-256 hash of data."""
        return hashlib.sha256(data).digest()
    
    @staticmethod
    def hmac_sha256(key: bytes, message: bytes) -> bytes:
        """Compute HMAC-SHA256 of message using key."""
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(message)
        return h.finalize()
    
    @staticmethod
    def hmac_verify(key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify HMAC-SHA256 signature."""
        try:
            expected = CryptoOperations.hmac_sha256(key, message)
            return hmac.compare_digest(expected, signature)
        except Exception:
            return False
    
    @staticmethod
    def serialize_public_key(public_key) -> bytes:
        """Serialize a public key to bytes (for storage/transmission)."""
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

