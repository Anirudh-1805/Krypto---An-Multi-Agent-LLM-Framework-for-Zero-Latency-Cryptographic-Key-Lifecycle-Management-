"""
Web Service Application

Simulates a web service that signs HTTP requests and responses.
Demonstrates misuse patterns:
- Uses a single long-lived signing key
- Signs every request/response (excessive usage)
- Never rotates keys (static configuration)
"""

import logging
from datetime import datetime
from typing import Optional
from crypto_core.key_manager import KeyManager, KeyAlgorithm


logger = logging.getLogger(__name__)


class WebService:
    """
    Simulated web service that signs HTTP requests and responses.
    
    Misuse patterns:
    - Creates a single signing key at startup and uses it forever
    - Signs every request/response without considering key age
    - Hardcoded key ID (static configuration)
    """
    
    def __init__(self, key_manager: KeyManager, service_name: str = "web-service"):
        self.key_manager = key_manager
        self.service_name = service_name
        self.signing_key_id: Optional[str] = None
        self.request_count = 0
        
        # MISUSE PATTERN: Static key ID - never changes
        self._static_key_id = f"{service_name}-signing-key-v1"
        
        logger.info(f"[{self.service_name}] Initializing web service")
        self._initialize_key()
    
    def _initialize_key(self):
        """Initialize the signing key (only called once at startup)."""
        # MISUSE PATTERN: Create key once, use forever
        try:
            # Try to use existing key (if it exists from previous run)
            metadata = self.key_manager.get_key_metadata(self._static_key_id)
            if metadata and not metadata.is_revoked:
                self.signing_key_id = self._static_key_id
                logger.info(f"[{self.service_name}] Reusing existing signing key: {self.signing_key_id}")
                return
        except:
            pass
        
        # Create new key if it doesn't exist
        self.signing_key_id = self.key_manager.generate_key(
            KeyAlgorithm.ECDSA,
            key_id=self._static_key_id
        )
        logger.info(f"[{self.service_name}] Created new signing key: {self.signing_key_id}")
    
    def handle_request(self, method: str, path: str, body: Optional[bytes] = None) -> dict:
        """
        Simulate handling an HTTP request.
        
        Returns:
            Dictionary with response data and signature
        """
        self.request_count += 1
        
        # Build request message
        request_message = f"{method} {path}".encode('utf-8')
        if body:
            request_message += b"\n" + body
        
        # MISUSE PATTERN: Sign every single request, no matter how many
        signature = self.key_manager.sign(self.signing_key_id, request_message)
        
        # Build response
        response_body = f"Response to {method} {path}".encode('utf-8')
        response_message = f"200 OK\n{path}".encode('utf-8') + b"\n" + response_body
        
        # MISUSE PATTERN: Sign every single response too
        response_signature = self.key_manager.sign(self.signing_key_id, response_message)
        
        logger.info(
            f"[{self.service_name}] Handled request #{self.request_count}: "
            f"{method} {path} (key: {self.signing_key_id})"
        )
        
        return {
            'status': 200,
            'body': response_body,
            'request_signature': signature.hex(),
            'response_signature': response_signature.hex(),
            'key_id': self.signing_key_id
        }
    
    def verify_request_signature(self, method: str, path: str, body: Optional[bytes], signature: bytes) -> bool:
        """Verify a request signature."""
        request_message = f"{method} {path}".encode('utf-8')
        if body:
            request_message += b"\n" + body
        
        return self.key_manager.verify(self.signing_key_id, request_message, signature)
    
    def get_stats(self) -> dict:
        """Get service statistics."""
        metadata = self.key_manager.get_key_metadata(self.signing_key_id)
        return {
            'service_name': self.service_name,
            'key_id': self.signing_key_id,
            'request_count': self.request_count,
            'key_usage_count': metadata.usage_count if metadata else 0,
            'key_created_at': metadata.created_at.isoformat() if metadata else None,
            'key_age_days': (
                (datetime.now() - metadata.created_at).days if metadata else None
            )
        }

