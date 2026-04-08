"""
Simulated Application Ecosystem

This module contains simulated applications that consume cryptographic keys.
Applications demonstrate realistic misuse patterns:
- Long-lived keys
- Excessive repeated usage
- Static configurations
"""

from .web_service import WebService
from .data_storage import DataStorageService
from .file_encryption import FileEncryptionService

__all__ = ['WebService', 'DataStorageService', 'FileEncryptionService']

