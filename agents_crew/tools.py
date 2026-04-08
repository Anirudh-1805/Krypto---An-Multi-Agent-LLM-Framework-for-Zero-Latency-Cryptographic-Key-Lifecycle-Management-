"""
CrewAI Tools for Key Management

Provides tools that expose KeyManager functionality to CrewAI agents.
"""

from crewai.tools import BaseTool
from typing import Type, Any
from pydantic import BaseModel, Field
import json


class GetKeyLogsInput(BaseModel):
    """Input schema for getting key operation logs."""
    limit: int = Field(default=100, description="Maximum number of log entries to retrieve")


class GetKeyMetadataInput(BaseModel):
    """Input schema for getting key metadata."""
    key_id: str = Field(default="", description="The key ID to get metadata for. Leave empty to get all keys.")


class RotateKeyInput(BaseModel):
    """Input schema for rotating a key."""
    key_id: str = Field(description="The key ID to rotate")
    reason: str = Field(description="Reason for rotation (for audit trail)")


class RevokeKeyInput(BaseModel):
    """Input schema for revoking a key."""
    key_id: str = Field(description="The key ID to revoke")
    reason: str = Field(description="Reason for revocation (for audit trail)")


class GetKeyLogsTool(BaseTool):
    """Tool to retrieve cryptographic operation logs."""
    name: str = "get_key_logs"
    description: str = "Retrieve cryptographic operation logs from the KeyManager. Returns a list of recent operations including timestamps, key IDs, operation types, and success status."
    args_schema: Type[BaseModel] = GetKeyLogsInput
    
    def __init__(self, key_manager):
        super().__init__()
        self._key_manager = key_manager
    
    def _run(self, limit: int = 100) -> str:
        """Retrieve operation logs."""
        logs = self._key_manager.get_operation_log()
        recent_logs = logs[-limit:] if len(logs) > limit else logs
        return json.dumps(recent_logs, indent=2)


class GetKeyMetadataTool(BaseTool):
    """Tool to retrieve key metadata."""
    name: str = "get_key_metadata"
    description: str = "Get metadata for all keys or a specific key. Returns key ID, algorithm, creation time, usage count, and revocation status."
    args_schema: Type[BaseModel] = GetKeyMetadataInput
    
    def __init__(self, key_manager):
        super().__init__()
        self._key_manager = key_manager
    
    def _run(self, key_id: str = "") -> str:
        """Get key metadata."""
        if key_id:
            metadata = self._key_manager.get_key_metadata(key_id)
            if metadata:
                return json.dumps(metadata.to_dict(), indent=2)
            return f"Key {key_id} not found"
        else:
            all_metadata = self._key_manager.get_all_key_metadata()
            return json.dumps(all_metadata, indent=2)


class RotateKeyTool(BaseTool):
    """Tool to rotate a cryptographic key."""
    name: str = "rotate_key"
    description: str = "Rotate a cryptographic key by creating a new key and marking the old one as rotated. Use this when a key is too old or has been overused."
    args_schema: Type[BaseModel] = RotateKeyInput
   
    def __init__(self, key_manager):
        super().__init__()
        self._key_manager = key_manager
    
    def _run(self, key_id: str, reason: str) -> str:
        """Rotate a key."""
        try:
            # Get old key metadata to copy algorithm
            old_metadata = self._key_manager.get_key_metadata(key_id)
            if not old_metadata:
                return f"Error: Key {key_id} not found"
            
            # Generate new key with same algorithm
            new_key_id = f"{key_id}-rotated-{old_metadata.usage_count}"
            self._key_manager.generate_key(old_metadata.algorithm, new_key_id)
            
            # Mark old key as rotated
            self._key_manager._rotate_key(key_id, new_key_id)
            
            return f"Success: Rotated key {key_id} to {new_key_id}. Reason: {reason}"
        except Exception as e:
            return f"Error rotating key: {str(e)}"


class RevokeKeyTool(BaseTool):
    """Tool to revoke a cryptographic key."""
    name: str = "revoke_key"
    description: str = "Revoke a cryptographic key, making it unusable. Use this only for compromised or failed keys."
    args_schema: Type[BaseModel] = RevokeKeyInput
    
    def __init__(self, key_manager):
        super().__init__()
        self._key_manager = key_manager
    
    def _run(self, key_id: str, reason: str) -> str:
        """Revoke a key."""
        try:
            self._key_manager._revoke_key(key_id)
            return f"Success: Revoked key {key_id}. Reason: {reason}"
        except Exception as e:
            return f"Error revoking key: {str(e)}"
