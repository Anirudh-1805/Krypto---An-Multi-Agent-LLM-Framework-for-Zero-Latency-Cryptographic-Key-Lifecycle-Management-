"""
Audit Agent Module

Maintains an immutable, tamper-evident audit trail.
Uses hash chaining to ensure log integrity.
"""

import logging
import json
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum
from agents.policy_agent import PolicyDecision
from agents.key_action_agent import ActionExecution


logger = logging.getLogger(__name__)


class AuditEventType(Enum):
    """Types of audit events."""
    KEY_GENERATED = "key_generated"
    KEY_ROTATED = "key_rotated"
    KEY_REVOKED = "key_revoked"
    POLICY_DECISION = "policy_decision"
    ACTION_EXECUTED = "action_executed"
    OPERATION = "operation"
    ANOMALY_DETECTED = "anomaly_detected"


class AuditEntry:
    """Represents a single audit log entry."""
    
    def __init__(self, event_type: AuditEventType, data: Dict[str, Any], 
                 previous_hash: Optional[str] = None):
        self.entry_id = str(hashlib.sha256(
            f"{event_type.value}:{json.dumps(data, sort_keys=True)}:{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16])
        self.timestamp = datetime.now()
        self.event_type = event_type
        self.data = data
        self.previous_hash = previous_hash
        self.entry_hash = self._compute_hash()
    
    def _compute_hash(self) -> str:
        """Compute hash for this entry (includes previous hash for chaining)."""
        content = json.dumps({
            'entry_id': self.entry_id,
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type.value,
            'data': self.data,
            'previous_hash': self.previous_hash
        }, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert entry to dictionary."""
        return {
            'entry_id': self.entry_id,
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type.value,
            'data': self.data,
            'previous_hash': self.previous_hash,
            'entry_hash': self.entry_hash
        }


class AuditAgent:
    """
    Audit Agent: Maintains immutable, tamper-evident audit trail.
    
    Responsibilities:
    - Record all policy decisions and actions
    - Use tamper-evident logging (hash chaining)
    - Ensure logs are append-only
    - Support verification of integrity
    
    Restrictions:
    - Does NOT modify existing entries
    - Does NOT delete entries
    - Only appends new entries
    """
    
    def __init__(self):
        self.entries: List[AuditEntry] = []
        self.last_hash: Optional[str] = None
        
        # Create genesis entry
        genesis = AuditEntry(
            event_type=AuditEventType.KEY_GENERATED,
            data={'message': 'Audit log initialized', 'system': 'krypto'},
            previous_hash=None
        )
        self.entries.append(genesis)
        self.last_hash = genesis.entry_hash
        
        logger.info("Audit Agent initialized")
    
    def log_key_generated(self, key_id: str, algorithm: str, metadata: Dict[str, Any]):
        """Log a key generation event."""
        entry = AuditEntry(
            event_type=AuditEventType.KEY_GENERATED,
            data={
                'key_id': key_id,
                'algorithm': algorithm,
                'metadata': metadata
            },
            previous_hash=self.last_hash
        )
        self._append_entry(entry)
    
    def log_key_rotated(self, old_key_id: str, new_key_id: str, metadata: Dict[str, Any]):
        """Log a key rotation event."""
        entry = AuditEntry(
            event_type=AuditEventType.KEY_ROTATED,
            data={
                'old_key_id': old_key_id,
                'new_key_id': new_key_id,
                'metadata': metadata
            },
            previous_hash=self.last_hash
        )
        self._append_entry(entry)
    
    def log_key_revoked(self, key_id: str, reason: str, metadata: Dict[str, Any]):
        """Log a key revocation event."""
        entry = AuditEntry(
            event_type=AuditEventType.KEY_REVOKED,
            data={
                'key_id': key_id,
                'reason': reason,
                'metadata': metadata
            },
            previous_hash=self.last_hash
        )
        self._append_entry(entry)
    
    def log_policy_decision(self, decision: PolicyDecision):
        """Log a policy decision."""
        entry = AuditEntry(
            event_type=AuditEventType.POLICY_DECISION,
            data={
                'decision_id': decision.decision_id,
                'key_id': decision.key_id,
                'action': decision.action.value,
                'policy_name': decision.policy_name,
                'explanation': decision.explanation,
                'evidence': decision.evidence,
                'timestamp': decision.timestamp.isoformat(),
                'signature': decision.signature
            },
            previous_hash=self.last_hash
        )
        self._append_entry(entry)
    
    def log_action_executed(self, execution: ActionExecution):
        """Log an action execution."""
        entry = AuditEntry(
            event_type=AuditEventType.ACTION_EXECUTED,
            data={
                'execution_id': execution.execution_id,
                'decision_id': execution.decision.decision_id,
                'key_id': execution.decision.key_id,
                'action': execution.decision.action.value,
                'status': execution.status.value,
                'timestamp': execution.timestamp.isoformat(),
                'verified': execution.verified,
                'result': execution.result,
                'error': execution.error
            },
            previous_hash=self.last_hash
        )
        self._append_entry(entry)
    
    def log_operation(self, key_id: str, operation: str, service_id: str, 
                      success: bool, metadata: Dict[str, Any]):
        """Log a cryptographic operation."""
        entry = AuditEntry(
            event_type=AuditEventType.OPERATION,
            data={
                'key_id': key_id,
                'operation': operation,
                'service_id': service_id,
                'success': success,
                'metadata': metadata
            },
            previous_hash=self.last_hash
        )
        self._append_entry(entry)
    
    def log_anomaly(self, signal_type: str, key_id: str, severity: str, 
                    description: str, evidence: Dict[str, Any]):
        """Log an anomaly signal."""
        entry = AuditEntry(
            event_type=AuditEventType.ANOMALY_DETECTED,
            data={
                'signal_type': signal_type,
                'key_id': key_id,
                'severity': severity,
                'description': description,
                'evidence': evidence
            },
            previous_hash=self.last_hash
        )
        self._append_entry(entry)
    
    def _append_entry(self, entry: AuditEntry):
        """Append an entry to the audit log (append-only operation)."""
        self.entries.append(entry)
        self.last_hash = entry.entry_hash
        logger.debug(f"Audit entry added: {entry.event_type.value} (ID: {entry.entry_id})")
    
    def verify_integrity(self) -> Dict[str, Any]:
        """
        Verify the integrity of the audit log by checking hash chain.
        
        Returns:
            Dict with 'valid' (bool) and 'details' (list of issues)
        """
        issues = []
        
        if not self.entries:
            return {'valid': False, 'details': ['Audit log is empty']}
        
        # Check genesis entry
        if self.entries[0].previous_hash is not None:
            issues.append("Genesis entry should have null previous_hash")
        
        # Check hash chain
        for i in range(len(self.entries)):
            entry = self.entries[i]
            
            # Verify entry hash
            expected_hash = entry._compute_hash()
            if entry.entry_hash != expected_hash:
                issues.append(
                    f"Entry {i} (ID: {entry.entry_id}) hash mismatch: "
                    f"expected {expected_hash}, got {entry.entry_hash}"
                )
            
            # Verify previous hash link (except genesis)
            if i > 0:
                prev_entry = self.entries[i - 1]
                if entry.previous_hash != prev_entry.entry_hash:
                    issues.append(
                        f"Entry {i} (ID: {entry.entry_id}) previous_hash mismatch: "
                        f"expected {prev_entry.entry_hash}, got {entry.previous_hash}"
                    )
        
        # Verify last_hash matches last entry
        if self.last_hash != self.entries[-1].entry_hash:
            issues.append(
                f"Last hash mismatch: expected {self.entries[-1].entry_hash}, "
                f"got {self.last_hash}"
            )
        
        valid = len(issues) == 0
        
        return {
            'valid': valid,
            'details': issues,
            'total_entries': len(self.entries),
            'last_hash': self.last_hash
        }
    
    def get_entries(self, event_type: Optional[AuditEventType] = None,
                   key_id: Optional[str] = None,
                   limit: Optional[int] = None) -> List[AuditEntry]:
        """Get audit entries, optionally filtered."""
        entries = self.entries
        
        if event_type:
            entries = [e for e in entries if e.event_type == event_type]
        
        if key_id:
            entries = [e for e in entries if e.data.get('key_id') == key_id]
        
        if limit:
            entries = entries[-limit:]  # Most recent
        
        return entries
    
    def export_log(self, filepath: Optional[str] = None) -> str:
        """
        Export audit log to JSON format.
        
        Args:
            filepath: Optional file path to write to
        
        Returns:
            JSON string of audit log
        """
        log_data = {
            'export_timestamp': datetime.now().isoformat(),
            'total_entries': len(self.entries),
            'last_hash': self.last_hash,
            'entries': [entry.to_dict() for entry in self.entries]
        }
        
        json_str = json.dumps(log_data, indent=2)
        
        if filepath:
            with open(filepath, 'w') as f:
                f.write(json_str)
            logger.info(f"Audit log exported to {filepath}")
        
        return json_str
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get audit log statistics."""
        stats = {
            'total_entries': len(self.entries),
            'by_event_type': {},
            'by_key_id': {},
            'first_entry': self.entries[0].timestamp.isoformat() if self.entries else None,
            'last_entry': self.entries[-1].timestamp.isoformat() if self.entries else None,
            'last_hash': self.last_hash
        }
        
        for entry in self.entries:
            # Count by event type
            event_type = entry.event_type.value
            stats['by_event_type'][event_type] = stats['by_event_type'].get(event_type, 0) + 1
            
            # Count by key_id if present
            key_id = entry.data.get('key_id')
            if key_id:
                stats['by_key_id'][key_id] = stats['by_key_id'].get(key_id, 0) + 1
        
        return stats

