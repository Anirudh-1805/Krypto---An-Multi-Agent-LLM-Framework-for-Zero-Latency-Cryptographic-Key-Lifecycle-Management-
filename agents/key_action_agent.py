"""
Key Action Agent Module

Executes authorized policy decisions (key rotation, revocation).
Does NOT make decisions.
Does NOT access monitoring data.
Only executes signed, verified policy decisions.
"""

import logging
import uuid
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from enum import Enum
from crypto_core.key_manager import KeyManager, KeyAlgorithm, KeyMetadata
from agents.policy_agent import PolicyAgent, PolicyDecision, ActionType


logger = logging.getLogger(__name__)


class ActionStatus(Enum):
    """Status of an action execution."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    REJECTED = "rejected"


class ActionExecution:
    """Represents an action execution record."""
    
    def __init__(self, decision: PolicyDecision, status: ActionStatus, 
                 timestamp: datetime, result: Optional[Dict[str, Any]] = None,
                 error: Optional[str] = None):
        self.execution_id = str(uuid.uuid4())
        self.decision = decision
        self.status = status
        self.timestamp = timestamp
        self.result = result or {}
        self.error = error
        self.verified = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert execution to dictionary."""
        return {
            'execution_id': self.execution_id,
            'decision_id': self.decision.decision_id,
            'key_id': self.decision.key_id,
            'action': self.decision.action.value,
            'status': self.status.value,
            'timestamp': self.timestamp.isoformat(),
            'verified': self.verified,
            'result': self.result,
            'error': self.error
        }


class KeyActionAgent:
    """
    Key Action Agent: Executes authorized policy decisions.
    
    Responsibilities:
    - Execute ONLY authorized policy decisions
    - Verify authenticity of signed instructions
    - Support key rotation and revocation
    - Ensure smooth transitions during rotation
    
    Restrictions:
    - Does NOT make decisions
    - Does NOT access monitoring data
    - Rejects invalid or unsigned instructions
    """
    
    def __init__(self, key_manager: KeyManager, policy_agent: PolicyAgent):
        self.key_manager = key_manager
        self.policy_agent = policy_agent
        self.executions: List[ActionExecution] = []
        self.rotation_grace_period_hours = 24  # Grace period before revoking old key
        
        # Track active rotations: key_id -> (old_key_id, new_key_id, grace_period_end)
        self.active_rotations: Dict[str, tuple] = {}
        
        logger.info("Key Action Agent initialized")
    
    def execute_decision(self, decision: PolicyDecision) -> ActionExecution:
        """
        Execute a policy decision after verifying its authenticity.
        
        Args:
            decision: PolicyDecision to execute
        
        Returns:
            ActionExecution record
        """
        # Verify the decision signature
        if not decision.signature:
            logger.warning(f"Decision {decision.decision_id} has no signature - REJECTED")
            execution = ActionExecution(
                decision=decision,
                status=ActionStatus.REJECTED,
                timestamp=datetime.now(),
                error="Decision has no signature"
            )
            self.executions.append(execution)
            return execution
        
        # Verify signature authenticity
        if not self.policy_agent.verify_decision(decision):
            logger.warning(f"Decision {decision.decision_id} signature verification failed - REJECTED")
            execution = ActionExecution(
                decision=decision,
                status=ActionStatus.REJECTED,
                timestamp=datetime.now(),
                error="Signature verification failed"
            )
            self.executions.append(execution)
            return execution
        
        logger.info(f"Executing verified decision: {decision}")
        
        # Execute based on action type
        execution = None
        
        if decision.action == ActionType.ROTATE_KEY:
            execution = self._rotate_key(decision)
        elif decision.action == ActionType.REVOKE_KEY:
            execution = self._revoke_key(decision)
        elif decision.action == ActionType.ALERT:
            execution = self._handle_alert(decision)
        elif decision.action == ActionType.NO_ACTION:
            execution = ActionExecution(
                decision=decision,
                status=ActionStatus.COMPLETED,
                timestamp=datetime.now(),
                result={'message': 'No action required'}
            )
        else:
            execution = ActionExecution(
                decision=decision,
                status=ActionStatus.REJECTED,
                timestamp=datetime.now(),
                error=f"Unknown action type: {decision.action}"
            )
        
        if execution:
            execution.verified = True
            self.executions.append(execution)
        
        return execution
    
    def _rotate_key(self, decision: PolicyDecision) -> ActionExecution:
        """
        Rotate a key with grace period.
        
        Process:
        1. Generate new key with same algorithm
        2. Mark old key as rotated (but keep it active)
        3. Set grace period before old key revocation
        4. Applications can migrate to new key during grace period
        """
        key_id = decision.key_id
        timestamp = datetime.now()
        
        try:
            # Get current key metadata
            old_metadata = self.key_manager.get_key_metadata(key_id)
            if not old_metadata:
                return ActionExecution(
                    decision=decision,
                    status=ActionStatus.FAILED,
                    timestamp=timestamp,
                    error=f"Key {key_id} not found"
                )
            
            if old_metadata.is_revoked:
                return ActionExecution(
                    decision=decision,
                    status=ActionStatus.FAILED,
                    timestamp=timestamp,
                    error=f"Key {key_id} is already revoked"
                )
            
            # Generate new key with same algorithm
            new_key_id = f"{key_id.rsplit('-v', 1)[0]}-v{int(key_id.rsplit('-v', 1)[1]) + 1}"
            
            logger.info(f"Rotating key {key_id} -> {new_key_id}")
            
            # Generate new key
            new_key_id_actual = self.key_manager.generate_key(
                old_metadata.algorithm,
                key_id=new_key_id
            )
            
            # Mark old key as rotated (internal method)
            self.key_manager._rotate_key(key_id, new_key_id_actual)
            
            # Set grace period
            grace_period_end = timestamp + timedelta(hours=self.rotation_grace_period_hours)
            self.active_rotations[key_id] = (key_id, new_key_id_actual, grace_period_end)
            
            logger.info(
                f"Key rotation initiated: {key_id} -> {new_key_id_actual} "
                f"(grace period until {grace_period_end.isoformat()})"
            )
            
            return ActionExecution(
                decision=decision,
                status=ActionStatus.COMPLETED,
                timestamp=timestamp,
                result={
                    'old_key_id': key_id,
                    'new_key_id': new_key_id_actual,
                    'grace_period_end': grace_period_end.isoformat(),
                    'message': f'Key rotated. Old key remains active until {grace_period_end.isoformat()}'
                }
            )
        
        except Exception as e:
            logger.error(f"Key rotation failed: {e}")
            return ActionExecution(
                decision=decision,
                status=ActionStatus.FAILED,
                timestamp=timestamp,
                error=str(e)
            )
    
    def _revoke_key(self, decision: PolicyDecision) -> ActionExecution:
        """Revoke a key immediately."""
        key_id = decision.key_id
        timestamp = datetime.now()
        
        try:
            # Get key metadata
            metadata = self.key_manager.get_key_metadata(key_id)
            if not metadata:
                return ActionExecution(
                    decision=decision,
                    status=ActionStatus.FAILED,
                    timestamp=timestamp,
                    error=f"Key {key_id} not found"
                )
            
            if metadata.is_revoked:
                return ActionExecution(
                    decision=decision,
                    status=ActionStatus.COMPLETED,
                    timestamp=timestamp,
                    result={'message': f'Key {key_id} was already revoked'}
                )
            
            # Check if key is in grace period (don't revoke during rotation grace period)
            if key_id in self.active_rotations:
                old_key_id, new_key_id, grace_period_end = self.active_rotations[key_id]
                if datetime.now() < grace_period_end:
                    return ActionExecution(
                        decision=decision,
                        status=ActionStatus.FAILED,
                        timestamp=timestamp,
                        error=f"Key {key_id} is in rotation grace period until {grace_period_end.isoformat()}"
                    )
            
            # Revoke the key
            self.key_manager._revoke_key(key_id)
            
            # Remove from active rotations if present
            if key_id in self.active_rotations:
                del self.active_rotations[key_id]
            
            logger.warning(f"Key {key_id} has been REVOKED")
            
            return ActionExecution(
                decision=decision,
                status=ActionStatus.COMPLETED,
                timestamp=timestamp,
                result={
                    'message': f'Key {key_id} has been revoked',
                    'revoked_at': timestamp.isoformat()
                }
            )
        
        except Exception as e:
            logger.error(f"Key revocation failed: {e}")
            return ActionExecution(
                decision=decision,
                status=ActionStatus.FAILED,
                timestamp=timestamp,
                error=str(e)
            )
    
    def _handle_alert(self, decision: PolicyDecision) -> ActionExecution:
        """Handle an alert action (log only, no key changes)."""
        logger.warning(f"ALERT: {decision.explanation} (Key: {decision.key_id})")
        
        return ActionExecution(
            decision=decision,
            status=ActionStatus.COMPLETED,
            timestamp=datetime.now(),
            result={
                'message': 'Alert logged',
                'alert_description': decision.explanation
            }
        )
    
    def execute_pending_rotations(self):
        """
        Check for rotations that have passed grace period and can be finalized.
        This should be called periodically.
        """
        now = datetime.now()
        to_finalize = []
        
        for old_key_id, (_, new_key_id, grace_period_end) in list(self.active_rotations.items()):
            if now >= grace_period_end:
                to_finalize.append(old_key_id)
        
        for old_key_id in to_finalize:
            logger.info(f"Grace period ended for {old_key_id}, old key can now be revoked if needed")
            # Note: We don't auto-revoke here - that requires a new policy decision
            # This just marks that the grace period is over
    
    def get_executions(self, key_id: Optional[str] = None, 
                      status: Optional[ActionStatus] = None) -> List[ActionExecution]:
        """Get execution records, optionally filtered."""
        executions = self.executions
        
        if key_id:
            executions = [e for e in executions if e.decision.key_id == key_id]
        
        if status:
            executions = [e for e in executions if e.status == status]
        
        return executions
    
    def get_active_rotations(self) -> Dict[str, Dict[str, Any]]:
        """Get information about active rotations."""
        result = {}
        now = datetime.now()
        
        for old_key_id, (_, new_key_id, grace_period_end) in self.active_rotations.items():
            result[old_key_id] = {
                'new_key_id': new_key_id,
                'grace_period_end': grace_period_end.isoformat(),
                'grace_period_active': now < grace_period_end,
                'time_remaining_hours': max(0, (grace_period_end - now).total_seconds() / 3600)
            }
        
        return result

