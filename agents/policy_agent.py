"""
Policy Agent Module

Evaluates policies and makes decisions about key lifecycle actions.
Does NOT execute actions.
Does NOT access private keys.
"""

import logging
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from enum import Enum
from crypto_core.key_manager import KeyManager, KeyMetadata
from crypto_core.crypto_operations import CryptoOperations
from .monitoring_agent import MonitoringAgent, AnomalySignal


logger = logging.getLogger(__name__)


class ActionType(Enum):
    """Types of actions that can be decided."""
    ROTATE_KEY = "rotate_key"
    REVOKE_KEY = "revoke_key"
    ALERT = "alert"
    NO_ACTION = "no_action"


class PolicyDecision:
    """Represents a policy decision with explanation and signature."""
    
    def __init__(self, key_id: str, action: ActionType, policy_name: str, 
                 explanation: str, evidence: Dict[str, Any], 
                 timestamp: Optional[datetime] = None):
        self.key_id = key_id
        self.action = action
        self.policy_name = policy_name
        self.explanation = explanation
        self.evidence = evidence
        self.timestamp = timestamp or datetime.now()
        self.decision_id = self._generate_decision_id()
        self.signature = None  # Will be set by sign_decision()
    
    def _generate_decision_id(self) -> str:
        """Generate a unique decision ID based on content."""
        content = f"{self.key_id}:{self.action.value}:{self.policy_name}:{self.timestamp.isoformat()}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def sign_decision(self, signing_key_id: str, key_manager: KeyManager) -> bool:
        """
        Sign this decision using a policy signing key.
        
        Args:
            signing_key_id: Key ID to use for signing
            key_manager: KeyManager instance
        
        Returns:
            True if signing successful
        """
        try:
            # Create decision payload
            payload = json.dumps({
                'decision_id': self.decision_id,
                'key_id': self.key_id,
                'action': self.action.value,
                'policy_name': self.policy_name,
                'timestamp': self.timestamp.isoformat(),
                'explanation': self.explanation,
                'evidence': self.evidence
            }, sort_keys=True).encode('utf-8')
            
            # Sign the payload
            signature = key_manager.sign(signing_key_id, payload)
            self.signature = signature.hex()
            return True
        except Exception as e:
            logger.error(f"Failed to sign decision: {e}")
            return False
    
    def verify_signature(self, signing_key_id: str, key_manager: KeyManager) -> bool:
        """Verify the signature on this decision."""
        if not self.signature:
            return False
        
        try:
            payload = json.dumps({
                'decision_id': self.decision_id,
                'key_id': self.key_id,
                'action': self.action.value,
                'policy_name': self.policy_name,
                'timestamp': self.timestamp.isoformat(),
                'explanation': self.explanation,
                'evidence': self.evidence
            }, sort_keys=True).encode('utf-8')
            
            return key_manager.verify(signing_key_id, payload, bytes.fromhex(self.signature))
        except Exception as e:
            logger.error(f"Failed to verify decision signature: {e}")
            return False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert decision to dictionary."""
        return {
            'decision_id': self.decision_id,
            'key_id': self.key_id,
            'action': self.action.value,
            'policy_name': self.policy_name,
            'explanation': self.explanation,
            'evidence': self.evidence,
            'timestamp': self.timestamp.isoformat(),
            'signature': self.signature,
            'signature_verified': None  # Must be checked separately
        }
    
    def __str__(self) -> str:
        return f"Decision {self.decision_id}: {self.action.value} for key {self.key_id} (Policy: {self.policy_name})"


class PolicyRule:
    """Represents a single policy rule."""
    
    def __init__(self, name: str, condition: Dict[str, Any], action: str, 
                 explanation_template: str, priority: int = 0):
        self.name = name
        self.condition = condition  # Dict with conditions to evaluate
        self.action = action  # Action to take if condition is met
        self.explanation_template = explanation_template
        self.priority = priority  # Higher priority rules evaluated first
    
    def evaluate(self, key_metadata: KeyMetadata, usage_stats: Dict[str, Any], 
                 anomaly_signals: List[AnomalySignal]) -> Optional[Dict[str, Any]]:
        """
        Evaluate this rule against key metadata and usage statistics.
        
        Returns:
            Dict with 'matches' (bool) and 'evidence' if rule matches, None otherwise
        """
        evidence = {}
        matches = True
        
        # Evaluate each condition
        for condition_key, condition_value in self.condition.items():
            if condition_key == 'max_age_days':
                key_age = (datetime.now() - key_metadata.created_at).total_seconds() / 86400
                if key_age <= condition_value:
                    matches = False
                else:
                    evidence['key_age_days'] = key_age
                    evidence['threshold_days'] = condition_value
            
            elif condition_key == 'max_usage_count':
                usage_count = usage_stats.get('total_operations', 0)
                if usage_count <= condition_value:
                    matches = False
                else:
                    evidence['usage_count'] = usage_count
                    evidence['threshold'] = condition_value
            
            elif condition_key == 'max_usage_rate_per_minute':
                usage_rate = usage_stats.get('usage_rate_per_minute', 0.0)
                if usage_rate <= condition_value:
                    matches = False
                else:
                    evidence['usage_rate'] = usage_rate
                    evidence['threshold'] = condition_value
            
            elif condition_key == 'max_failure_rate':
                failure_rate = usage_stats.get('failure_rate', 0.0)
                if failure_rate <= condition_value:
                    matches = False
                else:
                    evidence['failure_rate'] = failure_rate
                    evidence['threshold'] = condition_value
            
            elif condition_key == 'has_anomaly_signal':
                # Check if there are anomaly signals of specified type/severity
                signal_type = condition_value.get('type', None)
                severity = condition_value.get('severity', None)
                
                matching_signals = [
                    s for s in anomaly_signals
                    if (signal_type is None or s.signal_type == signal_type) and
                       (severity is None or s.severity == severity)
                ]
                
                if not matching_signals:
                    matches = False
                else:
                    evidence['anomaly_signals'] = [s.to_dict() for s in matching_signals]
            
            elif condition_key == 'is_revoked':
                if key_metadata.is_revoked != condition_value:
                    matches = False
                else:
                    evidence['is_revoked'] = key_metadata.is_revoked
            
            elif condition_key == 'is_rotated':
                if key_metadata.is_rotated != condition_value:
                    matches = False
                else:
                    evidence['is_rotated'] = key_metadata.is_rotated
        
        if matches:
            return {
                'matches': True,
                'evidence': evidence,
                'action': self.action,
                'explanation_template': self.explanation_template
            }
        
        return None


class PolicyAgent:
    """
    Policy Agent: Evaluates policies and makes decisions about key lifecycle.
    
    Responsibilities:
    - Evaluate key metadata + monitoring signals
    - Apply explicit, predefined security policies
    - Decide actions: Rotate key, Revoke key, Alert, No action
    - Generate signed, verifiable policy decisions
    - Provide human-readable explanations
    
    Restrictions:
    - Does NOT execute actions
    - Does NOT access raw private keys
    """
    
    def __init__(self, key_manager: KeyManager, monitoring_agent: MonitoringAgent, 
                 policy_signing_key_id: Optional[str] = None):
        self.key_manager = key_manager
        self.monitoring_agent = monitoring_agent
        self.policy_signing_key_id = policy_signing_key_id
        self.policies: List[PolicyRule] = []
        self.decisions: List[PolicyDecision] = []
        
        # Initialize default policies if none provided
        self._load_default_policies()
        
        # Create policy signing key if not provided
        if not self.policy_signing_key_id:
            self._initialize_policy_signing_key()
        
        logger.info("Policy Agent initialized")
    
    def _initialize_policy_signing_key(self):
        """Initialize a key for signing policy decisions."""
        try:
            self.policy_signing_key_id = "policy-agent-signing-key"
            # Try to use existing key
            metadata = self.key_manager.get_key_metadata(self.policy_signing_key_id)
            if metadata and not metadata.is_revoked:
                logger.info("Using existing policy signing key")
                return
        except:
            pass
        
        # Create new key
        from crypto_core.key_manager import KeyAlgorithm
        self.key_manager.generate_key(KeyAlgorithm.ECDSA, key_id=self.policy_signing_key_id)
        logger.info("Created new policy signing key")
    
    def _load_default_policies(self):
        """Load default security policies."""
        from crypto_core.key_manager import KeyAlgorithm
        
        # Policy 1: Rotate keys older than 90 days
        self.policies.append(PolicyRule(
            name="rotate_old_keys",
            condition={'max_age_days': 90},
            action=ActionType.ROTATE_KEY.value,
            explanation_template="Key is {key_age_days:.1f} days old, exceeding the {threshold_days} day rotation policy.",
            priority=10
        ))
        
        # Policy 2: Rotate keys with excessive usage
        self.policies.append(PolicyRule(
            name="rotate_high_usage_keys",
            condition={'max_usage_count': 1000},
            action=ActionType.ROTATE_KEY.value,
            explanation_template="Key has been used {usage_count} times, exceeding the {threshold} usage threshold.",
            priority=9
        ))
        
        # Policy 3: Revoke keys with high failure rate
        self.policies.append(PolicyRule(
            name="revoke_failing_keys",
            condition={'max_failure_rate': 0.05},
            action=ActionType.REVOKE_KEY.value,
            explanation_template="Key has {failure_rate:.1%} failure rate, exceeding the {threshold:.1%} threshold. Key may be compromised.",
            priority=20  # High priority - security issue
        ))
        
        # Policy 4: Alert on high usage rate
        self.policies.append(PolicyRule(
            name="alert_high_usage_rate",
            condition={'max_usage_rate_per_minute': 10.0},
            action=ActionType.ALERT.value,
            explanation_template="Key usage rate is {usage_rate:.2f} ops/min, exceeding the {threshold} ops/min threshold. Possible abuse detected.",
            priority=5
        ))
        
        # Policy 5: Alert on critical anomaly signals
        self.policies.append(PolicyRule(
            name="alert_critical_anomalies",
            condition={'has_anomaly_signal': {'severity': 'critical'}},
            action=ActionType.ALERT.value,
            explanation_template="Critical anomaly signals detected for this key. Immediate attention required.",
            priority=15
        ))
        
        logger.info(f"Loaded {len(self.policies)} default policies")
    
    def load_policies_from_dict(self, policies_config: List[Dict[str, Any]]):
        """
        Load policies from a dictionary configuration.
        
        Args:
            policies_config: List of policy dictionaries with keys:
                - name: Policy name
                - condition: Dict of conditions
                - action: Action to take
                - explanation_template: Template for explanation
                - priority: Optional priority (default 0)
        """
        self.policies.clear()
        
        for policy_dict in policies_config:
            rule = PolicyRule(
                name=policy_dict['name'],
                condition=policy_dict['condition'],
                action=policy_dict['action'],
                explanation_template=policy_dict.get('explanation_template', 'Policy condition met.'),
                priority=policy_dict.get('priority', 0)
            )
            self.policies.append(rule)
        
        # Sort by priority (highest first)
        self.policies.sort(key=lambda p: p.priority, reverse=True)
        
        logger.info(f"Loaded {len(self.policies)} policies from configuration")
    
    def evaluate_key(self, key_id: str) -> Optional[PolicyDecision]:
        """
        Evaluate policies for a specific key and make a decision.
        
        Args:
            key_id: Key ID to evaluate
        
        Returns:
            PolicyDecision if action needed, None if no action
        """
        # Get key metadata
        key_metadata = self.key_manager.get_key_metadata(key_id)
        if not key_metadata:
            logger.warning(f"Key {key_id} not found")
            return None
        
        if key_metadata.is_revoked:
            logger.debug(f"Key {key_id} is already revoked, skipping evaluation")
            return None
        
        # Get usage statistics
        usage_stats = self.monitoring_agent.get_usage_statistics(key_id)
        if not usage_stats:
            usage_stats = {}
        
        # Get anomaly signals
        anomaly_signals = self.monitoring_agent.get_anomaly_signals(key_id)
        
        # Evaluate policies in priority order
        for policy in self.policies:
            result = policy.evaluate(key_metadata, usage_stats, anomaly_signals)
            
            if result and result['matches']:
                # Policy condition met - create decision
                action = ActionType(result['action'])
                evidence = result['evidence']
                
                # Generate explanation from template
                explanation = self._format_explanation(
                    result['explanation_template'],
                    evidence,
                    key_metadata
                )
                
                decision = PolicyDecision(
                    key_id=key_id,
                    action=action,
                    policy_name=policy.name,
                    explanation=explanation,
                    evidence=evidence
                )
                
                # Sign the decision
                if self.policy_signing_key_id:
                    decision.sign_decision(self.policy_signing_key_id, self.key_manager)
                
                self.decisions.append(decision)
                logger.info(f"Policy decision made: {decision}")
                
                return decision
        
        # No policy matched - no action needed
        return None
    
    def evaluate_all_keys(self) -> List[PolicyDecision]:
        """
        Evaluate policies for all keys.
        
        Returns:
            List of PolicyDecision objects
        """
        all_metadata = self.key_manager.get_all_key_metadata()
        decisions = []
        
        for key_info in all_metadata:
            key_id = key_info['key_id']
            if key_info.get('is_revoked', False):
                continue
            
            decision = self.evaluate_key(key_id)
            if decision:
                decisions.append(decision)
        
        return decisions
    
    def _format_explanation(self, template: str, evidence: Dict[str, Any], 
                           key_metadata: KeyMetadata) -> str:
        """Format explanation template with evidence and metadata."""
        # Add key metadata to evidence for template formatting
        template_vars = {
            **evidence,
            'key_id': key_metadata.key_id,
            'algorithm': key_metadata.algorithm.value,
            'created_at': key_metadata.created_at.isoformat(),
            'usage_count': key_metadata.usage_count
        }
        
        try:
            return template.format(**template_vars)
        except KeyError as e:
            logger.warning(f"Missing variable in explanation template: {e}")
            return template
    
    def get_decisions(self, key_id: Optional[str] = None, 
                     action: Optional[ActionType] = None) -> List[PolicyDecision]:
        """
        Get policy decisions, optionally filtered.
        
        Args:
            key_id: Optional key ID filter
            action: Optional action type filter
        
        Returns:
            List of PolicyDecision objects
        """
        decisions = self.decisions
        
        if key_id:
            decisions = [d for d in decisions if d.key_id == key_id]
        
        if action:
            decisions = [d for d in decisions if d.action == action]
        
        return decisions
    
    def verify_decision(self, decision: PolicyDecision) -> bool:
        """Verify the signature on a policy decision."""
        if not self.policy_signing_key_id:
            return False
        return decision.verify_signature(self.policy_signing_key_id, self.key_manager)

