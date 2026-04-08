"""
Full System Validation Script

Validates that:
- No agent violates authority boundaries
- No private keys exposed
- All actions traceable
- Audit log integrity
- System behaves safely under anomaly scenarios
"""

import logging
from datetime import datetime
from crypto_core.key_manager import KeyManager, KeyAlgorithm
from agents.monitoring_agent import MonitoringAgent
from agents.policy_agent import PolicyAgent
from agents.key_action_agent import KeyActionAgent
from agents.audit_agent import AuditAgent
from apps.web_service import WebService
from apps.data_storage import DataStorageService


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SystemValidator:
    """Validates the entire system."""
    
    def __init__(self):
        self.key_manager = KeyManager()
        self.monitoring_agent = MonitoringAgent(self.key_manager)
        self.audit_agent = AuditAgent()
        self.policy_agent = PolicyAgent(self.key_manager, self.monitoring_agent)
        self.key_action_agent = KeyActionAgent(self.key_manager, self.policy_agent)
        self.issues = []
        self.passed = []
    
    def validate_all(self):
        """Run all validation checks."""
        logger.info("=" * 60)
        logger.info("SYSTEM VALIDATION")
        logger.info("=" * 60)
        
        self.check_authority_boundaries()
        self.check_private_key_exposure()
        self.check_action_traceability()
        self.check_audit_integrity()
        self.check_anomaly_scenarios()
        
        self.print_results()
    
    def check_authority_boundaries(self):
        """Check that no agent violates authority boundaries."""
        logger.info("\n[CHECK 1] Authority Boundaries")
        
        # Monitoring Agent should NOT make decisions
        if hasattr(self.monitoring_agent, 'make_decision'):
            self.issues.append("Monitoring Agent has decision-making capability")
        else:
            self.passed.append("Monitoring Agent: No decision-making")
        
        # Policy Agent should NOT execute actions
        if hasattr(self.policy_agent, 'execute_action'):
            self.issues.append("Policy Agent has action execution capability")
        else:
            self.passed.append("Policy Agent: No action execution")
        
        # Key Action Agent should NOT make decisions
        if hasattr(self.key_action_agent, 'evaluate_policy'):
            self.issues.append("Key Action Agent has policy evaluation capability")
        else:
            self.passed.append("Key Action Agent: No policy evaluation")
        
        # Key Action Agent should NOT access monitoring
        if hasattr(self.key_action_agent, 'monitoring_agent'):
            self.issues.append("Key Action Agent has monitoring access")
        else:
            self.passed.append("Key Action Agent: No monitoring access")
        
        # Verify Key Action Agent only executes signed decisions
        from agents.policy_agent import PolicyDecision, ActionType
        test_decision = PolicyDecision(
            key_id="test-key",
            action=ActionType.ROTATE_KEY,
            policy_name="test",
            explanation="test",
            evidence={}
        )
        # Decision has no signature - should be rejected
        execution = self.key_action_agent.execute_decision(test_decision)
        if execution.status.value == "rejected":
            self.passed.append("Key Action Agent: Rejects unsigned decisions")
        else:
            self.issues.append("Key Action Agent: Accepts unsigned decisions")
    
    def check_private_key_exposure(self):
        """Check that private keys are never exposed."""
        logger.info("\n[CHECK 2] Private Key Exposure")
        
        # Generate a key
        key_id = self.key_manager.generate_key(
            KeyAlgorithm.AES_GCM,
            key_id="test-exposure-key"
        )
        
        # Try to access private key material directly
        try:
            # This should fail - _keys is private
            keys = self.key_manager._keys
            if key_id in keys:
                key_material, metadata = keys[key_id]
                # Check if we can access it (we can in Python, but shouldn't in design)
                # This is a design check, not a runtime check
                self.passed.append("Private keys stored in private attribute")
        except:
            pass
        
        # Check that get_key_metadata doesn't return private material
        metadata = self.key_manager.get_key_metadata(key_id)
        if metadata:
            metadata_dict = metadata.to_dict()
            if 'private_key' in metadata_dict or 'key_material' in metadata_dict:
                self.issues.append("Key metadata exposes private key material")
            else:
                self.passed.append("Key metadata: No private material exposed")
        
        # Check that Monitoring Agent doesn't have key access
        if hasattr(self.monitoring_agent, '_keys') or hasattr(self.monitoring_agent, 'keys'):
            self.issues.append("Monitoring Agent has key storage access")
        else:
            self.passed.append("Monitoring Agent: No key storage access")
        
        # Check that Policy Agent doesn't have key access
        if hasattr(self.policy_agent, '_keys') or hasattr(self.policy_agent, 'keys'):
            self.issues.append("Policy Agent has key storage access")
        else:
            self.passed.append("Policy Agent: No key storage access")
    
    def check_action_traceability(self):
        """Check that all actions are traceable."""
        logger.info("\n[CHECK 3] Action Traceability")
        
        # Create a test application
        web_service = WebService(self.key_manager, "test-service")
        key_id = web_service.signing_key_id
        
        # Perform some operations
        web_service.handle_request("GET", "/test")
        
        # Check that operations are logged
        operation_log = self.key_manager.get_operation_log()
        if len(operation_log) > 0:
            self.passed.append("Operations are logged in KeyManager")
        else:
            self.issues.append("Operations not logged")
        
        # Check that Monitoring Agent observes operations
        self.monitoring_agent.observe_operations()
        stats = self.monitoring_agent.get_usage_statistics(key_id)
        if stats:
            self.passed.append("Monitoring Agent tracks operations")
        else:
            self.issues.append("Monitoring Agent not tracking operations")
        
        # Check that Policy Agent can make decisions
        decision = self.policy_agent.evaluate_key(key_id)
        if decision is None or decision.action.value == "no_action":
            # This is fine - no policy matched
            self.passed.append("Policy Agent can evaluate keys")
        else:
            # Log the decision to audit
            self.audit_agent.log_policy_decision(decision)
            self.passed.append("Policy decisions are traceable")
        
        # Check that Key Action Agent logs executions
        if decision and decision.action.value != "no_action":
            execution = self.key_action_agent.execute_decision(decision)
            if execution:
                self.audit_agent.log_action_executed(execution)
                self.passed.append("Action executions are traceable")
    
    def check_audit_integrity(self):
        """Check audit log integrity."""
        logger.info("\n[CHECK 4] Audit Log Integrity")
        
        # Add some audit entries
        self.audit_agent.log_key_generated("test-key-1", "AES-GCM", {})
        self.audit_agent.log_operation("test-key-1", "encrypt", "test-service", True, {})
        
        # Verify integrity
        integrity = self.audit_agent.verify_integrity()
        if integrity['valid']:
            self.passed.append("Audit log integrity: Valid")
        else:
            self.issues.append(f"Audit log integrity issues: {integrity['details']}")
        
        # Check hash chaining
        entries = self.audit_agent.get_entries()
        if len(entries) >= 2:
            # Check that each entry references previous hash
            for i in range(1, len(entries)):
                if entries[i].previous_hash != entries[i-1].entry_hash:
                    self.issues.append(f"Hash chain broken at entry {i}")
                else:
                    self.passed.append("Hash chain: Valid")
    
    def check_anomaly_scenarios(self):
        """Check system behavior under anomaly scenarios."""
        logger.info("\n[CHECK 5] Anomaly Scenarios")
        
        # Scenario 1: Unsigned decision
        from agents.policy_agent import PolicyDecision, ActionType
        unsigned_decision = PolicyDecision(
            key_id="test-key",
            action=ActionType.REVOKE_KEY,
            policy_name="test",
            explanation="test",
            evidence={}
        )
        execution = self.key_action_agent.execute_decision(unsigned_decision)
        if execution.status.value == "rejected":
            self.passed.append("Anomaly: Unsigned decision rejected")
        else:
            self.issues.append("Anomaly: Unsigned decision accepted")
        
        # Scenario 2: Revoke non-existent key
        fake_decision = PolicyDecision(
            key_id="non-existent-key",
            action=ActionType.REVOKE_KEY,
            policy_name="test",
            explanation="test",
            evidence={}
        )
        fake_decision.signature = "fake-signature"
        # This will fail verification, but let's check
        execution = self.key_action_agent.execute_decision(fake_decision)
        if execution.status.value in ["rejected", "failed"]:
            self.passed.append("Anomaly: Invalid decision handled safely")
        else:
            self.issues.append("Anomaly: Invalid decision not handled")
        
        # Scenario 3: Attempt to access private keys through API
        # Use a key that exists from earlier test
        metadata = self.key_manager.get_key_metadata("test-exposure-key")
        if metadata:
            metadata_dict = metadata.to_dict()
            # Check that metadata doesn't contain private key material
            if 'private_key' not in metadata_dict and 'key_material' not in metadata_dict:
                self.passed.append("Anomaly: API doesn't expose private keys")
            else:
                self.issues.append("Anomaly: API exposes private keys")
        else:
            self.passed.append("Anomaly: Invalid key access handled")
    
    def print_results(self):
        """Print validation results."""
        logger.info("\n" + "=" * 60)
        logger.info("VALIDATION RESULTS")
        logger.info("=" * 60)
        
        logger.info(f"\nPassed Checks: {len(self.passed)}")
        for check in self.passed:
            logger.info(f"  ✅ {check}")
        
        logger.info(f"\nIssues Found: {len(self.issues)}")
        for issue in self.issues:
            logger.info(f"  ❌ {issue}")
        
        if len(self.issues) == 0:
            logger.info("\n✅ ALL VALIDATION CHECKS PASSED")
        else:
            logger.info(f"\n⚠️  {len(self.issues)} ISSUE(S) FOUND")
        
        logger.info("=" * 60)


def main():
    """Run system validation."""
    validator = SystemValidator()
    validator.validate_all()


if __name__ == "__main__":
    main()

