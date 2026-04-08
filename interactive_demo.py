"""
Interactive Demo Script

This script provides an interactive way to explore the system.
Run it and follow the prompts to see how each component works.
"""

import logging
from crypto_core.key_manager import KeyManager, KeyAlgorithm
from agents.monitoring_agent import MonitoringAgent
from agents.policy_agent import PolicyAgent
from agents.key_action_agent import KeyActionAgent
from agents.audit_agent import AuditAgent
from apps.web_service import WebService

logging.basicConfig(level=logging.WARNING)  # Reduce noise
logger = logging.getLogger(__name__)


def print_section(title):
    """Print a formatted section header."""
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)


def demo_key_manager():
    """Demonstrate Key Manager."""
    print_section("1. KEY MANAGER - Creating and Using Keys")
    
    km = KeyManager()
    
    print("\n📝 Creating a new AES-GCM key...")
    key_id = km.generate_key(KeyAlgorithm.AES_GCM, "demo-key")
    print(f"✅ Key created: {key_id}")
    
    print("\n📝 Encrypting some data...")
    plaintext = b"Hello, this is secret data!"
    ciphertext, nonce = km.encrypt(key_id, plaintext)
    print(f"✅ Data encrypted (ciphertext length: {len(ciphertext)} bytes)")
    
    print("\n📝 Decrypting the data...")
    decrypted = km.decrypt(key_id, ciphertext, nonce)
    print(f"✅ Data decrypted: {decrypted.decode()}")
    
    print("\n📝 Checking key metadata...")
    metadata = km.get_key_metadata(key_id)
    print(f"✅ Key algorithm: {metadata.algorithm.value}")
    print(f"✅ Usage count: {metadata.usage_count}")
    print(f"✅ Created: {metadata.created_at}")
    
    return km, key_id


def demo_monitoring(km):
    """Demonstrate Monitoring Agent."""
    print_section("2. MONITORING AGENT - Observing Operations")
    
    monitoring = MonitoringAgent(km)
    
    print("\n📝 Performing some operations...")
    key_id = km.generate_key(KeyAlgorithm.ECDSA, "monitored-key")
    for i in range(5):
        km.sign(key_id, f"Message {i}".encode())
    
    print("\n📝 Monitoring Agent observing operations...")
    monitoring.observe_operations()
    
    print("\n📝 Getting usage statistics...")
    stats = monitoring.get_usage_statistics(key_id)
    if stats:
        print(f"✅ Total operations: {stats['total_operations']}")
        print(f"✅ Operation types: {stats['operation_counts']}")
        print(f"✅ Success rate: {(1 - stats['failure_rate'])*100:.1f}%")
    
    print("\n📝 Checking for anomalies...")
    anomalies = monitoring.detect_anomalies()
    if anomalies:
        print(f"⚠️  Found {len(anomalies)} anomaly signals:")
        for signal in anomalies:
            print(f"   - {signal}")
    else:
        print("✅ No anomalies detected")
    
    return monitoring


def demo_policy(km, monitoring):
    """Demonstrate Policy Agent."""
    print_section("3. POLICY AGENT - Making Decisions")
    
    policy = PolicyAgent(km, monitoring)
    
    print("\n📝 Creating a key to evaluate...")
    key_id = km.generate_key(KeyAlgorithm.AES_GCM, "policy-test-key")
    
    print("\n📝 Generating high usage to trigger policy...")
    # Simulate high usage (exceeds 1000 threshold)
    for i in range(1001):
        km.encrypt(key_id, f"data {i}".encode())
    
    # Update monitoring
    monitoring.observe_operations()
    
    print("\n📝 Policy Agent evaluating key...")
    decision = policy.evaluate_key(key_id)
    
    if decision:
        print(f"✅ Decision made: {decision.action.value}")
        print(f"   Policy: {decision.policy_name}")
        print(f"   Explanation: {decision.explanation}")
        print(f"   Signed: {'Yes' if decision.signature else 'No'}")
        return policy, decision
    else:
        print("✅ No action needed (key complies with policies)")
        return policy, None


def demo_key_action(km, policy, decision):
    """Demonstrate Key Action Agent."""
    print_section("4. KEY ACTION AGENT - Executing Actions")
    
    if not decision:
        print("⚠️  No decision to execute. Skipping...")
        return None
    
    action = KeyActionAgent(km, policy)
    
    print(f"\n📝 Executing decision: {decision.action.value}")
    print(f"   Decision ID: {decision.decision_id}")
    
    execution = action.execute_decision(decision)
    
    print(f"\n✅ Execution status: {execution.status.value}")
    if execution.error:
        print(f"   Error: {execution.error}")
    else:
        print(f"   Result: {execution.result}")
    
    if execution.status.value == "completed" and decision.action.value == "rotate_key":
        print("\n📝 Checking active rotations...")
        rotations = action.get_active_rotations()
        for old_key, info in rotations.items():
            print(f"   Old key: {old_key}")
            print(f"   New key: {info['new_key_id']}")
            print(f"   Grace period ends: {info['grace_period_end']}")
    
    return action


def demo_audit(audit_agent):
    """Demonstrate Audit Agent."""
    print_section("5. AUDIT AGENT - Maintaining Audit Trail")
    
    print("\n📝 Checking audit log integrity...")
    integrity = audit_agent.verify_integrity()
    
    if integrity['valid']:
        print("✅ Audit log integrity: VALID")
    else:
        print("❌ Audit log integrity: INVALID")
        print(f"   Issues: {integrity['details']}")
    
    print(f"\n📝 Audit log statistics:")
    stats = audit_agent.get_statistics()
    print(f"   Total entries: {stats['total_entries']}")
    print(f"   By event type: {stats['by_event_type']}")
    
    print("\n📝 Recent entries:")
    entries = audit_agent.get_entries(limit=5)
    for entry in entries[-5:]:
        print(f"   - {entry.event_type.value}: {entry.timestamp}")


def main():
    """Run the interactive demo."""
    print("\n" + "=" * 60)
    print("INTERACTIVE DEMO: Cryptographic Key Lifecycle Management")
    print("=" * 60)
    print("\nThis demo will walk you through each component of the system.")
    print("Press Enter to continue after each section...")
    
    input("\n>>> Press Enter to start...")
    
    # Initialize audit agent first
    audit = AuditAgent()
    
    # 1. Key Manager
    km, key_id = demo_key_manager()
    input("\n>>> Press Enter to continue to Monitoring Agent...")
    
    # 2. Monitoring Agent
    monitoring = demo_monitoring(km)
    input("\n>>> Press Enter to continue to Policy Agent...")
    
    # 3. Policy Agent
    policy, decision = demo_policy(km, monitoring)
    input("\n>>> Press Enter to continue to Key Action Agent...")
    
    # 4. Key Action Agent
    action = demo_key_action(km, policy, decision)
    input("\n>>> Press Enter to continue to Audit Agent...")
    
    # 5. Audit Agent
    demo_audit(audit)
    
    print_section("DEMO COMPLETE")
    print("\n✅ You've seen all the major components!")
    print("\nNext steps:")
    print("  - Read PRACTICAL_GUIDE.md for detailed usage")
    print("  - Run 'python main.py' for full simulation")
    print("  - Explore the code in each module")
    print("\nHappy exploring! 🚀\n")


if __name__ == "__main__":
    main()

