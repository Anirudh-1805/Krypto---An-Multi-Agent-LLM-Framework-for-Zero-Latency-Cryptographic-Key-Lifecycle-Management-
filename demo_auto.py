"""
Automatic Demo Script

This script demonstrates the system without requiring user input.
Run it to see a complete walkthrough of all components.
"""

import logging
import time
from crypto_core.key_manager import KeyManager, KeyAlgorithm
from agents.monitoring_agent import MonitoringAgent
from agents.policy_agent import PolicyAgent
from agents.key_action_agent import KeyActionAgent
from agents.audit_agent import AuditAgent
from apps.web_service import WebService

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)


def print_section(title):
    """Print a formatted section header."""
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60 + "\n")


def main():
    """Run the automatic demo."""
    print("\n" + "=" * 60)
    print("AUTOMATIC DEMO: Cryptographic Key Lifecycle Management")
    print("=" * 60)
    print("\nThis demo walks through each component automatically.\n")
    time.sleep(1)
    
    # Initialize all components
    print("Initializing components...")
    km = KeyManager()
    monitoring = MonitoringAgent(km)
    audit = AuditAgent()
    policy = PolicyAgent(km, monitoring)
    action = KeyActionAgent(km, policy)
    print("[OK] All components initialized\n")
    time.sleep(1)
    
    # 1. Key Manager
    print_section("1. KEY MANAGER - Creating and Using Keys")
    key_id = km.generate_key(KeyAlgorithm.AES_GCM, "demo-key")
    print(f"[OK] Created key: {key_id}")
    
    plaintext = b"Hello, this is secret data!"
    ciphertext, nonce = km.encrypt(key_id, plaintext)
    print(f"[OK] Encrypted data (ciphertext: {len(ciphertext)} bytes)")
    
    decrypted = km.decrypt(key_id, ciphertext, nonce)
    print(f"[OK] Decrypted: {decrypted.decode()}")
    
    metadata = km.get_key_metadata(key_id)
    print(f"[OK] Key metadata: {metadata.algorithm.value}, {metadata.usage_count} uses")
    time.sleep(1)
    
    # 2. Monitoring Agent
    print_section("2. MONITORING AGENT - Observing Operations")
    monitored_key = km.generate_key(KeyAlgorithm.ECDSA, "monitored-key")
    print(f"[OK] Created key for monitoring: {monitored_key}")
    
    for i in range(5):
        km.sign(monitored_key, f"Message {i}".encode())
    print("[OK] Performed 5 signing operations")
    
    monitoring.observe_operations()
    stats = monitoring.get_usage_statistics(monitored_key)
    print(f"[OK] Statistics: {stats['total_operations']} operations, "
          f"{stats['operation_counts']}")
    
    anomalies = monitoring.detect_anomalies()
    print(f"[OK] Anomaly check: {len(anomalies)} signals detected")
    time.sleep(1)
    
    # 3. Policy Agent
    print_section("3. POLICY AGENT - Making Decisions")
    policy_key = km.generate_key(KeyAlgorithm.AES_GCM, "policy-test-key")
    print(f"[OK] Created key for policy test: {policy_key}")
    
    # Simulate high usage
    print("[INFO] Simulating high usage (1001 operations)...")
    for i in range(1001):
        km.encrypt(policy_key, f"data {i}".encode())
    
    monitoring.observe_operations()
    decision = policy.evaluate_key(policy_key)
    
    if decision:
        print(f"[OK] Decision: {decision.action.value}")
        print(f"   Policy: {decision.policy_name}")
        print(f"   Explanation: {decision.explanation[:60]}...")
        print(f"   Signed: {'Yes' if decision.signature else 'No'}")
    else:
        print("[OK] No action needed")
    time.sleep(1)
    
    # 4. Key Action Agent
    print_section("4. KEY ACTION AGENT - Executing Actions")
    if decision:
        print(f"[INFO] Executing decision: {decision.action.value}")
        execution = action.execute_decision(decision)
        print(f"[OK] Execution status: {execution.status.value}")
        if execution.result:
            print(f"   Result: {list(execution.result.keys())}")
    else:
        print("[WARN]  No decision to execute")
    time.sleep(1)
    
    # 5. Audit Agent
    print_section("5. AUDIT AGENT - Maintaining Audit Trail")
    integrity = audit.verify_integrity()
    print(f"[OK] Audit log integrity: {'VALID' if integrity['valid'] else 'INVALID'}")
    
    stats = audit.get_statistics()
    print(f"[OK] Total entries: {stats['total_entries']}")
    print(f"[OK] Event types: {list(stats['by_event_type'].keys())}")
    
    # 6. Full Workflow
    print_section("6. FULL WORKFLOW - Complete Example")
    print("[INFO] Creating a web service and using it...")
    web_service = WebService(km, "demo-web-service")
    
    for i in range(3):
        response = web_service.handle_request("GET", f"/api/demo/{i}")
        print(f"   Request {i+1}: Status {response['status']}")
    
    monitoring.observe_operations()
    web_key = web_service.signing_key_id
    
    print(f"\n[INFO] Checking monitoring for key: {web_key}")
    web_stats = monitoring.get_usage_statistics(web_key)
    if web_stats:
        print(f"   Operations: {web_stats['total_operations']}")
        print(f"   Services: {web_stats['services_using']}")
    
    print(f"\n[INFO] Evaluating policies for key: {web_key}")
    web_decision = policy.evaluate_key(web_key)
    if web_decision:
        print(f"   Decision: {web_decision.action.value}")
    else:
        print("   No action needed")
    
    print_section("DEMO COMPLETE")
    print("[OK] You've seen all major components in action!")
    print("\nNext steps:")
    print("  [READ] Read QUICK_START.md for quick reference")
    print("  [READ] Read PRACTICAL_GUIDE.md for detailed usage")
    print("  [GO] Run 'python main.py' for full simulation")
    print("  [EXPLORE] Explore the code in each module")
    print("\nHappy exploring! [GO]\n")


if __name__ == "__main__":
    main()

