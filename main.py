"""
Main Entry Point: Simulated Application Ecosystem with Monitoring and Policy Agents

This script demonstrates:
- Increment 1: Applications using cryptographic keys through Key Management API
- Increment 3: Monitoring Agent observing operations and detecting anomalies
- Increment 4: Policy Agent evaluating policies and making decisions
"""

import logging
import time
import json
from crypto_core.key_manager import KeyManager
from apps.web_service import WebService
from apps.data_storage import DataStorageService
from apps.file_encryption import FileEncryptionService
from agents.monitoring_agent import MonitoringAgent
from agents.policy_agent import PolicyAgent, ActionType
from agents.key_action_agent import KeyActionAgent
from agents.audit_agent import AuditAgent


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


def simulate_web_service_workload(web_service: WebService, num_requests: int = 20):
    """Simulate web service workload with excessive signing."""
    logger.info("=" * 60)
    logger.info("Simulating Web Service Workload")
    logger.info("=" * 60)
    
    for i in range(num_requests):
        # Simulate various HTTP requests
        method = "GET" if i % 3 == 0 else "POST"
        path = f"/api/endpoint/{i % 5}"
        body = f"Request body {i}".encode('utf-8') if method == "POST" else None
        
        response = web_service.handle_request(method, path, body)
        logger.info(f"Request {i+1}: {method} {path} -> Status {response['status']}")
        
        # Small delay to simulate real-world timing
        time.sleep(0.1)
    
    stats = web_service.get_stats()
    logger.info(f"\nWeb Service Stats:")
    logger.info(f"  Total requests: {stats['request_count']}")
    logger.info(f"  Key usage count: {stats['key_usage_count']}")
    logger.info(f"  Key age: {stats['key_age_days']} days")


def simulate_data_storage_workload(storage: DataStorageService, num_records: int = 15):
    """Simulate data storage workload with repeated encryption/decryption."""
    logger.info("\n" + "=" * 60)
    logger.info("Simulating Data Storage Service Workload")
    logger.info("=" * 60)
    
    # Store records
    for i in range(num_records):
        record_id = f"user_data_{i}"
        data = f"Sensitive user data for record {i}".encode('utf-8')
        storage.store_data(record_id, data)
        logger.info(f"Stored record: {record_id}")
        time.sleep(0.05)
    
    # Retrieve some records (causing more key usage)
    logger.info("\nRetrieving records...")
    for i in range(0, num_records, 3):  # Retrieve every 3rd record
        record_id = f"user_data_{i}"
        data = storage.retrieve_data(record_id)
        if data:
            logger.info(f"Retrieved record: {record_id} -> {data.decode('utf-8')[:30]}...")
        time.sleep(0.05)
    
    stats = storage.get_stats()
    logger.info(f"\nData Storage Stats:")
    logger.info(f"  Total operations: {stats['operation_count']}")
    logger.info(f"  Stored records: {stats['stored_records']}")
    logger.info(f"  Key usage count: {stats['key_usage_count']}")
    logger.info(f"  Key age: {stats['key_age_days']} days")


def simulate_file_encryption_workload(file_service: FileEncryptionService):
    """Simulate file encryption workload with batch operations."""
    logger.info("\n" + "=" * 60)
    logger.info("Simulating File Encryption Service Workload")
    logger.info("=" * 60)
    
    # Individual file operations
    logger.info("Encrypting individual files...")
    for i in range(5):
        filename = f"document_{i}.txt"
        content = f"Content of document {i}".encode('utf-8')
        file_service.encrypt_file(filename, content)
        time.sleep(0.05)
    
    # Batch operation (causes usage spike)
    logger.info("\nPerforming batch encryption (usage spike)...")
    batch_files = {
        f"batch_file_{i}.txt": f"Batch file content {i}".encode('utf-8')
        for i in range(10)
    }
    success_count = file_service.encrypt_files_batch(batch_files)
    logger.info(f"Batch encryption: {success_count} files encrypted")
    
    # Decrypt some files
    logger.info("\nDecrypting files...")
    for filename in list(file_service.list_files())[:3]:
        content = file_service.decrypt_file(filename)
        if content:
            logger.info(f"Decrypted: {filename} -> {content.decode('utf-8')[:30]}...")
        time.sleep(0.05)
    
    stats = file_service.get_stats()
    logger.info(f"\nFile Encryption Stats:")
    logger.info(f"  Total operations: {stats['operation_count']}")
    logger.info(f"  Encrypted files: {stats['encrypted_files']}")
    logger.info(f"  Key usage count: {stats['key_usage_count']}")
    logger.info(f"  Key age: {stats['key_age_days']} days")


def display_monitoring_results(monitoring_agent: MonitoringAgent):
    """Display monitoring agent results."""
    logger.info("\n" + "=" * 60)
    logger.info("Monitoring Agent Results")
    logger.info("=" * 60)
    
    # Get usage statistics
    usage_stats = monitoring_agent.get_usage_statistics()
    
    if not usage_stats:
        logger.info("No usage statistics available.")
        return
    
    logger.info(f"\nUsage Statistics for {len(usage_stats)} keys:\n")
    
    for key_id, stats in usage_stats.items():
        logger.info(f"Key: {key_id}")
        logger.info(f"  Total operations: {stats['total_operations']}")
        logger.info(f"  Success rate: {(1 - stats['failure_rate'])*100:.1f}%")
        logger.info(f"  Key age: {stats.get('key_age_days', 0):.1f} days")
        logger.info(f"  Usage rate: {stats.get('usage_rate_per_minute', 0):.2f} ops/min")
        logger.info(f"  Services using: {', '.join(stats.get('services_using', []))}")
        logger.info("")
    
    # Get anomaly signals
    anomaly_signals = monitoring_agent.get_anomaly_signals()
    
    if anomaly_signals:
        logger.info(f"\nAnomaly Signals Detected: {len(anomaly_signals)}\n")
        for signal in anomaly_signals:
            logger.info(f"  {signal}")
            logger.info(f"    Evidence: {json.dumps(signal.evidence, indent=6)}")
    else:
        logger.info("\nNo anomaly signals detected.")


def display_policy_decisions(policy_agent: PolicyAgent):
    """Display policy agent decisions."""
    logger.info("\n" + "=" * 60)
    logger.info("Policy Agent Decisions")
    logger.info("=" * 60)
    
    decisions = policy_agent.get_decisions()
    
    if not decisions:
        logger.info("No policy decisions made (no actions needed).")
        return
    
    logger.info(f"\nTotal decisions: {len(decisions)}\n")
    
    # Group by action type
    by_action = {}
    for decision in decisions:
        action = decision.action.value
        if action not in by_action:
            by_action[action] = []
        by_action[action].append(decision)
    
    for action_type, action_decisions in sorted(by_action.items()):
        logger.info(f"\n{action_type.upper()} Decisions ({len(action_decisions)}):")
        for decision in action_decisions:
            logger.info(f"\n  Decision ID: {decision.decision_id}")
            logger.info(f"  Key ID: {decision.key_id}")
            logger.info(f"  Policy: {decision.policy_name}")
            logger.info(f"  Explanation: {decision.explanation}")
            logger.info(f"  Evidence: {json.dumps(decision.evidence, indent=4)}")
            logger.info(f"  Signed: {'Yes' if decision.signature else 'No'}")
            
            # Verify signature
            if decision.signature:
                verified = policy_agent.verify_decision(decision)
                logger.info(f"  Signature Verified: {verified}")


def main():
    """Main simulation function."""
    logger.info("=" * 60)
    logger.info("Increments 1, 3, 4: Application Ecosystem + Monitoring + Policy")
    logger.info("=" * 60)
    logger.info("\nThis simulation demonstrates:")
    logger.info("  - Increment 1: Applications using cryptographic keys")
    logger.info("  - Increment 3: Monitoring Agent observing operations")
    logger.info("  - Increment 4: Policy Agent making decisions")
    logger.info("")
    
    # Initialize Key Manager (central API)
    key_manager = KeyManager()
    logger.info("Initialized Key Manager")
    
    # Initialize Audit Agent (first, as others will log to it)
    audit_agent = AuditAgent()
    logger.info("Initialized Audit Agent")
    
    # Initialize Monitoring Agent
    monitoring_agent = MonitoringAgent(key_manager)
    logger.info("Initialized Monitoring Agent")
    
    # Initialize Policy Agent
    policy_agent = PolicyAgent(key_manager, monitoring_agent)
    logger.info("Initialized Policy Agent")
    
    # Initialize Key Action Agent
    key_action_agent = KeyActionAgent(key_manager, policy_agent)
    logger.info("Initialized Key Action Agent\n")
    
    # Initialize applications
    web_service = WebService(key_manager, "web-api")
    data_storage = DataStorageService(key_manager, "user-database")
    file_service = FileEncryptionService(key_manager, "file-storage")
    
    logger.info("All applications initialized\n")
    time.sleep(1)
    
    # Run workloads
    logger.info("=" * 60)
    logger.info("PHASE 1: Application Workloads")
    logger.info("=" * 60)
    
    simulate_web_service_workload(web_service, num_requests=20)
    time.sleep(0.5)
    
    simulate_data_storage_workload(data_storage, num_records=15)
    time.sleep(0.5)
    
    simulate_file_encryption_workload(file_service)
    time.sleep(1)
    
    # Monitoring Agent observes operations
    logger.info("\n" + "=" * 60)
    logger.info("PHASE 2: Monitoring Agent Analysis")
    logger.info("=" * 60)
    
    monitoring_agent.observe_operations()
    anomaly_signals = monitoring_agent.detect_anomalies()
    
    if anomaly_signals:
        logger.info(f"\nMonitoring Agent detected {len(anomaly_signals)} new anomaly signals:")
        for signal in anomaly_signals:
            logger.info(f"  - {signal}")
    
    display_monitoring_results(monitoring_agent)
    time.sleep(1)
    
    # Policy Agent evaluates policies
    logger.info("\n" + "=" * 60)
    logger.info("PHASE 3: Policy Agent Evaluation")
    logger.info("=" * 60)
    
    decisions = policy_agent.evaluate_all_keys()
    
    if decisions:
        logger.info(f"\nPolicy Agent made {len(decisions)} decisions:")
        for decision in decisions:
            logger.info(f"  - {decision}")
            # Log to audit
            audit_agent.log_policy_decision(decision)
    else:
        logger.info("\nPolicy Agent: No actions needed (all keys comply with policies)")
    
    display_policy_decisions(policy_agent)
    time.sleep(1)
    
    # Key Action Agent executes decisions
    logger.info("\n" + "=" * 60)
    logger.info("PHASE 4: Key Action Agent Execution")
    logger.info("=" * 60)
    
    if decisions:
        logger.info(f"\nExecuting {len(decisions)} policy decisions...")
        for decision in decisions:
            execution = key_action_agent.execute_decision(decision)
            logger.info(f"  Decision {decision.decision_id}: {execution.status.value}")
            if execution.error:
                logger.warning(f"    Error: {execution.error}")
            # Log to audit
            audit_agent.log_action_executed(execution)
    else:
        logger.info("No decisions to execute")
    
    # Display audit log
    logger.info("\n" + "=" * 60)
    logger.info("PHASE 5: Audit Log")
    logger.info("=" * 60)
    
    integrity = audit_agent.verify_integrity()
    logger.info(f"\nAudit Log Integrity: {'✅ VALID' if integrity['valid'] else '❌ INVALID'}")
    logger.info(f"Total entries: {integrity['total_entries']}")
    logger.info(f"Last hash: {integrity['last_hash'][:16]}...")
    
    stats = audit_agent.get_statistics()
    logger.info(f"\nAudit Statistics:")
    logger.info(f"  By event type: {json.dumps(stats['by_event_type'], indent=4)}")
    
    if not integrity['valid']:
        logger.error(f"Issues: {integrity['details']}")
    
    logger.info("\n" + "=" * 60)
    logger.info("Simulation Complete")
    logger.info("=" * 60)
    logger.info("\nSummary:")
    logger.info("  - Applications created keys and performed operations")
    logger.info("  - Monitoring Agent observed all operations and detected anomalies")
    logger.info("  - Policy Agent evaluated policies and made decisions")
    logger.info("  - All decisions are signed and verifiable")
    logger.info("  - Next: Key Action Agent will execute these decisions")
    logger.info("")


if __name__ == "__main__":
    main()

