"""
Enhanced Main Script with Anomaly Simulation

This version includes configurable scenarios to trigger different agent behaviors:
- Key rotations (high usage)
- Key revocations (high failure rate)
- Alerts (unusual patterns)
"""

import os
import sys
import logging
from dotenv import load_dotenv
from crewai import Crew, Process

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto_core.key_manager import KeyManager, KeyAlgorithm
from agents_crew.tools import (
    GetKeyLogsTool, 
    GetKeyMetadataTool, 
    RotateKeyTool, 
    RevokeKeyTool
)
from agents_crew.agents import (
    create_monitoring_agent,
    create_policy_agent,
    create_action_agent,
    get_llm
)
from agents_crew.tasks import (
    create_monitoring_task,
    create_policy_evaluation_task,
    create_action_execution_task
)

# Import simulated applications
from apps.web_service import WebService
from apps.data_storage import DataStorageService
from apps.file_encryption import FileEncryptionService


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def setup_environment():
    """Load environment variables and verify API key."""
    load_dotenv()
    
    if not os.getenv('OPENAI_API_KEY'):
        logger.error("OPENAI_API_KEY not found in environment!")
        logger.error("Please create a .env file with your OpenAI API key:")
        logger.error("OPENAI_API_KEY=sk-...")
        sys.exit(1)
    
    logger.info("Environment configured successfully")


def simulate_workload_normal(key_manager: KeyManager):
    """Normal workload - moderate usage."""
    logger.info("\n[SCENARIO: NORMAL USAGE]")
    
    web_service = WebService(key_manager)
    data_storage = DataStorageService(key_manager)
    file_encryption = FileEncryptionService(key_manager)
    
    # Moderate usage
    for i in range(50):
        web_service.handle_request("GET", f"/api/data/{i}")
    
    for i in range(30):
        data_storage.store_data(f"user_{i}", f'{{"name": "User {i}"}}'.encode())
    
    files = {f"file_{i}.txt": f"Content {i}".encode() for i in range(20)}
    file_encryption.encrypt_files_batch(files)


def simulate_workload_high_usage(key_manager: KeyManager):
    """High usage workload - will trigger ROTATION."""
    logger.info("\n[SCENARIO: HIGH USAGE - WILL TRIGGER ROTATION]")
    
    web_service = WebService(key_manager)
    data_storage = DataStorageService(key_manager)
    file_encryption = FileEncryptionService(key_manager)
    
    # High usage to trigger rotation (>1000 ops)
    logger.info("Generating 600 web requests (1200 operations)...")
    for i in range(600):
        web_service.handle_request("GET", f"/api/data/{i}")
    
    logger.info("Generating 300 storage operations...")
    for i in range(300):
        data_storage.store_data(f"record_{i}", f'{{"id": {i}}}'.encode())
    
    logger.info("Generating large file batch...")
    files = {f"file_{i}.txt": f"Data {i}".encode() for i in range(200)}
    file_encryption.encrypt_files_batch(files)


def simulate_workload_with_failures(key_manager: KeyManager):
    """
    Simulate failures to trigger REVOCATION.
    
    Strategy: Corrupt a key to cause decryption failures (>5% failure rate).
    """
    logger.info("\n[SCENARIO: KEY COMPROMISE - WILL TRIGGER REVOCATION]")
    
    data_storage = DataStorageService(key_manager)
    
    # 1. First, do some successful encryptions
    logger.info("Phase 1: Normal operations...")
    for i in range(20):
        data_storage.store_data(f"user_{i}", f'{{"name": "User {i}"}}'.encode())
    
    # 2. Simulate key compromise by corrupting the key material
    logger.info("Phase 2: Simulating key compromise (corrupting key)...")
    
    # Get the encryption key ID
    key_id = data_storage.encryption_key_id
    
    # Corrupt the key in the backend to simulate compromise
    # This will cause decryption failures
    metadata = key_manager.get_key_metadata(key_id)
    if metadata:
        # Store corrupted data to simulate key corruption
        import os as os_module
        corrupted_key = os_module.urandom(32)  # Random garbage
        key_manager._backend.store_key(
            key_id, 
            corrupted_key,  # Corrupted key!
            metadata.to_dict()
        )
        logger.info(f"✗ Corrupted key {key_id} to simulate compromise")
    
    # 3. Try to decrypt - this will fail repeatedly
    logger.info("Phase 3: Attempting operations with corrupted key (will fail)...")
    for i in range(20):
        try:
            # Try to retrieve - this will fail due to corruption
            data_storage.retrieve_data(f"user_{i}")
        except Exception as e:
            # Expected - key is corrupted
            pass
    
    logger.info("Failure rate now >5% - should trigger REVOCATION policy")


def simulate_workload_mixed_anomalies(key_manager: KeyManager):
    """Complex scenario with multiple anomalies."""
    logger.info("\n[SCENARIO: MIXED ANOMALIES]")
    
    web_service = WebService(key_manager)
    data_storage = DataStorageService(key_manager)
    file_encryption = FileEncryptionService(key_manager)
    
    # Anomaly 1: Burst traffic on web service
    logger.info("Anomaly 1: Traffic burst on web service...")
    for i in range(100):
        web_service.handle_request("POST", f"/api/urgent/{i}")
    
    # Anomaly 2: High encryption volume
    logger.info("Anomaly 2: Mass encryption event...")
    for i in range(500):
        data_storage.store_data(f"bulk_{i}", f'{{"data": {i}}}'.encode())
    
    # Anomaly 3: Unusual file encryption pattern
    logger.info("Anomaly 3: Large file batch...")
    files = {f"sensitive_{i}.dat": f"Secret {i}".encode() for i in range(300)}
    file_encryption.encrypt_files_batch(files)


def run_crew(key_manager: KeyManager):
    """Run the CrewAI agents to autonomously manage key lifecycle."""
    logger.info("\n" + "="*60)
    logger.info("PHASE 2: Running CrewAI Agents")
    logger.info("="*60)
    
    # Initialize LLM
    llm = get_llm()
    
    # Create tools
    tools = [
        GetKeyLogsTool(key_manager=key_manager),
        GetKeyMetadataTool(key_manager=key_manager),
        RotateKeyTool(key_manager=key_manager),
        RevokeKeyTool(key_manager=key_manager)
    ]
    
    # Create agents
    logger.info("\nInitializing agents...")
    monitoring_agent = create_monitoring_agent(tools, llm)
    policy_agent = create_policy_agent(tools, llm)
    action_agent = create_action_agent(tools, llm)
    
    # Create tasks
    logger.info("Creating task sequence...")
    task1 = create_monitoring_task(monitoring_agent, tools)
    task2 = create_policy_evaluation_task(policy_agent, tools, context_tasks=[task1])
    task3 = create_action_execution_task(action_agent, tools, context_tasks=[task1, task2])
    
    # Create crew
    crew = Crew(
        agents=[monitoring_agent, policy_agent, action_agent],
        tasks=[task1, task2, task3],
        process=Process.sequential,
        verbose=True
    )
    
    # Run the crew
    logger.info("\n" + "="*60)
    logger.info("Starting Autonomous Key Lifecycle Management...")
    logger.info("="*60 + "\n")
    
    result = crew.kickoff()
    
    return result


def print_summary(key_manager: KeyManager):
    """Print a summary of key states after agent actions."""
    logger.info("\n" + "="*60)
    logger.info("PHASE 3: Summary")
    logger.info("="*60)
    
    all_metadata = key_manager.get_all_key_metadata()
    
    logger.info(f"\nTotal keys in system: {len(all_metadata)}")
    
    active_keys = [k for k in all_metadata if not k['is_revoked'] and not k['is_rotated']]
    rotated_keys = [k for k in all_metadata if k['is_rotated']]
    revoked_keys = [k for k in all_metadata if k['is_revoked']]
    
    logger.info(f"Active keys: {len(active_keys)}")
    logger.info(f"Rotated keys: {len(rotated_keys)}")
    logger.info(f"Revoked keys: {len(revoked_keys)}")
    
    if rotated_keys:
        logger.info("\nRotated keys:")
        for key in rotated_keys:
            logger.info(f"  - {key['key_id']}")
    
    if revoked_keys:
        logger.info("\nRevoked keys:")
        for key in revoked_keys:
            logger.info(f"  - {key['key_id']}")


def main():
    """Main execution flow with scenario selection."""
    print("\n" + "="*60)
    print("KRYPTO: Autonomous Key Lifecycle Management")
    print("Powered by CrewAI")
    print("="*60 + "\n")
    
    # Setup
    setup_environment()
    
    # Initialize Key Manager
    logger.info("Initializing Key Management System...")
    key_manager = KeyManager()
    
    # Choose scenario
    print("\nAvailable Scenarios:")
    print("1. Normal Usage (no violations)")
    print("2. High Usage (triggers ROTATION)")
    print("3. Key Compromise (triggers REVOCATION)")
    print("4. Mixed Anomalies (multiple violations)")
    print("5. Custom (edit code to customize)")
    
    # For automation, use scenario 2 by default
    # Change this to test different scenarios:
    SCENARIO =  3# <-- CHANGE THIS (1-4)

    logger.info(f"\n[Running Scenario {SCENARIO}]")
    logger.info("="*60)
    logger.info("PHASE 1: Simulating Application Workload")
    logger.info("="*60)
    
    scenarios = {
        1: simulate_workload_normal,
        2: simulate_workload_high_usage,
        3: simulate_workload_with_failures,
        4: simulate_workload_mixed_anomalies
    }
    
    # Run selected scenario
    scenarios.get(SCENARIO, simulate_workload_normal)(key_manager)
    
    logger.info("\nWorkload simulation complete!")
    logger.info(f"Total operations logged: {len(key_manager.get_operation_log())}")
    
    # Phase 2: Run CrewAI agents
    result = run_crew(key_manager)
    
    # Phase 3: Show summary
    print_summary(key_manager)
    
    logger.info("\n" + "="*60)
    logger.info("Autonomous key lifecycle management complete!")
    logger.info("="*60 + "\n")


if __name__ == "__main__":
    main()
