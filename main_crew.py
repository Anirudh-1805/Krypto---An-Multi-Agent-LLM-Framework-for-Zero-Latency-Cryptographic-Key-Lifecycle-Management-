"""
Main CrewAI Orchestration Script

This script demonstrates the autonomous key lifecycle management system 
using CrewAI agents.
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


def simulate_workload(key_manager: KeyManager):
    """
    Simulate application workload to generate key usage data.
    This creates the conditions that the agents will detect and fix.
    """
    logger.info("\n" + "="*60)
    logger.info("PHASE 1: Simulating Application Workload")
    logger.info("="*60)
    
    # Create simulated applications
    web_service = WebService(key_manager)
    data_storage = DataStorageService(key_manager)
    file_encryption = FileEncryptionService(key_manager)
    
    # Simulate workloads that will trigger policies
    logger.info("\n[Web Service] Processing requests...")
    for i in range(600):
        
        web_service.handle_request("GET", f"/api/data/{i}")
    
    logger.info("[Data Storage] Encrypting records...")
    for i in range(30):
        data_storage.store_data(f"user_{i}", f"{{\"name\": \"User {i}\", \"data\": \"sensitive\"}}".encode())
    
    logger.info("[File Encryption] Encrypting files...")
    files_to_encrypt = {f"file_{i}.txt": f"Content of file {i}".encode() for i in range(20)}
    file_encryption.encrypt_files_batch(files_to_encrypt)
    
    logger.info("\nWorkload simulation complete!")
    logger.info(f"Total operations logged: {len(key_manager.get_operation_log())}")


def run_crew(key_manager: KeyManager):
    """
    Run the CrewAI agents to autonomously manage key lifecycle.
    """
    logger.info("\n" + "="*60)
    logger.info("PHASE 2: Running CrewAI Agents")
    logger.info("="*60)
    
    # Initialize LLM
    llm = get_llm()
    
    # Create tools (all agents get access to all tools)
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
        process=Process.sequential,  # Tasks run in order
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
    """Main execution flow."""
    print("\n" + "="*60)
    print("KRYPTO: Autonomous Key Lifecycle Management")
    print("Powered by CrewAI")
    print("="*60 + "\n")
    
    # Setup
    setup_environment()
    
    # Initialize Key Manager
    logger.info("Initializing Key Management System...")
    key_manager = KeyManager()
    
    # Phase 1: Simulate workload
    simulate_workload(key_manager)
    
    # Phase 2: Run CrewAI agents
    result = run_crew(key_manager)
    
    # Phase 3: Show summary
    print_summary(key_manager)
    
    logger.info("\n" + "="*60)
    logger.info("Autonomous key lifecycle management complete!")
    logger.info("="*60 + "\n")


if __name__ == "__main__":
    main()
