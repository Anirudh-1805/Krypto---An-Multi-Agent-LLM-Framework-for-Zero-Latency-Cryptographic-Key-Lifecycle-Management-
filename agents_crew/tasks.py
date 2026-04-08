"""
CrewAI Task Definitions

Defines the tasks that agents will perform in sequence.
"""

from crewai import Task


def create_monitoring_task(agent, tools) -> Task:
    """
    Task 1: Analyze usage logs and detect anomalies.
    
    Assigned to: Monitoring Agent
    """
    description = """
    Analyze the cryptographic operation logs from the Key Management System.
    
    Your objectives:
    1. Use the get_key_logs tool to retrieve recent operation logs
    2. Use the get_key_metadata tool to get information about all keys
    3. Identify any concerning patterns:
       - Keys older than 90 days
       - Keys with more than 1000 operations
       - Keys with high usage rates (>10 ops/min)
       - Keys with failure rates >5%
    4. Summarize your findings with specific key IDs and metrics
    
    Be thorough and specific. List all problematic keys you find.
    """
    
    expected_output = """
    A detailed report listing:
    - All keys with anomalies (by key ID)
    - Specific metrics for each key (age, usage count, failure rate)
    - Recommended priority level (low, medium, high, critical)
    """
    
    return Task(
        description=description,
        expected_output=expected_output,
        agent=agent,
        tools=tools
    )


def create_policy_evaluation_task(agent, tools, context_tasks: list) -> Task:
    """
    Task 2: Evaluate policies and decide actions.
    
    Assigned to: Policy Agent
    Depends on: Monitoring Task results
    """
    description = """
    Based on the Security Auditor's findings, evaluate each problematic key against 
    security policies and decide what action to take.
    
    Security Policies:
    1. ROTATE keys that are:
       - Older than 90 days
       - Have been used more than 1000 times
    
    2. REVOKE keys that are:
       - Have a failure rate exceeding 5% (possible compromise)
    
    3. ALERT only (no action) for:
       - High usage rate (>10 ops/min) but not meeting other criteria
    
    For each problematic key:
    - State the key ID
    - State the policy violated
    - State the action (ROTATE, REVOKE, or ALERT)
    - Provide justification
    
    Create a prioritized action list.
    """
    
    expected_output = """
    A prioritized action list with:
    - Key ID
    - Action (ROTATE/REVOKE/ALERT)
    - Policy violated
    - Justification based on evidence
    """
    
    return Task(
        description=description,
        expected_output=expected_output,
        agent=agent,
        tools=tools,
        context=context_tasks  # Uses monitoring task results
    )


def create_action_execution_task(agent, tools, context_tasks: list) -> Task:
    """
    Task 3: Execute the decided actions.
    
    Assigned to: Key Action Agent
    Depends on: Policy Evaluation results
    """
    description = """
    Execute the key lifecycle actions as decided by the Security Policy Enforcer.
    
    For each action in the prioritized list:
    1. For ROTATE actions:
       - Use the rotate_key tool with the key ID and policy reason
       - Confirm the new key was created successfully
    
    2. For REVOKE actions:
       - Use the revoke_key tool with the key ID and policy reason
       - Confirm revocation
    
    3. For ALERT actions:
       - Log the alert (no tool action needed)
    
    Execute actions in priority order and report results.
    Be cautious and verify each action was successful.
    """
    
    expected_output = """
    An execution report listing:
    - Each action taken (ROTATED/REVOKED/ALERTED)
    - Key ID affected
    - Success/failure status
    - Any errors encountered
    """
    
    return Task(
        description=description,
        expected_output=expected_output,
        agent=agent,
        tools=tools,
        context=context_tasks  # Uses policy evaluation results
    )
