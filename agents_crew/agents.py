"""
CrewAI Agent Definitions

Defines the specialized agents for key lifecycle management:
- Monitoring Agent: Detects anomalies
- Policy Agent: Evaluates risks and decides actions
- Key Action Agent: Executes lifecycle operations
"""

from crewai import Agent
from langchain_openai import ChatOpenAI


def create_monitoring_agent(tools: list, llm) -> Agent:
    """
    Create the Monitoring Agent.
    
    Role: Security Auditor who analyzes cryptographic operation logs.
    Goal: Detect anomalies and patterns of key misuse.
    """
    return Agent(
        role="Security Auditor",
        goal="Analyze cryptographic operation logs to detect anomalies, excessive usage, old keys, and suspicious patterns",
        backstory="""You are an expert cryptographer and security analyst with years of experience 
        in key management systems. You specialize in detecting patterns of cryptographic misuse, 
        such as keys being used too frequently, keys that are too old and need rotation, or 
        unusual failure rates that might indicate compromise. You follow NIST guidelines for 
        key lifecycle management and are vigilant about security best practices.""",
        tools=tools,
        llm=llm,
        verbose=True,
        allow_delegation=False
    )


def create_policy_agent(tools: list, llm) -> Agent:
    """
    Create the Policy Agent.
    
    Role: Policy Enforcer who evaluates security policies.
    Goal: Decide if keys need rotation, revocation, or alerts.
    """
    return Agent(
        role="Security Policy Enforcer",
        goal="Evaluate key metadata and anomaly signals against security policies, and decide what actions to take (rotate, revoke, or alert)",
        backstory="""You are a strict security officer responsible for enforcing organizational 
        security policies. You have deep knowledge of cryptographic best practices and compliance 
        requirements (NIST, PCI-DSS, GDPR). When you detect policy violations, you make firm 
        decisions about key rotation or revocation. You always provide clear justifications for 
        your decisions based on the evidence and applicable policies. Your decisions are final 
        and must be executed by the Key Action Agent.""",
        tools=tools,
        llm=llm,
        verbose=True,
        allow_delegation=True  # Can delegate to Key Action Agent
    )


def create_action_agent(tools: list, llm) -> Agent:
    """
    Create the Key Action Agent.
    
    Role: Key Administrator who executes lifecycle operations.
    Goal: Safely rotate or revoke keys as directed.
    """
    return Agent(
        role="Key Administrator",
        goal="Execute key lifecycle operations (rotation, revocation) safely and reliably, following policy decisions",
        backstory="""You are a trusted system administrator with root access to the Key Management 
        System. You are responsible for executing key lifecycle operations with precision and care. 
        When given a directive to rotate or revoke a key, you verify the authorization, execute 
        the operation, and confirm completion. You never take action without proper authorization 
        from the Policy Agent. You maintain detailed logs of all operations for audit purposes.""",
        tools=tools,
        llm=llm,
        verbose=True,
        allow_delegation=False
    )


def get_llm(model: str = "gpt-4o-mini", temperature: float = 0.1):
    """
    Get the LLM instance for agents.
    
    Args:
        model: OpenAI model to use (default: gpt-4o-mini for cost efficiency)
        temperature: Temperature for LLM (low for consistent policy decisions)
    """
    import os
    api_key = os.getenv('OPENAI_API_KEY')
    return ChatOpenAI(model=model, temperature=temperature, api_key=api_key)
