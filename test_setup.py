"""
Simple test to verify CrewAI setup with gpt-4o-mini
"""
import os
from dotenv import load_dotenv

# Load environment
load_dotenv()

# Test 1: Check API key
api_key = os.getenv('OPENAI_API_KEY')
if api_key:
    print(f"✓ API Key found: {api_key[:20]}...")
else:
    print("✗ API Key NOT found")
    exit(1)

# Test 2: Test LangChain OpenAI with explicit key
from langchain_openai import ChatOpenAI

try:
    llm = ChatOpenAI(
        model="gpt-4o-mini",
        api_key=api_key,
        temperature=0.1
    )
    print(f"✓ LLM initialized successfully: {llm.model_name}")
    
    # Test 3: Make a simple call
    response = llm.invoke("Say 'Hello' in one word")
    print(f"✓ API call successful: {response.content}")
    
    print("\n✅ All tests passed! CrewAI should work now.")
    
except Exception as e:
    print(f"✗ Error: {e}")
    exit(1)
