# An Agentic System for Autonomous Cryptographic Key Lifecycle Management

## 🚀 Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run the system
python main.py

# Validate security
python system_validation.py
```

**New to the system?** Start with [QUICK_START.md](QUICK_START.md) or [PRACTICAL_GUIDE.md](PRACTICAL_GUIDE.md)

## Implemented Increments

### Increment 1: Simulated Application Ecosystem ✅
### Increment 2: Cryptographic Core ✅ (cross-checked with requirements)
### Increment 3: Monitoring Agent ✅
### Increment 4: Policy Agent ✅

## Increment 1: Simulated Application Ecosystem

This increment implements the foundation of the system: simulated applications that consume cryptographic keys through a central Key Management API.

### Architecture Overview

The system follows strict separation of concerns:

- **Applications** (`apps/`): Simulated services that need cryptographic operations
- **Cryptographic Core** (`crypto_core/`): Central Key Management API and cryptographic operations
- **No Agents Yet**: Monitoring, Policy, Key Action, and Audit agents will be added in future increments

### Components

#### Cryptographic Core (`crypto_core/`)

- **`key_manager.py`**: Central Key Management API
  - Applications request cryptographic operations through this interface
  - Private keys are stored internally and never exposed
  - All operations are logged for future monitoring
  - Supports AES-GCM (encryption), RSA/ECDSA (signing)

- **`crypto_operations.py`**: Standard cryptographic primitives
  - Uses the `cryptography` library (standard Python crypto)
  - Implements AES-GCM, RSA, ECDSA, SHA-256
  - No key storage (handled by KeyManager)

#### Simulated Applications (`apps/`)

1. **Web Service** (`web_service.py`)
   - Signs HTTP requests and responses
   - Misuse pattern: Single long-lived key, signs every request/response
   - Algorithm: ECDSA

2. **Data Storage Service** (`data_storage.py`)
   - Encrypts data at rest
   - Misuse pattern: One key for all records, never rotates
   - Algorithm: AES-GCM

3. **File Encryption Service** (`file_encryption.py`)
   - Encrypts files before storage
   - Misuse pattern: Batch operations cause usage spikes
   - Algorithm: AES-GCM

### Design Choices

1. **Central Key Management API**: All applications must use `KeyManager` - they cannot manage keys directly. This enforces the constraint that applications never see private key material.

2. **Static Key IDs**: Applications use hardcoded key IDs (e.g., `"web-service-signing-key-v1"`). This demonstrates the misuse pattern of static configurations that never change.

3. **Operation Logging**: Every cryptographic operation is logged with metadata (key ID, operation type, success/failure, timestamps). This log will be consumed by the Monitoring Agent in future increments.

4. **In-Memory Key Storage**: For simulation purposes, keys are stored in memory. In a real system, this would be a secure key store with proper access controls.

5. **No Lifecycle Management**: Applications never rotate or revoke keys - they just use them. This is intentional to demonstrate what the autonomous agents will need to fix.

### Installation

```bash
# Install dependencies
pip install -r requirements.txt
```

### Running the Simulation

```bash
python main.py
```

This will:
1. Initialize the Key Manager
2. Create three simulated applications
3. Run workloads that demonstrate misuse patterns
4. Display key usage statistics and operation logs

### Expected Output

The simulation will show:
- Each application creating and using cryptographic keys
- High usage counts (excessive repeated operations)
- All operations being logged
- No key rotation or lifecycle management

## Increment 2: Cryptographic Core ✅

**Status**: Implemented and cross-checked with requirements.

### Requirements Met:
- ✅ Standard cryptographic primitives (AES-GCM, RSA, ECDSA, HMAC-SHA256, SHA-256)
- ✅ Centralized Key Management API (`KeyManager`)
- ✅ Secure key generation and storage (in-memory for simulation)
- ✅ Key metadata (id, algorithm, creation time, state)
- ✅ No exposure of raw private keys
- ✅ Applications interact ONLY via API
- ✅ Clear API interface with error handling

### Components:
- `crypto_core/key_manager.py`: Central Key Management API
- `crypto_core/crypto_operations.py`: Cryptographic primitives

## Increment 3: Monitoring Agent ✅

**Status**: Implemented and tested.

### Requirements Met:
- ✅ Observes all cryptographic operations
- ✅ Records key usage events (key_id, service_id, operation, timestamp)
- ✅ Aggregates usage statistics
- ✅ Generates anomaly signals based on simple rules (thresholds, frequency)
- ✅ Does NOT make decisions
- ✅ Does NOT trigger actions
- ✅ Does NOT access private keys

### Components:
- `agents/monitoring_agent.py`: Monitoring Agent implementation
  - `UsageEvent`: Represents a single key usage event
  - `UsageStatistics`: Aggregated statistics per key
  - `AnomalySignal`: Detected anomalies with severity levels

### Anomaly Detection Rules:
- Excessive usage count (threshold: 1000 operations)
- Key age (threshold: 90 days)
- High usage rate (threshold: 10 ops/min)
- High failure rate (threshold: 5%)

## Increment 4: Policy Agent ✅

**Status**: Implemented and tested.

### Requirements Met:
- ✅ Evaluates key metadata + monitoring signals
- ✅ Applies explicit, predefined security policies (JSON/YAML)
- ✅ Decides actions: Rotate key, Revoke key, Alert, No action
- ✅ Generates signed, verifiable policy decisions
- ✅ Provides human-readable explanations for every decision
- ✅ Does NOT execute actions
- ✅ Does NOT access raw private keys

### Components:
- `agents/policy_agent.py`: Policy Agent implementation
  - `PolicyRule`: Represents a policy rule with conditions
  - `PolicyDecision`: Signed decision with explanation
  - `PolicyAgent`: Evaluates policies and makes decisions

### Default Policies:
- Rotate keys older than 90 days
- Rotate keys with excessive usage (>1000 operations)
- Revoke keys with high failure rate (>5%)
- Alert on high usage rate (>10 ops/min)
- Alert on critical anomaly signals

### Policy Configuration:
- `policies/default_policies.json`: Declarative policy definitions

### Next Steps (Future Increments)

- **Increment 5**: Key Action Agent - executes lifecycle operations
- **Increment 6**: Audit Agent - maintains immutable audit trail

### Constraints

- ✅ Uses only standard cryptographic libraries (`cryptography`)
- ✅ Private keys never exposed to applications
- ✅ All operations logged for monitoring
- ✅ Simulation-only (no real-world services)
- ✅ Python-based, incremental development

