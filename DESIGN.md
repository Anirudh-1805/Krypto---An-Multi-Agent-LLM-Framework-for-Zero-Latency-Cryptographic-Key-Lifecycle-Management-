# Design Document: Increment 1 - Simulated Application Ecosystem

## Overview

Increment 1 establishes the foundation of the system by implementing:
1. A central Cryptographic Core with Key Management API
2. Three simulated applications that consume cryptographic keys
3. Realistic misuse patterns that future agents will detect and correct

## Design Choices

### 1. Central Key Management API

**Decision**: All applications must use `KeyManager` - they cannot manage keys directly.

**Rationale**:
- Enforces the constraint that private key material never leaves the cryptographic core
- Applications receive only operation results (ciphertext, signatures), never keys
- Centralized logging enables future monitoring agents to observe all operations
- Single point of control for key lifecycle management (to be added in future increments)

**Implementation**:
- `KeyManager` class provides methods: `encrypt()`, `decrypt()`, `sign()`, `verify()`, `generate_key()`
- Applications receive a `KeyManager` instance and use it for all cryptographic operations
- Private keys are stored in `_keys` dictionary (in-memory for simulation)

### 2. Static Key IDs

**Decision**: Applications use hardcoded key IDs (e.g., `"web-service-signing-key-v1"`).

**Rationale**:
- Demonstrates the misuse pattern of static configurations
- Real-world applications often hardcode key identifiers
- Makes it easy to identify which application owns which key
- Future agents will need to handle key rotation while maintaining application compatibility

**Implementation**:
- Each application defines a `_static_key_id` attribute
- Key IDs follow pattern: `{service_name}-{purpose}-key-v1`
- Applications check if key exists, reuse if available, create if not

### 3. Operation Logging

**Decision**: Every cryptographic operation is logged with metadata.

**Rationale**:
- Monitoring Agent (future increment) needs historical data
- Enables detection of usage patterns (excessive usage, long-lived keys)
- Supports auditability requirements
- Logs include: timestamp, operation type, key ID, success/failure, operation metadata

**Implementation**:
- `KeyManager._log_operation()` method logs all operations
- Log entries are stored in `_operation_log` list
- Logs are accessible via `get_operation_log()` for monitoring agents

### 4. Key Metadata Without Private Material

**Decision**: Applications can query key metadata (ID, algorithm, creation date, usage count) but never private keys.

**Rationale**:
- Monitoring agents need key statistics without accessing private material
- Applications can check key status (revoked, rotated) without security risk
- Supports policy evaluation (e.g., "rotate keys older than 90 days")

**Implementation**:
- `KeyMetadata` class stores only non-sensitive information
- `get_key_metadata()` and `get_all_key_metadata()` return metadata dictionaries
- Private keys remain in `_keys` dictionary, never exposed

### 5. Misuse Patterns

**Decision**: Applications demonstrate realistic misuse patterns.

**Rationale**:
- Provides test cases for future autonomous agents
- Shows what problems the system needs to solve
- Demonstrates that applications are "naive" - they don't manage key lifecycle

**Implementation**:

**Web Service**:
- Creates one signing key at startup, uses it forever
- Signs every request AND every response (excessive usage)
- Never checks key age or usage patterns

**Data Storage Service**:
- Uses one encryption key for ALL records
- Never rotates keys, even after many operations
- Doesn't consider key age when storing sensitive data

**File Encryption Service**:
- Uses one key for all files
- Performs batch operations causing usage spikes
- No rate limiting or key rotation checks

### 6. Algorithm Support

**Decision**: Support AES-GCM, RSA, ECDSA, and SHA-256 only.

**Rationale**:
- Matches project requirements
- Uses standard, well-vetted algorithms
- AES-GCM for symmetric encryption (authenticated encryption)
- RSA/ECDSA for asymmetric signing (RSA for compatibility, ECDSA for efficiency)
- SHA-256 for hashing (used internally by signing algorithms)

**Implementation**:
- `CryptoOperations` class provides static methods for each algorithm
- Uses `cryptography` library (standard Python crypto)
- Key generation, encryption, decryption, signing, verification all implemented

### 7. In-Memory Key Storage

**Decision**: Keys are stored in memory (Python dictionary) for simulation.

**Rationale**:
- This is a simulation, not a production system
- Simplifies implementation for academic project
- In production, this would be a secure key store (HSM, cloud KMS, etc.)
- Access control is enforced by code structure (private `_keys` attribute)

**Implementation**:
- `KeyManager._keys` dictionary: `key_id -> (key_material, metadata)`
- Keys persist for the duration of the simulation
- No persistence to disk (simulation-only)

### 8. Application Structure

**Decision**: Each application is a Python class with clear responsibilities.

**Rationale**:
- Modular design allows easy addition of new applications
- Each application is independently testable
- Clear separation between application logic and cryptographic operations
- Applications are "dumb" - they just use keys, don't manage them

**Implementation**:
- `WebService`: Handles HTTP-like requests, signs everything
- `DataStorageService`: Stores encrypted records, retrieves them
- `FileEncryptionService`: Encrypts files, supports batch operations
- All applications follow same pattern: initialize key, perform operations, provide stats

## Data Flow

```
Application
    ↓ (requests operation)
KeyManager
    ↓ (uses key material)
CryptoOperations
    ↓ (returns result)
KeyManager
    ↓ (logs operation)
Operation Log
    ↓ (returns result)
Application
```

**Key Points**:
- Applications never see private keys
- All operations go through KeyManager
- All operations are logged
- Cryptographic operations use standard libraries

## Future Increments

This increment provides:
- ✅ Applications that consume keys
- ✅ Central Key Management API
- ✅ Operation logging
- ✅ Key metadata access

Next increments will add:
- Monitoring Agent: Observes operation logs and key metadata
- Policy Agent: Evaluates policies and makes decisions
- Key Action Agent: Executes lifecycle operations
- Audit Agent: Maintains immutable audit trail

## Testing

The simulation can be run with:
```bash
python main.py
```

This demonstrates:
- All three applications creating and using keys
- Excessive usage patterns (40 signing operations, 20 encryption operations, etc.)
- All operations being logged
- No key rotation or lifecycle management

The output shows key usage statistics that future monitoring agents will analyze.

