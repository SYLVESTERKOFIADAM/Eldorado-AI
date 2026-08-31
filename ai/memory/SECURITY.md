# Eldorado-AI Memory Security

## Threats

### Memory Poisoning

An attacker attempts to cause malicious or incorrect information to be stored as user memory.

### Memory Injection

Malicious stored content attempts to influence future model behavior as if it were a trusted instruction.

### Cross-User Memory Leakage

Memory belonging to one user becomes available to another user.

### Sensitive Memory Exposure

Private information is unnecessarily exposed through model context or logs.

### Stale Memory

Old information causes Eldorado to make incorrect assumptions.

### Memory-Based Privilege Escalation

A memory entry attempts to cause Eldorado to bypass authorization.

## Required Controls

- strict user/tenant isolation
- memory provenance
- memory classification
- confidence scoring
- expiration and invalidation
- access control
- audit logging
- retrieval scoping
- sensitive-data controls
- prompt-injection resistance
- explicit authorization checks

## Non-Negotiable Rule

Memory can influence personalization.

Memory cannot authorize an operation.
