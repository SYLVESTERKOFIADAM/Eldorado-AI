# Eldorado-AI Memory Architecture

## Purpose

The Eldorado-AI memory subsystem provides controlled personalization and adaptation across conversations.

Memory is not model training. It is an application-level persistence layer that allows the system to retain approved information and use it as context when appropriate.

## Memory Classes

### 1. Profile Memory

Long-lived information explicitly approved for retention.

Examples:
- preferred name
- preferred programming languages
- preferred response format
- stable project preferences

### 2. Preference Memory

Behavioral preferences that influence how Eldorado interacts with the user.

Examples:
- concise vs detailed explanations
- preferred coding conventions
- preferred workflow
- preferred tools

### 3. Episodic Memory

Useful information derived from previous interactions.

Examples:
- previous implementation decisions
- unresolved tasks
- project-specific decisions
- lessons from previous failures

### 4. Feedback Memory

Explicit corrections from the user.

Examples:
- "Don't use that approach again."
- "Always explain security implications."
- "Use PowerShell for Windows commands."

## Security Rules

1. Memory is data, not authority.
2. Stored memory must never override system security policy.
3. Memory must never grant permissions.
4. Memory must never create new tool privileges.
5. Untrusted external content must not automatically become trusted memory.
6. Sensitive information requires explicit handling rules.
7. Memory retrieval must be scoped to the current task.
8. The user must be able to inspect and delete stored memory.
9. Every memory write should be auditable.
10. Memory poisoning must be treated as a security threat.

## Adaptation Pipeline

User interaction
    |
    v
Candidate Memory Extraction
    |
    v
Validation / Classification
    |
    v
Security Policy Check
    |
    v
Confidence Assessment
    |
    v
User Approval (when required)
    |
    v
Encrypted Memory Store
    |
    v
Scoped Memory Retrieval
    |
    v
Context Construction
    |
    v
AI Response

## Important Principle

Eldorado should learn how to better assist the user without silently changing its security boundaries.

Personalization changes behavior.

Authorization controls what the system is allowed to do.

These are separate systems.
