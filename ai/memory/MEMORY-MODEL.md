# Eldorado-AI Memory Model

## Memory Record

Each memory record should eventually contain:

- id
- user_id
- type
- content
- source
- confidence
- sensitivity
- created_at
- updated_at
- last_used_at
- expires_at
- user_approved
- provenance
- status

## Memory Types

- profile
- preference
- episodic
- feedback
- project
- temporary

## Memory Status

- candidate
- active
- superseded
- deleted
- expired
- quarantined

## Provenance

Every memory should identify where it came from.

Possible sources:

- explicit_user_statement
- user_feedback
- conversation_inference
- imported_data
- external_content

External content must never automatically receive the same trust level as an explicit user statement.

## Confidence

Confidence represents how strongly Eldorado believes that the memory is valid.

Suggested range:

0.0 - 1.0

Confidence must not be interpreted as authorization.

A memory with confidence 1.0 still cannot grant permission to perform an action.
