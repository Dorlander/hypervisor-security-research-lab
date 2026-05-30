# Defensive Research Note Template

## Title

Short description of the suspected issue or package being reviewed.

## Summary

Briefly explain the behavior and why it may matter defensively.

## Scope and Limitations

- Analysis type:
- Passive-only review:
- Unknown binaries executed:
- Authorized environment:
- Publication restrictions:

## Environment

- Hypervisor:
- Host OS:
- Guest OS:
- CPU:
- Virtualization features:
- Network mode:
- Shared clipboard:
- Shared folders:
- USB passthrough:
- Snapshot used:

## File Inventory

| File | Size | Type | Signed | Notes |
|------|------|------|--------|-------|
|      |      |      |        |       |

## Static Metadata

Record relevant metadata without executing unknown components:

- Hashes:
- PE subsystem:
- Imports:
- Exports:
- Strings:
- Config files:
- Driver manifests:

## Privilege Layer Mapping

| Layer | Component | Evidence | Defensive Concern |
|------|-----------|----------|-------------------|
| Firmware / boot path | | | |
| Hypervisor | | | |
| Kernel mode | | | |
| User mode | | | |

## Expected Behavior

Describe what should happen.

## Observed Behavior

Describe what actually happened.

## Evidence Confidence

| Claim | Evidence Type | Confidence |
|------|---------------|------------|
|      |               |            |

## Reproduction Conditions

High-level conditions required to observe the behavior. Avoid weaponized exploit instructions.

## Security Impact Hypothesis

Explain the potential risk if the behavior is confirmed.

## Mitigations or Defensive Notes

Document configuration hardening, monitoring, or isolation improvements.

## Disclosure Status

- Not security-relevant
- Needs more validation
- Reported privately
- Coordinated disclosure in progress
