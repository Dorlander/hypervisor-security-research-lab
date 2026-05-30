# Hypervisor Attack Surface Map

This is a high-level defensive map of areas that can be reviewed in a controlled virtualization lab.

## Guest-to-Host Boundaries

Areas where guest-controlled input may influence host-side hypervisor behavior:

- Hypercalls
- VM exits
- Emulated devices
- Shared folders
- Clipboard integration
- Drag-and-drop integration
- Graphics acceleration
- USB passthrough
- Network adapters
- Snapshot and restore mechanisms

## CPU Virtualization Topics

Conceptual areas for defensive review:

- VM-exit handling
- Intercepts and control fields
- CPUID feature exposure
- MSR access policy
- Interrupt and exception handling
- Nested paging behavior such as NPT or EPT
- TLB and address translation assumptions

## Configuration-Based Risk Areas

Some issues are not code vulnerabilities but unsafe configurations:

- Bridged networking
- Shared clipboard
- Shared folders
- Host device passthrough
- Overly broad guest permissions
- Debug interfaces exposed to guests
- Unnecessary integration tools

## Defensive Questions

For each topic, ask:

- What input is guest-controlled?
- What component parses or handles that input?
- Does the host trust guest-provided state?
- What logs or traces show the boundary crossing?
- Can the behavior be reproduced safely?
- Is this a vulnerability, a misconfiguration, or expected behavior?
