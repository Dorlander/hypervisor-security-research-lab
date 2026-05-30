# Privilege Layer Model for Virtualization Research

This note provides a simple model for documenting low-level components by privilege layer.

## Why Layering Matters

Virtualization-related packages often include more than one kind of component. A user-mode loader may coordinate a kernel driver, which may in turn enable a hypervisor-level component. Some packages may also involve firmware or boot-time code.

Documenting these layers separately helps avoid vague conclusions such as "this is just a driver" or "this is just a loader."

## Common Layers

| Layer | Informal Ring | Examples | Defensive Notes |
|------|----------------|----------|-----------------|
| Firmware / boot path | Ring -2 | UEFI applications, DXE drivers, boot loaders | Can affect boot trust assumptions before the OS fully starts |
| Hypervisor | Ring -1 | VT-x, EPT, SVM, NPT components | Can observe or intercept guest execution below the OS |
| Kernel mode | Ring 0 | Windows drivers, kernel services | Can access privileged OS state and requires careful trust review |
| User mode | Ring 3 | Launchers, helper DLLs, configuration files | Often coordinates setup, configuration, or application-facing behavior |

## Events Worth Documenting

For hypervisor-level research, the following event categories are useful to describe at a high level:

- VM exits
- CPUID behavior
- MSR reads and writes
- RDTSC / RDTSCP behavior
- EPT or NPT mapping behavior
- I/O port access
- Interrupt and exception handling
- Guest-to-host integration features
- Shared memory or device passthrough behavior

## Defensive Review Questions

- Which component has the highest privilege level?
- Which component starts first?
- Which component is trusted by the rest of the chain?
- Which component parses guest-controlled input?
- Which component changes OS security assumptions?
- Which claims are proven by evidence and which are hypotheses?

## Safe Documentation Style

Prefer high-level descriptions such as:

- "This component appears to operate at the hypervisor layer."
- "The package includes a kernel-mode driver based on PE subsystem metadata."
- "The trust boundary appears to be guest-to-host through an emulated device."

Avoid turning observations into operational instructions.
