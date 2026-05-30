# References

This file lists public resources useful for defensive virtualization security research.

## Educational Hypervisor Projects

- SimpleSvm by Satoshi Tanda
  - Minimal educational hypervisor for Windows on AMD processors
  - Useful for studying SVM, NPT, VMCB, VM exits, CPUID, and MSR concepts at a high level

- SimpleVisor by Alex Ionescu
  - Educational Intel VT-x hypervisor reference

- HyperDbg
  - Open-source hypervisor-assisted Windows debugger
  - Useful for studying hardware-assisted debugging concepts, EPT-based monitoring, VM exits, CPUID/MSR monitoring, and defensive reverse-engineering workflows

## Firmware and Boot Research References

- EfiGuard by Mattiwatti
  - Public UEFI boot research project
  - Useful as a reference for understanding boot-time trust assumptions and the defensive risk of firmware-level components

## Vendor Documentation

- AMD64 Architecture Programmer's Manual
- Intel 64 and IA-32 Architectures Software Developer's Manual
- Microsoft Windows driver and code integrity documentation

## Defensive Analysis Topics

- PE header analysis
- Import/export table review
- Authenticode signature status
- Driver INF manifest review
- Static string extraction
- Passive decompilation for defensive understanding
- Privilege-layer mapping across firmware, hypervisor, kernel, and user mode

## Research Note

References are used for terminology and conceptual understanding. This repository does not copy source code from those projects and does not provide operational bypass instructions.
