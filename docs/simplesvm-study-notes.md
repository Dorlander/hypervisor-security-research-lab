# SimpleSvm Study Notes

These notes summarize safe, high-level ideas inspired by the public SimpleSvm educational hypervisor project.

## Why It Is Useful as a Reference

SimpleSvm is useful as an educational reference because it is intentionally minimal. A small project is easier to study than a production hypervisor, especially when the goal is to understand concepts and terminology.

## Ideas Adapted for This Repository

### 1. Clear Scope

SimpleSvm presents itself as a minimal educational hypervisor. This repository follows the same idea by making the scope narrow and explicit: defensive lab methodology for virtualization research.

### 2. Supported Platform Notes

Research notes should clearly state what environment they apply to, such as:

- Host OS
- Guest OS
- CPU vendor and virtualization feature support
- Hypervisor version
- Relevant features such as SVM, VT-x, NPT, or EPT

### 3. Glossary and Concept Mapping

Good research notes should define terms before using them. Useful concepts to document include:

- VM exit
- VMCB / VMCS
- Nested Page Tables / Extended Page Tables
- CPUID handling
- MSR access policy
- Guest physical vs host physical memory
- Intercepts

### 4. Responsible References

Instead of presenting unsupported claims, link to vendor manuals, educational projects, and official documentation.

### 5. No Weaponized Code

This repository should remain focused on methodology, notes, and defensive understanding. It should not copy hypervisor code or publish exploit chains.
