# Hypervisor Security Research Lab Notes

This repository documents my independent defensive security research in isolated lab environments, with a focus on hypervisor-based testing, virtualization attack surfaces, safe vulnerability research methodology, and passive analysis of low-level binary packages.

The purpose of this repository is to show a structured, responsible approach to virtualization security research rather than to publish exploit code or operational bypass instructions.

## Scope

All research described here is limited to controlled systems that I own or am explicitly authorized to test.

## Focus Areas

- Hypervisor-based lab design and isolation
- Virtualization attack surface mapping
- Guest-to-host and host-to-guest trust boundaries
- VM-exit and intercept behavior at a high level
- Nested paging concepts such as NPT/EPT from a defensive perspective
- MSR and CPUID handling as research topics
- Passive static analysis of low-level components
- Privilege-layer mapping across firmware, hypervisor, kernel, and user mode
- Safe reproduction planning for suspected vulnerabilities
- Responsible disclosure preparation when a validated issue is identified

## Lab Environment

Typical research is performed inside isolated virtual machines and disposable snapshots.

Default safety posture:

- No production systems
- No unauthorized targets
- No third-party infrastructure
- No bridged networking unless explicitly required
- Shared folders disabled by default
- Shared clipboard disabled by default
- USB passthrough disabled by default
- Snapshots created before each test

## Repository Structure

```text
docs/
  lab-scope.md                      — research scope and boundaries
  research-methodology.md           — general research workflow
  passive-binary-audit-methodology.md
  privilege-layer-model.md          — ring -2 / -1 / 0 / 3 breakdown
  attack-surface-map.md
  hypervisor-lab-checklist.md       — pre-flight checklist for lab tests
  simplesvm-study-notes.md          — AMD SVM / VMCB study notes
  report-template.md                — passive audit report template
  references.md                     — tools, projects, vendor docs

examples/
  cpuid-reader/
    cpuid_check.c                   — reads CPUID leaves relevant to virtualization
  kuser-reader/
    kuser_read.c                    — reads KUSER_SHARED_DATA fields from user mode
  vmcb-layout/
    vmcb_structs.h                  — annotated VMCB structure from AMD APM
    vmexit_handler_skeleton.c       — annotated VMEXIT dispatch skeleton
  passive-analysis/
    analyze_pe.ps1                  — PE header parser + string extractor (PowerShell)

SECURITY.md
DISCLAIMER.md
```

## Methodology

The research process generally follows this structure:

1. Define the component or trust boundary being reviewed.
2. Identify expected behavior and assumptions.
3. Build an isolated and reproducible lab case.
4. Prefer passive static analysis before executing unknown components.
5. Observe behavior using logs, traces, metadata, and configuration review.
6. Map findings by privilege layer and evidence confidence.
7. Document whether the behavior suggests a defensive concern.
8. Avoid publishing exploit details unless disclosure is coordinated and authorized.

## Passive Audit Notes

For unknown low-level packages, the preferred workflow is passive analysis first: file inventory, hashes, PE headers, import/export tables, driver manifests, configuration review, string extraction, and open-source reference comparison.

When documenting a package, components should be mapped by privilege layer: firmware or boot path, hypervisor level, kernel mode, and user mode. This keeps the analysis focused on defensive trust boundaries and risk assessment rather than operational misuse.

## Ethical Boundaries

This repository does not contain weaponized exploit code, instructions for unauthorized access, or steps for attacking real-world systems.

Any findings that appear security-relevant should be handled through responsible disclosure.

## Contact

For eligibility verification or research context, please contact me through the profile linked with this repository.
