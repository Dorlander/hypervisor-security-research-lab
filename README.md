# Hypervisor Security Research Lab Notes

This repository documents independent defensive security research in isolated lab environments, with a focus on hypervisor-based testing, virtualization attack surfaces, safe vulnerability research methodology, and passive analysis of low-level binary packages.

The purpose of this repository is to show a structured, responsible approach to virtualization security research rather than to publish exploit code, weaponized bypasses, or operational instructions for unauthorized activity.

## Scope

All research described here is limited to controlled systems that I own or am explicitly authorized to test.

This repository is intended for:

- defensive virtualization research
- low-level Windows and firmware-adjacent study
- passive binary/package analysis
- lab evidence collection
- documentation of trust boundaries and privilege layers

It is not intended for attacking production systems, evading security products, cheating systems, malware development, or unauthorized access.

## Focus Areas

- Hypervisor-based lab design and isolation
- Virtualization attack surface mapping
- Guest-to-host and host-to-guest trust boundaries
- VM-exit and intercept behavior at a high level
- Nested paging concepts such as NPT/EPT from a defensive perspective
- MSR, CPUID, XCR0, and timing telemetry as research topics
- Windows user-mode telemetry exposed through `KUSER_SHARED_DATA`
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
- Unknown binaries are inspected passively before execution

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
    cpuid_check.c                   — user-mode CPUID/XCR0 virtualization telemetry
  kuser-reader/
    kuser_read.c                    — user-mode KUSER_SHARED_DATA passive reader
  vmcb-layout/
    vmcb_structs.h                  — annotated VMCB structure from AMD APM
    vmexit_handler_skeleton.c       — annotated VMEXIT dispatch skeleton
  passive-analysis/
    analyze_pe.ps1                  — PE header parser + string extractor (PowerShell)

SECURITY.md
DISCLAIMER.md
```

## Examples

### `examples/cpuid-reader/cpuid_check.c`

A user-mode CPUID and XCR0 diagnostics sample. It requires no administrator privileges and performs no kernel interaction.

It currently reports:

- CPU vendor string from CPUID leaf `0x0`
- CPU brand string from extended leaves `0x80000002–0x80000004`
- basic feature flags from leaf `0x1`
- the hypervisor-present bit from `CPUID.1:ECX[31]`
- VMX, AVX, OSXSAVE, and SSE2 visibility
- XCR0 state to distinguish “CPU supports AVX” from “OS actually enables AVX state”
- structured extended features from leaf `0x7`, including AVX2, SMEP, SMAP, UMIP, RDSEED, SHA, and AVX-512F
- hypervisor vendor leaf `0x40000000`
- a bounded raw dump of exposed hypervisor leaves
- AMD extended feature flags from `0x80000001`
- AMD SVM details from `0x8000000A`, including SVM revision, ASIDs, NPT, clean bits, and flush-by-ASID
- a noisy CPUID timing sanity check, documented as a weak diagnostic signal only

Build examples:

```text
cl /W4 cpuid_check.c
gcc -Wall -Wextra cpuid_check.c -o cpuid_check
```

### `examples/kuser-reader/kuser_read.c`

A passive Windows user-mode reader for selected `KUSER_SHARED_DATA` fields at `0x7FFE0000`. It does not write memory, call undocumented syscalls, or require elevated privileges.

It currently reports:

- Windows build and version fields
- product type and native processor architecture
- image number range
- `NtSystemRoot`
- interrupt time, system time, timezone bias, and approximate uptime
- `GetTickCount64()` comparison output
- selected miscellaneous telemetry such as `LargePageMinimum`, timezone ID, RNG seed version, and validation runlevel
- the kernel-debugger byte at offset `0x308`, including `KdDebuggerEnabled` and `KdDebuggerNotPresent`

Build example:

```text
cl /W4 kuser_read.c
```

### `examples/vmcb-layout/`

Annotated AMD SVM / VMCB study notes based on public AMD documentation.

This directory is educational and structural. It is not a working hypervisor implementation. The files explain:

- the VMCB split between control area and guest-save area
- selected intercept-control fields
- MSRPM and IOPM concepts
- ASID, TLB control, nested paging, and clean bits
- conceptual VMEXIT dispatch flow
- how CPUID, MSR, VMMCALL, VMRUN, and NPF exits are represented in an AMD SVM model

### `examples/passive-analysis/analyze_pe.ps1`

A PowerShell script for passive static analysis of Windows PE binaries. It reads files without executing them.

It currently covers:

- file size, timestamp, and SHA-256 hash
- Authenticode signature status
- PE header parsing
- machine type, subsystem, section count, compile timestamp, and characteristics
- DLL characteristics such as ASLR, DEP, CFG, WDM driver flag, and related metadata
- a privilege-layer guess based on subsystem and metadata
- import-table guidance
- optional ASCII and UTF-16LE string extraction

Run examples:

```powershell
.\analyze_pe.ps1 -Path C:\path\to\file.sys
.\analyze_pe.ps1 -Path C:\path\to\file.sys -ExtractStrings
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

When documenting a package, components should be mapped by privilege layer:

- firmware or boot path: ring -2
- hypervisor level: ring -1
- kernel mode: ring 0
- user mode: ring 3

This keeps the analysis focused on defensive trust boundaries and risk assessment rather than operational misuse.

## Safety Notes

The examples are intentionally passive or educational:

- `cpuid_check.c` reads CPU-reported state only.
- `kuser_read.c` reads Windows shared user data only.
- `vmcb-layout` documents structures and control flow at a conceptual level.
- `analyze_pe.ps1` inspects files without executing them.

If a finding appears security-relevant, the expected next step is controlled validation and responsible disclosure, not public release of operational exploit steps.

## Ethical Boundaries

This repository does not contain weaponized exploit code, instructions for unauthorized access, or steps for attacking real-world systems.

Any findings that appear security-relevant should be handled through responsible disclosure.

## Contact

For eligibility verification or research context, please contact me through the profile linked with this repository.
