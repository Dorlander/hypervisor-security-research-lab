# Passive Binary Audit Methodology

This document describes a safe, passive workflow for reviewing low-level binary packages in a controlled research context.

The goal is to document what a package appears to contain, how its components relate to system privilege boundaries, and what defensive risks may exist. The workflow avoids executing unknown binaries and avoids publishing operational bypass instructions.

## Safety Position

Unknown low-level binaries should be treated as high risk until proven otherwise.

Default rules:

- Do not execute unknown binaries on a daily-use system
- Do not download suspicious samples from file-hosting mirrors unless there is a clear and authorized research reason
- Prefer static analysis, metadata review, and open-source reference comparison first
- Keep analysis inside an isolated VM or disposable machine
- Preserve hashes, filenames, timestamps, and source context
- Avoid redistributing proprietary, pirated, or suspicious binary packages

## Passive Analysis Inputs

Useful non-executing inputs include:

- File inventory
- Cryptographic hashes
- File sizes and timestamps
- PE headers and subsystem values
- Import and export tables
- Authenticode signature status
- INF driver installation manifests
- Plaintext configuration files
- String extraction results
- Open-source project references
- Decompiler output used only for defensive understanding

## Layered Component Mapping

Low-level packages can be documented by privilege layer instead of by filename alone.

Example layers:

| Layer | Typical Component Type | Defensive Question |
|------|-------------------------|-------------------|
| Firmware / boot path | UEFI application or DXE driver | Does it alter boot-time trust assumptions? |
| Hypervisor level | VT-x, EPT, SVM, or NPT component | Does it intercept CPU or memory events? |
| Kernel mode | Windows driver or service | Does it require signing, elevated privileges, or sensitive kernel access? |
| User mode | Loader, emulator, helper DLL, config | Does it launch, configure, or coordinate lower-level components? |

This mapping is useful because the same package may combine firmware, hypervisor, kernel, and user-mode components.

## Evidence Confidence

Every claim should be tied to the type of evidence that supports it.

Suggested confidence labels:

- Confirmed by metadata
- Confirmed by strings
- Confirmed by import/export table
- Confirmed by open-source project comparison
- Hypothesis based on component role
- Unknown / needs validation

## Risk Assessment Notes

A package does not need to show obvious commodity-malware behavior to be risky. Low-level components may still reduce system safety if they alter boot trust, driver signing assumptions, kernel integrity, hypervisor state, or debugging visibility.

Useful defensive questions:

- Does the package require disabling or weakening OS security features?
- Does it load unsigned or self-signed kernel drivers?
- Does it interact with firmware or boot-time code?
- Does it depend on hypervisor-level interception?
- Does it replace or emulate a trusted client component?
- Does it leave persistent changes after use?
- Are the components open source, modified open source, or closed source?
- Are the build provenance and hashes documented?

## Report Structure

A clear passive audit report should include:

1. Executive summary
2. Scope and limitations
3. File inventory
4. Static metadata summary
5. Layered component map
6. Open-source reference comparison
7. Risk assessment
8. Evidence confidence table
9. Defensive recommendations
10. Disclosure or publication notes

## Publication Boundaries

When writing public notes, avoid including:

- Download mirrors for suspicious packages
- Step-by-step bypass instructions
- Operational chains that enable misuse
- Proprietary binaries or copyrighted game files
- Claims that exceed the available evidence

The preferred public output is a defensive methodology note, not an instruction manual.
