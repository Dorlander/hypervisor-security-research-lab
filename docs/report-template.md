# Research Note Template

For passive binary audits, hypervisor component studies, or any structured analysis note.

---

**Title:**  
**Date:**  
**Method:** passive static analysis — string extraction, PE header analysis, INF parsing, config review, open-source reference comparison, Ghidra decompilation  
**Binaries executed:** No

---

## 1. Summary

What does this package appear to do, which privilege layers does it span, and what is the core defensive concern?

| Layer | Ring | Component | Role |
|-------|------|-----------|------|
| UEFI / Firmware | -2 | | |
| Hypervisor | -1 | | |
| Kernel | 0 | | |
| User mode | 3 | | |

---

## 2. Scope and Limitations

- Analysis type:
- Passive only (no execution):
- Test environment:
- What static analysis can miss: obfuscated payloads, encrypted sections, time-delayed or network-triggered behavior

---

## 3. Environment

- Host OS:
- Guest OS:
- Hypervisor product and version:
- CPU vendor + virtualization features:
- Network mode:
- Shared clipboard / folders / USB: OFF / OFF / OFF
- Snapshot taken: Yes / No

---

## 4. File Inventory

| File | Size (bytes) | Last Modified | Type | Signed | Notes |
|------|-------------|---------------|------|--------|-------|
| | | | | | |

**PE Header Summary:**

| File | Machine | Subsystem | Characteristics |
|------|---------|-----------|----------------|
| | 0x8664 (x64) | 1 = kernel driver | |

Subsystem reference: `1` = Native/Kernel, `2` = Windows GUI, `3` = Console

---

## 5. How It Works (High Level)

Describe trust boundaries crossed and the sequence of events. No operational step-by-step — focus on what components interact with what privilege levels and in what order.

---

## 6. Component Notes

Repeat this block for each significant binary:

### [filename] — [layer]

- **Based on:** (known open-source project, or closed source)
- **License:**
- **Size / Subsystem:**
- **Key imports:** (APIs that indicate what the component does)
- **Key strings:**
- **Modifications from original:** (if it's a known project — what was added?)
- **Defensive concern:**

**Kernel API patterns worth noting:**

| API | What it suggests |
|-----|----------------|
| `MmAllocateContiguousNodeMemory` | VMCB/VMCS allocation — physically contiguous memory for hardware virtualization structures |
| `KeSetSystemGroupAffinityThread` | Per-core execution — hypervisor init must run on each logical processor |
| `PsSetCreateProcessNotifyRoutine` | Process creation callback — driver watches for a specific process |
| `PsLookupProcessByProcessId` | Targeted process lookup — not system-wide, specific PID |
| `NtQuerySystemInformation(0xC4)` | Check for existing hypervisor before loading another |
| `ExCreateCallback` + `ExRegisterCallback` | Power state callbacks — needed for sleep/hibernate devirtualization |
| `KdDebuggerNotPresent` | Direct access to kernel debugger detection variable |
| `MmMapLockedPagesSpecifyCache` + `MmProbeAndLockPages` | Mapping physical pages into virtual space — shared memory or DMA-style access |

---

## 7. Privilege Layer Map

| Layer | Component | Evidence | Defensive question |
|------|-----------|----------|--------------------|
| Firmware / boot | | | Does it run before OS security features initialize? |
| Hypervisor | | | Does it intercept CPUID, MSR, or RDTSC from below the OS? |
| Kernel | | | Does it modify kernel structures or bypass driver signing? |
| User mode | | | Does it launch, configure, or coordinate lower-layer components? |

---

## 8. Static Metadata

- SHA-256 hashes:
- PE subsystem values:
- Notable imports:
- Notable exports:
- Config files:
- INF manifests:
- Interesting strings:

---

## 9. Open-Source Comparison

| Component | Likely base project | License | Modified? | What was added |
|-----------|-------------------|---------|-----------|---------------|
| | | | | |

---

## 10. Risk Notes

| Risk | Severity | Details |
|------|----------|---------|
| | CRITICAL / HIGH / MEDIUM / LOW | |

Questions to answer:

- Does it require disabling DSE, PatchGuard, Secure Boot, or HVCI?
- Does it load unsigned kernel drivers?
- Does it interact with the UEFI boot chain?
- Does it intercept CPUID, MSR, or RDTSC from ring -1?
- Does it read/write physical memory to modify protected kernel structures (e.g., `KUSER_SHARED_DATA`, `KdDebuggerNotPresent`, `g_CiEnabled`)?
- Does it register persistent kernel callbacks (`PsSetCreateProcessNotifyRoutine`, `CmRegisterCallback`, etc.)?
- Are outbound network connections present in any config or string?
- Does it leave persistent system changes after the session ends?

---

## 11. Evidence Confidence

| Claim | Evidence | Confidence |
|------|----------|-----------|
| | Confirmed by PE header | High |
| | Confirmed by import table | High |
| | Confirmed by strings | Medium |
| | Matched to open-source project | High |
| | Inferred from component role | Low |
| | Unresolved | — |

---

## 12. Recommendations

Hardening suggestions, monitoring points, or isolation changes based on findings.

---

## 13. Disclosure

- [ ] Not security-relevant
- [ ] Needs more evidence
- [ ] Reported privately to vendor
- [ ] Coordinated disclosure in progress
- [ ] Public — after vendor coordination or confirmed no impact
