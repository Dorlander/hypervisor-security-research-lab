# Hypervisor Lab Checklist

Pre-flight list before any controlled virtualization security test.

---

## Host Setup

- Machine is not used for production work
- OS updates applied; record exact build number (`winver`)
- CPU vendor confirmed (AMD or Intel), virtualization extension enabled in BIOS
  - AMD: SVM / AMD-V enabled in BIOS settings
  - Intel: VT-x / Intel Virtualization Technology enabled
- Record NPT (AMD) or EPT (Intel) support — check via `CPUID 0x8000000A` on AMD, `CPUID 0x1` ECX VMX features on Intel
- Check whether Hyper-V or HVCI is active — both occupy ring -1 and will block a research hypervisor from loading. Verify with `systeminfo | findstr Hyper-V` and check Device Security → Core isolation in Windows Security
- Workspace created for notes, logs, and binary artifacts

## VM Guest Setup

- Disposable VM — not a machine with data you care about
- Snapshot created before the test begins
- Shared clipboard: OFF
- Shared folders: OFF
- Drag-and-drop: OFF
- USB passthrough: OFF
- Networking: NAT or host-only unless the test specifically requires bridged

---

## Before Loading Unsigned Kernel Drivers

Loading a research hypervisor or any unsigned `.sys` file requires disabling DSE. Do this only on an isolated test machine.

**Option 1 — Test signing mode** (least invasive):
```
bcdedit /set testsigning on
bcdedit /set hypervisorlaunchtype off   ← only if loading your own ring -1 hypervisor
```
Disables DSE via test signing. PatchGuard still runs, but a ring -1 hypervisor can use split page table views so PatchGuard checks ring 0 and sees unmodified memory.

**Option 2 — EfiGuard** (also disables PatchGuard):
Boot from EfiGuard USB. It patches `bootmgfw.efi` → `winload.efi` → `ntoskrnl.exe` in sequence during DXE phase. PatchGuard and DSE are both gone for the session. Requires Secure Boot disabled in BIOS (or hash enrolled via HashTool).

Before either option:
- [ ] Snapshot the VM
- [ ] Document every BCD change with intent to revert
- [ ] Confirm Secure Boot status
- [ ] Confirm HVCI (Memory Integrity) is off — EfiGuard explicitly cannot bypass it; it runs at VTL1

---

## Hypervisor Component Checklist

When loading or studying a ring -1 driver:

- [ ] CPU vendor and SVM/VMX availability confirmed
- [ ] No conflicting hypervisor already running — can check via `NtQuerySystemInformation(0xC4)` or by checking if `hypervisorlaunchtype` is `off`
- [ ] Understand which intercepts are configured: CPUID? RDTSC? specific MSRs via MSRPM? I/O ports via IOPM?
- [ ] Power state transitions handled — devirtualize before sleep, revirtualize after wake; missing this causes BSOD on resume
- [ ] Devirtualization path confirmed for driver unload
- [ ] Per-core init — driver must run VMRUN / VMLAUNCH on every logical core, not just core 0
- [ ] VMCB/VMCS allocated as physically contiguous memory (`MmAllocateContiguousNodeMemory`) — hardware requires physical addresses, not virtual

---

## Passive Binary Analysis Checklist

Before executing any unknown low-level binary:

**File metadata:**
- [ ] File inventory — name, size, last modified timestamp
- [ ] SHA-256 hash of each file before any analysis

**PE header:**
- [ ] Machine type — `0x8664` (x64), `0x014C` (x86)
- [ ] Subsystem — `1` = Native/Kernel driver, `2` = Windows GUI, `3` = Console
- [ ] Characteristics — bit `0x2000` set means DLL; absent means standalone executable
- [ ] PE sections — `.text`, `.rdata`, `.data`, `.reloc` are normal; unusual section names or high entropy sections worth noting

**Signatures and trust:**
- [ ] Authenticode signature status — signed by whom? self-signed? unsigned?
- [ ] If signed: certificate chain, issuer, validity dates, revocation status

**Imports and exports:**
- [ ] Import table — which DLLs does it link to? (`ntoskrnl.exe`, `Wdf01000.sys`, `ndis.sys`, `user32.dll` etc.)
- [ ] Specific API calls of interest: network APIs, process enumeration, memory allocation, debug-related calls
- [ ] Export table — what functions does it expose, if any

**Strings:**
- [ ] ASCII string extraction (printable sequences ≥6 chars)
- [ ] Unicode / UTF-16LE string extraction
- [ ] Look for: file paths, registry keys, error messages, version strings, API names, certificate subjects

**Driver manifest (INF), if present:**
- [ ] Service name, display name
- [ ] `StartType` — 0=boot, 1=system, 2=auto, 3=demand, 4=disabled
- [ ] `ServiceBinary` path — does it match the actual filename?
- [ ] KMDF version (`KmdfLibraryVersion`) — implies minimum Windows version
- [ ] Unfinished placeholder strings (e.g., `<Your manufacturer name>`, `TODO:`) indicate template-generated files

**Privilege layer mapping:**
- [ ] Categorize each component before drawing conclusions: firmware, hypervisor, kernel, or user mode
- [ ] Check for known open-source project strings — modified builds of SimpleSvm, HyperDbg, EfiGuard, Goldberg emulator etc. are common

---

## Test Documentation

Record for every test:

- Date and time
- Host OS name and build (`winver`)
- Guest OS name and build
- Hypervisor product and version
- CPU vendor, model, virtualization features present
- VM configuration — networking mode, shared device state
- BCD changes made and whether they were reverted afterward
- Expected behavior
- Observed behavior
- Logs collected (event log, hypervisor log, procmon trace)
- Reproduction reliability

---

## After Testing

- Revert BCD changes: `bcdedit /deletevalue testsigning`, `bcdedit /set hypervisorlaunchtype auto`
- Revert VM to pre-test snapshot if needed
- Archive notes and artifacts
- Clean up temporary files
- Classify the result: expected behavior / configuration hardening note / potential vulnerability
