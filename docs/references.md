# References

Public resources used for defensive virtualization and kernel security research.

---

## Educational Hypervisor Projects

**SimpleSvm** — Satoshi Tanda (MIT)  
Minimal AMD SVM hypervisor for Windows. Good for learning VMCB layout, VMEXIT handling, per-core virtualization, and CPUID/MSR intercept mechanics without drowning in production complexity. The MSRPM (8KB, two bits per MSR) and IOPM (12KB, one bit per I/O port) structures are well-illustrated here.  
https://github.com/tandasat/SimpleSvm

**SimpleVisor** — Alex Ionescu (Apache 2.0)  
Intel VT-x counterpart to SimpleSvm. Shows VMCS-based approach: VMXON/VMLAUNCH lifecycle, EPT setup, and VM-exit reason handling on Intel hardware.  
https://github.com/ionescu007/SimpleVisor

**HyperDbg** (open source, academic paper: arxiv.org/pdf/2207.05676)  
Hypervisor-level debugger built on Intel VT-x. Uses EPT to monitor memory accesses (read/write/execute) at the physical page level without modifying guest code. Runs entirely in VMX-root mode, invisible to the guest OS. Key capabilities: unlimited hardware breakpoints via EPT hooks (not limited to the four DR0-DR7 debug registers), physical-address read/write bypassing virtual memory protections, CPUID/MSR interception, and a built-in scripting engine for event-driven analysis.  
https://github.com/HyperDbg/HyperDbg

**NoirVisor** — Zero-Tang  
More complete hypervisor research project; useful for studying multi-vendor (AMD + Intel) support in a single codebase and more advanced VMCB/VMCS usage patterns.  
https://github.com/Zero-Tang/NoirVisor

---

## Firmware and Boot References

**EfiGuard** — Mattiwatti (GPL-3.0)  
UEFI DXE driver that patches the Windows boot chain at runtime — before the kernel loads. Supports all EFI-compatible Windows x64 versions from Vista SP1 through Windows 11. Uses the Zydis disassembler library internally for pattern-independent instruction scanning.

Key patch points:
- `bootmgfw.efi` — hooks `ImgArchStartBootApplication`, patches `ImgpValidateImageHash` and `ImgpFilterValidationFailure`
- `winload.efi` — patches `OslFwpKernelSetupPhase1`, can set `VbsPolicyDisabled` EFI variable
- `ntoskrnl.exe` — disables PatchGuard via `KeInitAmd64SpecificState`, `CcInitializeBcbProfiler`, `ExpLicenseWatchInitWorker`, `g_PgContext`, `KiSwInterrupt`, `KiVerifyScopesExecute`, `KiMcaDeferredRecoveryService`

Two DSE bypass modes: boot-time patch of `SepInitializeCodeIntegrity` (sets `g_CiEnabled` to 0 before Code Integrity initializes), or a `SetVariable()` EFI runtime hook that allows toggling `g_CiEnabled`/`g_CiOptions` from user mode post-boot.

Limitation: cannot touch HVCI — it runs at VTL1, a higher privilege level than the UEFI DXE phase.  
https://github.com/Mattiwatti/EfiGuard

---

## Windows Kernel Security Features

| Feature | What it protects | How it works | Bypassed by |
|---------|-----------------|-------------|-------------|
| PatchGuard (KPP) | Kernel code and critical structures | Periodic integrity checks from hidden timer context | UEFI-level patching before kernel init (EfiGuard), ring -1 split views |
| DSE | Unsigned kernel driver loading | `SepInitializeCodeIntegrity` → `g_CiEnabled`/`g_CiOptions` checked on driver load | Boot-time patch of `g_CiEnabled`, test signing mode, UEFI SetVariable hook |
| HVCI / Memory Integrity | Kernel code pages | Runs at VTL1 (Secure World), enforces that kernel pages are never writable + executable | Requires VTL1-level attack; not defeated by ring -1 hypervisors |
| Secure Boot | UEFI boot chain integrity | Firmware validates EFI application signatures against PK/KEK/db | Disabling in BIOS, or enrolling attacker-controlled cert |
| VBS | LSASS memory, HVCI, Credential Guard | Isolates critical security components in VTL1 via hypervisor | Requires disabling at UEFI level before Windows boot |

---

## Key Windows Structures for Virtualization Research

**KUSER_SHARED_DATA** (`0x7FFE0000` user-mode, `0xFFFFF78000000000` kernel-mode)  
Single 4KB page mapped read-only into every process and read-write from the kernel. Contains fields that the kernel updates instead of issuing syscalls for — timekeeping, OS version, processor features. Notable fields for anti-analysis research: `TickCountMultiplier` (offset 0x004), `InterruptTime` (0x008), `SystemTime` (0x014), `NtBuildNumber` (0x260), `KdDebuggerEnabled` (0x308). Microsoft proposed randomizing this structure's address in 2022 (MSRC blog) to complicate exploitation that relies on its fixed address.

**`nt!KdDebuggerNotPresent`**  
Kernel global set to 1 when no kernel debugger is attached. Accessible from user mode indirectly via `NtQuerySystemInformation` or directly via `KUSER_SHARED_DATA.KdDebuggerEnabled`. A common anti-debug check target.

**`nt!g_CiEnabled` / `nt!g_CiOptions`**  
Boolean/flags controlling Code Integrity enforcement state. On Vista/7 it was `g_CiEnabled` in ntoskrnl; from Windows 8 onward it moved to `CI.dll` as `g_CiOptions`. Protected by PatchGuard on Windows 8+, so runtime modification risks a BSOD unless PatchGuard is also disabled.

---

## Vendor Documentation

- AMD64 Architecture Programmer's Manual, Volume 2 — System Programming (Chapter 15: Secure Virtual Machine)
- Intel 64 and IA-32 Architectures SDM, Volume 3C — VMX chapter
- Microsoft WDK: driver signing, INF format, KMDF versioning
- Microsoft MSRC Blog — "Randomizing the KUSER_SHARED_DATA Structure on Windows" (2022)

---

## Passive Analysis Tools

| Tool | Use case |
|------|---------|
| Ghidra 12.x | Decompilation and disassembly; custom analysis scripts via Java API |
| PE-bear / CFF Explorer | PE header parsing, section layout, import/export tables |
| sigcheck (Sysinternals) | Authenticode signature status, catalog verification |
| WinObjEx64 | Kernel object browser — named objects, callbacks, loaded drivers |
| Process Monitor (Sysinternals) | File, registry, process activity tracing |
| strings / PowerShell regex | ASCII + UTF-16LE string extraction without execution |
| pefile (Python) | Programmatic PE analysis, export enumeration |
