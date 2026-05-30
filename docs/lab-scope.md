# Lab Scope

This lab covers defensive security research on hypervisors and virtualization environments. All work is done in isolated VMs on hardware I own. The focus is understanding how trust boundaries work at each privilege level — not building attack tools.

---

## Research Topics

### Hypervisor Architecture

**AMD SVM:** VMCB structure (control area + guest save area), MSRPM and IOPM bitmaps, VMRUN/VMEXIT lifecycle, ASID management, Nested Page Tables (NPT), per-core initialization via thread affinity.

**Intel VT-x:** VMCS layout, VMXON/VMLAUNCH/VMRESUME flow, Extended Page Tables (EPT), VM-exit reason codes and handler patterns.

**Both:** CPUID intercept mechanics, MSR intercept bitmaps, RDTSC/RDTSCP interception, power state (sleep/hibernate) handling, devirtualization on driver unload.

### Privilege Layer Breakdown

| Layer | Ring | Focus |
|-------|------|-------|
| UEFI / Firmware | -2 | DXE driver execution, boot chain trust, Secure Boot validation, patch points before OS kernel loads |
| Hypervisor | -1 | SVM/VMX init, guest-host isolation, CPUID/MSR/RDTSC intercepts, nested paging |
| Kernel | 0 | PatchGuard internals, DSE enforcement, `KUSER_SHARED_DATA`, `KdDebuggerNotPresent`, driver loading pipeline |
| User mode | 3 | Process launch surface, DLL loading order, API hook surface, inter-process trust |

### Specific Topics

**PatchGuard (KPP):** first introduced with Windows XP x64 / Vista x64. Runs integrity checks from a hidden timer context. Initialization call stack goes through `KeInitAmd64SpecificState` → `KiFilterFiberContext`. Multiple initialization paths exist — `ExpLicenseWatchInitWorker` is one of them at roughly 4% probability. Protected structures include kernel code pages, SSDT, IDT, GDT, and critical global variables including `g_CiOptions`.

**Driver Signature Enforcement:** enforced via `SepInitializeCodeIntegrity` at boot — sets `g_CiEnabled` (Vista/7) or `g_CiOptions` (Windows 8+). On Windows 8+ the options variable lives in `CI.dll` and is protected by PatchGuard, meaning runtime modification without also disabling PatchGuard risks a BSOD.

**KUSER_SHARED_DATA** (`0x7FFE0000`): a single 4KB page mapped read-only in every process and read-write from the kernel. Fixed address used since early Windows NT versions. Key fields: `TickCountMultiplier` (0x004), `InterruptTime` (0x008), `SystemTime` (0x014), `NtBuildNumber` (0x260), `KdDebuggerEnabled` (0x308). Microsoft proposed randomizing this address (MSRC, 2022) to reduce exploitation reliability that depends on its fixed location.

**Hypervisor-present bit:** CPUID leaf `0x1`, ECX bit 31. Set to 1 when a hypervisor is active. Leaf `0x40000000` returns the hypervisor vendor string — SimpleSvm returns `"SimpleSvm "`, Hyper-V returns `"Microsoft Hv"`, KVM returns `"KVMKVMKVM\0\0\0"`.

**UEFI boot chain trust:** `bootmgfw.efi` → `winload.efi` → `ntoskrnl.exe`. Each stage validates the next via Authenticode and SecureBoot policy. EfiGuard operates in the DXE phase and patches validation functions (`ImgpValidateImageHash`, `ImgpFilterValidationFailure`) before they can reject modified binaries.

### Open-Source Reference Projects

These projects are used as study references, not copied into this repo:

- **SimpleSvm** (MIT, Satoshi Tanda) — minimal AMD SVM hypervisor
- **SimpleVisor** (Apache 2.0, Alex Ionescu) — minimal Intel VT-x hypervisor
- **HyperDbg** (open source) — hypervisor-level debugger using EPT for invisible memory monitoring
- **EfiGuard** (GPL-3.0, Mattiwatti) — UEFI DXE bootkit for PatchGuard/DSE research

---

## Out of Scope

- Systems I don't own or lack explicit authorization to test
- DRM bypass on software I don't own
- Distributing pirated binaries or proprietary game files
- Publishing operational exploit chains or step-by-step bypass instructions

---

## Environment Rules

- All tests in isolated VMs with snapshots taken before each session
- Shared clipboard, shared folders, USB passthrough: off by default
- Bridged networking: only when needed and with no sensitive data at risk
- Unknown binaries: analyzed only in disposable VMs, never on a daily-use machine
- DSE/PatchGuard disable: only on test machines, documented, reverted after

---

## Disclosure

Any finding that looks like a real vulnerability in a shipping product gets handled through responsible disclosure before anything is made public.
