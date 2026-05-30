# SimpleSvm Study Notes

**Project:** github.com/tandasat/SimpleSvm (MIT, Satoshi Tanda)  
**Platform:** Windows x64, AMD processors with SVM support

SimpleSvm is a minimal educational hypervisor — roughly 17KB compiled. That size is the point: the full control flow fits in your head, unlike production hypervisors where a single subsystem can span tens of thousands of lines. Good starting point before touching anything more complex.

---

## AMD SVM Basics

SVM (Secure Virtual Machine) is AMD's hardware virtualization extension, enabled by setting the `SVME` bit in the `EFER` MSR. Once active, the CPU gains two execution modes: VMX-root equivalent is called "host mode" and the guest runs in "guest mode." Transitions from guest to host are called `#VMEXIT` events.

### VMCB — Virtual Machine Control Block

Each logical CPU core needs its own VMCB — a hardware-defined structure split into two regions:

**Control area** — tells the CPU what to intercept:
- Intercept bitmaps for instructions (CPUID, VMRUN, RDTSC, I/O ports)
- MSRPM physical address — 8KB bitmap, two bits per MSR (read intercept, write intercept)
- IOPM physical address — 12KB bitmap covering all 64K I/O ports
- nCR3 — physical address of the Nested Page Table root
- ASID — Address Space Identifier, avoids full TLB flushes on every VMEXIT

**Guest save area** — CPU state snapshot:
- All general-purpose registers, segment descriptors (CS/SS/DS/ES/FS/GS), IDTR, GDTR
- CR0, CR3, CR4, EFER, DR6, DR7
- RIP, RSP, RFLAGS at the point of the last VMRUN

The VMCB must sit in physically contiguous memory — hence `MmAllocateContiguousNodeMemory`. Virtual addresses aren't enough; the hardware walks physical pages directly.

SVM also supports a "clean fields" bitmap in the VMCB that marks which save area regions haven't changed since the last VMEXIT. If the hypervisor doesn't touch certain fields between VMRUNs, it can set those bits and the CPU skips re-reading them, reducing context switch overhead.

---

## Initialization Flow

1. Check `CPUID` for SVM support; verify `EFER.SVME` can be set
2. For each logical core (via `KeSetSystemGroupAffinityThread`): allocate VMCB + host save area, capture current register state with `RtlCaptureContext`, fill VMCB guest save area, set intercept bits, call `VMRUN`
3. From this point the OS is a guest; SimpleSvm handles `#VMEXIT` events and returns control via `VMRUN`
4. On driver unload: devirtualize each core, restore host state, unload cleanly

Power transitions (sleep/hibernate) require devirtualization before suspend and re-virtualization after resume — done via `\Callback\PowerState`. Missing this causes a BSOD because the VMCB state is lost across a power cycle.

---

## CPUID Intercept

When a guest executes `CPUID`, SVM triggers `#VMEXIT` with exit code `0x72`. The hypervisor reads the requested leaf from the VMCB exit info fields, executes `CPUID` itself, modifies the result as needed, writes it back to the guest's RAX/RBX/RCX/RDX in the VMCB save area, then resumes.

| Leaf | What software checks | Default SimpleSvm behavior |
|------|---------------------|--------------------------|
| `0x1` ECX bit 31 | Hypervisor-present flag | Left set — guest sees a hypervisor |
| `0x40000000` | Hypervisor vendor string | Returns `"SimpleSvm "` |
| `0x8000000A` | SVM feature flags | Passed through |
| Everything else | — | Passed through |

Any software reading leaf `0x1` ECX will see bit 31 set while SimpleSvm runs, unless the handler explicitly clears it before writing back to the guest.

---

## MSR Intercept

SimpleSvm intercepts writes to `EFER` to block the guest from clearing `SVME`. If the guest could clear that bit, it would step out of SVM mode entirely and escape the hypervisor. The MSRPM bit for the `EFER` write path is set to 1 to trigger a `#VMEXIT` on any attempt.

---

## Key Kernel APIs

| API | Why it's needed |
|-----|----------------|
| `MmAllocateContiguousNodeMemory` | VMCB requires physical contiguity |
| `MmGetPhysicalAddress` | Hardware uses physical, not virtual, addresses |
| `RtlCaptureContext` | Snapshot all registers to seed the VMCB guest state |
| `KeSetSystemGroupAffinityThread` | Per-core init — must run on every logical processor |
| `KeQueryActiveProcessorCountEx` | Know how many VMCBs to allocate |
| `ExAllocatePool2` | Non-contiguous per-core metadata |
| `KeBugCheck` | Last-resort BSOD if the hypervisor hits an unrecoverable state |

---

## Glossary

| Term | Meaning |
|------|---------|
| SVM | AMD Secure Virtual Machine — the hardware extension enabling ring -1 |
| VT-x / VMX | Intel's equivalent of SVM |
| VMCB | Virtual Machine Control Block — AMD's per-core hypervisor control structure |
| VMCS | Virtual Machine Control Structure — Intel's equivalent |
| VMRUN | AMD instruction to enter guest mode |
| VMEXIT / `#VMEXIT` | Trap from guest to hypervisor |
| NPT | Nested Page Tables — AMD's second-level address translation |
| EPT | Extended Page Tables — Intel's equivalent of NPT |
| ASID | Address Space Identifier — avoids TLB invalidation on VMEXIT |
| MSRPM | MSR Permission Map — bitmap controlling which MSRs trigger VMEXIT |
| IOPM | I/O Permission Map — bitmap controlling which I/O ports trigger VMEXIT |
| EFER | Extended Feature Enable Register — contains the `SVME` bit |
| RDTSC | Read Timestamp Counter — can be intercepted to control timing visibility |
| Ring -1 | Hypervisor privilege level, above kernel ring 0 |
| Ring -2 | UEFI/firmware context, executes before the OS kernel |
