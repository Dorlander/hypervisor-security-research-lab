/*
 * vmcb_structs.h
 *
 * VMCB (Virtual Machine Control Block) structure layout for AMD SVM.
 *
 * Source: AMD64 Architecture Programmer's Manual, Volume 2, Chapter 15
 * (Secure Virtual Machine Architecture). This is entirely from public
 * vendor documentation — no proprietary code.
 *
 * The VMCB is a 4KB hardware-defined structure split into two 2KB halves:
 *   - Control area  (offset 0x000 – 0x3FF): what the hypervisor configures
 *   - Guest save area (offset 0x400 – 0xFFF): CPU state snapshot
 *
 * Hardware reads and writes these directly by physical address.
 * The VMCB must be in physically contiguous memory (hence MmAllocateContiguousNodeMemory).
 * The CPU does NOT use virtual addresses here — virtual→physical translation
 * must be resolved before passing the address to VMRUN.
 */

#pragma once
#include <stdint.h>

/*
 * Compiler note: bit field ordering within a storage unit is implementation-defined
 * in C. This struct assumes MSVC behavior (fields allocated from low bit to high bit),
 * which matches the AMD hardware layout (AMD APM Vol. 2, Fig. 15-1).
 * GCC and Clang use the same low-to-high ordering on x86 in practice, but this is
 * not guaranteed by the standard. Do not use this struct to directly memory-map a
 * real VMCB without verifying bit positions against the actual AMD APM offsets.
 */

/* =========================================================================
 * MSRPM — MSR Permission Map
 *
 * 8KB (two 4KB pages), physically contiguous.
 * Two bits per MSR:
 *   bit 0 = intercept reads  (1 = VMEXIT on RDMSR)
 *   bit 1 = intercept writes (1 = VMEXIT on WRMSR)
 *
 * MSR ranges covered:
 *   Chunk 0: MSRs 0x00000000 – 0x00001FFF  (0x2000 MSRs × 2 bits = 8KB, split across pages)
 *   Chunk 1: MSRs 0xC0000000 – 0xC0001FFF
 *   Chunk 2: MSRs 0xC0010000 – 0xC0011FFF
 *
 * Example: to intercept RDMSR/WRMSR for EFER (0xC0000080):
 *   EFER is in chunk 1 (C0000000 range).
 *   Index within chunk 1 = 0xC0000080 - 0xC0000000 = 0x80
 *   Bit position in MSRPM = (chunk1_offset_bytes * 8) + (0x80 * 2) + 0/1
 * ========================================================================= */
#define MSRPM_SIZE  0x2000  /* 8KB */
#define IOPM_SIZE   0x3000  /* 12KB */

/* =========================================================================
 * VMCB Control Area (offset 0x000)
 * ========================================================================= */
typedef struct _VMCB_CONTROL_AREA {

    /* 0x000 — Intercept exceptions (one bit per exception vector 0–31) */
    uint32_t  InterceptExceptions;

    /* 0x004 — Intercept instruction groups (first word) */
    uint32_t  InterceptCrReads    : 16;  /* CR0–CR15 read */
    uint32_t  InterceptCrWrites   : 16;  /* CR0–CR15 write */

    /* 0x008 */
    uint32_t  InterceptDrReads    : 16;  /* DR0–DR15 read */
    uint32_t  InterceptDrWrites   : 16;  /* DR0–DR15 write */

    /* 0x00C — General intercept flags */
    uint32_t  InterceptIntr       :  1;  /* physical interrupts */
    uint32_t  InterceptNmi        :  1;
    uint32_t  InterceptSmi        :  1;
    uint32_t  InterceptInit       :  1;
    uint32_t  InterceptVIntr      :  1;  /* virtual interrupts */
    uint32_t  InterceptCrWr0      :  1;  /* CR0 writes that change PE/PG only */
    uint32_t  InterceptIdtrRd     :  1;
    uint32_t  InterceptGdtrRd     :  1;
    uint32_t  InterceptLdtrRd     :  1;
    uint32_t  InterceptTrRd       :  1;
    uint32_t  InterceptIdtrWr     :  1;
    uint32_t  InterceptGdtrWr     :  1;
    uint32_t  InterceptLdtrWr     :  1;
    uint32_t  InterceptTrWr       :  1;
    uint32_t  InterceptRdtsc      :  1;  /* RDTSC — needed for timing spoof */
    uint32_t  InterceptRdpmc      :  1;
    uint32_t  InterceptPushf      :  1;
    uint32_t  InterceptPopf       :  1;
    uint32_t  InterceptCpuid      :  1;  /* CPUID — needed for HV-present spoof */
    uint32_t  InterceptRsm        :  1;
    uint32_t  InterceptIret       :  1;
    uint32_t  InterceptIntn       :  1;  /* INT n */
    uint32_t  InterceptInvd       :  1;
    uint32_t  InterceptPause      :  1;
    uint32_t  InterceptHlt        :  1;
    uint32_t  InterceptInvlpg     :  1;
    uint32_t  InterceptInvlpga    :  1;
    uint32_t  InterceptIoio       :  1;  /* IN/OUT — requires IOPM */
    uint32_t  InterceptMsr        :  1;  /* RDMSR/WRMSR — requires MSRPM */
    uint32_t  InterceptTaskSwitch :  1;
    uint32_t  InterceptFerrFreeze :  1;
    uint32_t  InterceptShutdown   :  1;

    /* 0x010 */
    uint32_t  InterceptVmrun      :  1;  /* prevent nested VMRUN from guest */
    uint32_t  InterceptVmmcall    :  1;  /* guest calling into hypervisor */
    uint32_t  InterceptVmload     :  1;
    uint32_t  InterceptVmsave     :  1;
    uint32_t  InterceptStgi       :  1;
    uint32_t  InterceptClgi       :  1;
    uint32_t  InterceptSkinit     :  1;
    uint32_t  InterceptRdtscp     :  1;  /* RDTSCP — companion to RDTSC intercept */
    uint32_t  InterceptIcebp      :  1;
    uint32_t  InterceptWbinvd     :  1;
    uint32_t  InterceptMonitor    :  1;
    uint32_t  InterceptMwait      :  1;
    uint32_t  InterceptMwaitCond  :  1;
    uint32_t  InterceptXsetbv     :  1;
    uint32_t  Reserved0           : 18;

    uint8_t   Reserved1[0x03C - 0x014];

    /* 0x03C — IOPM base physical address */
    uint64_t  IopmBasePa;

    /* 0x044 — MSRPM base physical address */
    uint64_t  MsrpmBasePa;

    /* 0x04C — TSC offset added to RDTSC results seen by the guest */
    uint64_t  TscOffset;

    /* 0x054 — Guest ASID (Address Space Identifier, must be non-zero) */
    uint32_t  GuestAsid;

    /* 0x058 — TLB control (0 = no flush, 1 = flush all on VMRUN) */
    uint32_t  TlbControl;

    /* 0x05C — Virtual interrupt state */
    uint64_t  VIntr;

    /* 0x064 — Interrupt shadow (set during STI / MOV-SS) */
    uint64_t  InterruptShadow;

    /* 0x06C — Exit code — filled by CPU on #VMEXIT */
    uint64_t  ExitCode;

    /* 0x074 — Exit info 1 & 2 — details of the exit (e.g., which MSR, CPUID leaf) */
    uint64_t  ExitInfo1;
    uint64_t  ExitInfo2;

    /* 0x084 — Exit interrupt info */
    uint64_t  ExitIntInfo;

    /* 0x08C — Nested paging enable + other NPF bits */
    uint64_t  NpEnable;

    /* 0x094 — AVIC (Advanced Virtual Interrupt Controller) fields */
    uint64_t  AvicApicBar;

    /* 0x09C — Guest PA of GHCB (for AMD SEV-ES) */
    uint64_t  GhcbGpa;

    /* 0x0A4 — Event injection — inject exception/interrupt into guest on next VMRUN */
    uint64_t  EventInject;

    /* 0x0AC — N_CR3 — Nested page table root (physical address of PML4 for NPT) */
    uint64_t  NCr3;

    /* 0x0B4 — LBR virtualization, virtualized VMSAVE/VMLOAD */
    uint64_t  LbrVirt;

    /* 0x0B8 — VMCB state clean fields bitmap
     *
     * Optimization: if the hypervisor hasn't changed certain VMCB fields since
     * the last VMEXIT, it can set the corresponding bits here. The CPU then
     * skips re-reading those fields on the next VMRUN, reducing overhead.
     *
     * Bit meanings (AMD APM Table 15-10):
     *   bit 0  — I   (intercept controls, IOPM, MSRPM)
     *   bit 1  — IOPM
     *   bit 2  — ASID
     *   bit 3  — TPR (V_TPR field)
     *   bit 4  — NP  (nested paging state, N_CR3)
     *   bit 5  — CRx (CR0-CR4, EFER, DR6-DR7)
     *   bit 6  — DRx
     *   bit 7  — DT  (IDTR, GDTR)
     *   bit 8  — SEG (CS, DS, SS, ES, FS, GS, TR, LDTR)
     *   bit 9  — CR2
     *   bit 10 — LBR
     *   bit 11 — AVIC
     */
    uint32_t  VmcbCleanBits;

    uint32_t  Reserved2;

    /* 0x0C0 — Next RIP (set by CPU for instructions that cause VMEXIT) */
    uint64_t  NextRip;

    /* 0x0C8 — Number of bytes fetched for the instruction that caused VMEXIT */
    uint8_t   NumOfBytesFetched;
    uint8_t   GuestInstructionBytes[15];

    /* 0x0D8 — AVIC fields */
    uint64_t  AvicApicBacking;
    uint64_t  Reserved3;
    uint64_t  AvicLogicalTable;
    uint64_t  AvicPhysicalTable;

    uint8_t   Reserved4[0x400 - 0x0F8];

} VMCB_CONTROL_AREA;

/* =========================================================================
 * VMCB Guest Save Area (offset 0x400)
 *
 * Snapshot of all guest CPU state. The CPU saves this on #VMEXIT and
 * restores it on VMRUN. The hypervisor populates this once at initialization
 * (from RtlCaptureContext output) and the hardware keeps it up to date.
 * ========================================================================= */
typedef struct _SEGMENT_DESCRIPTOR {
    uint16_t  Selector;
    uint16_t  Attributes;  /* packed segment attributes (P, DPL, S, Type, etc.) */
    uint32_t  Limit;
    uint64_t  Base;
} SEGMENT_DESCRIPTOR;

typedef struct _VMCB_GUEST_SAVE_AREA {
    /* 0x400 — Segment registers */
    SEGMENT_DESCRIPTOR  ES;
    SEGMENT_DESCRIPTOR  CS;
    SEGMENT_DESCRIPTOR  SS;
    SEGMENT_DESCRIPTOR  DS;
    SEGMENT_DESCRIPTOR  FS;
    SEGMENT_DESCRIPTOR  GS;
    SEGMENT_DESCRIPTOR  GDTR;   /* base + limit only, selector/attr unused */
    SEGMENT_DESCRIPTOR  LDTR;
    SEGMENT_DESCRIPTOR  IDTR;   /* base + limit only */
    SEGMENT_DESCRIPTOR  TR;

    uint8_t  Reserved0[0x4CB - 0x4A0];

    /* 0x4CB — CPL at time of VMEXIT */
    uint8_t  CPL;

    uint8_t  Reserved1[4];

    /* 0x4D0 — EFER */
    uint64_t  EFER;

    uint8_t  Reserved2[0x548 - 0x4D8];

    /* 0x548 — Control registers */
    uint64_t  CR4;
    uint64_t  CR3;  /* guest page table root */
    uint64_t  CR0;
    uint64_t  DR7;
    uint64_t  DR6;
    uint64_t  RFLAGS;
    uint64_t  RIP;

    uint8_t  Reserved3[0x5D8 - 0x580];

    /* 0x5D8 — Stack and general-purpose registers */
    uint64_t  RSP;

    uint8_t  Reserved4[0x5F8 - 0x5E0];

    uint64_t  RAX;

    /* 0x600 — MSRs */
    uint64_t  STAR;
    uint64_t  LSTAR;  /* long-mode SYSCALL target RIP */
    uint64_t  CSTAR;
    uint64_t  SFMASK;

    uint64_t  KernelGsBase;
    uint64_t  SysenterCs;
    uint64_t  SysenterEsp;
    uint64_t  SysenterEip;

    uint64_t  CR2;  /* page fault linear address */

    uint8_t  Reserved5[0x638 - 0x630];

    uint64_t  GPAT;         /* guest PAT MSR */
    uint64_t  DbgCtl;
    uint64_t  BrFrom;
    uint64_t  BrTo;
    uint64_t  LastExcepFrom;
    uint64_t  LastExcepTo;

    /* ... remaining fields are LBR and AVIC state ... */

} VMCB_GUEST_SAVE_AREA;

/* =========================================================================
 * Full VMCB — 4KB
 * ========================================================================= */
typedef struct _VMCB {
    VMCB_CONTROL_AREA   ControlArea;   /* 0x000 – 0x3FF */
    VMCB_GUEST_SAVE_AREA GuestState;   /* 0x400 – 0xFFF */
} VMCB;

/*
 * === What happens at VMRUN (conceptually) ===
 *
 * 1. CPU reads the physical VMCB address from RAX
 * 2. Saves host state to the Host Save Area (separate 4KB page, physical addr in VM_HSAVE_PA MSR)
 * 3. Loads guest state from VMCB.GuestState into CPU registers
 * 4. Applies intercept configuration from VMCB.ControlArea
 * 5. Begins executing guest at VMCB.GuestState.RIP
 *
 * === What happens at #VMEXIT ===
 *
 * 1. CPU saves current guest register state back to VMCB.GuestState
 * 2. Writes exit reason to VMCB.ControlArea.ExitCode
 * 3. Fills ExitInfo1/ExitInfo2 with details (e.g., for CPUID exit: leaf in RAX)
 * 4. Restores host state from Host Save Area
 * 5. Execution resumes at the instruction after VMRUN in the host (hypervisor)
 *
 * The hypervisor then inspects ExitCode, handles the event (e.g., emulates
 * CPUID with modified results), updates VMCB.GuestState.RIP to point past
 * the trapped instruction (or uses NextRip if available), and calls VMRUN again.
 *
 * === Why this matters defensively ===
 *
 * Any software running inside a VM (guest) that tries to detect virtualization
 * by reading CPUID, RDTSC, or specific MSRs can be fooled if the hypervisor
 * intercepts those instructions and returns crafted values.
 *
 * The CPUID intercept bit (ControlArea.InterceptCpuid) + VMEXIT handler that
 * clears ECX bit 31 on leaf 0x1 is the mechanism behind "hypervisor hiding."
 * The RDTSC intercept (InterceptRdtsc) + TscOffset field control timing visibility.
 */
