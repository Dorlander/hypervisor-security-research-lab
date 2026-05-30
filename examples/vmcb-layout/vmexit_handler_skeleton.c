/*
 * vmexit_handler_skeleton.c
 *
 * Annotated skeleton of an AMD SVM VMEXIT handler.
 *
 * This is NOT a working hypervisor — it's a study guide showing the structure
 * of how VMEXIT dispatch works and what each exit code means defensively.
 *
 * Based on public AMD documentation (AMD APM Vol. 2, Chapter 15) and
 * SimpleSvm source (github.com/tandasat/SimpleSvm, MIT).
 *
 * Exit codes are defined in AMD APM Table B-1.
 */

#include "vmcb_structs.h"
#include <stdint.h>

/* Exit codes from AMD APM Appendix B */
#define VMEXIT_CPUID        0x72
#define VMEXIT_MSR          0x7C
#define VMEXIT_VMRUN        0x80
#define VMEXIT_VMMCALL      0x81
#define VMEXIT_NPF          0x400   /* Nested Page Fault */
#define VMEXIT_INVALID      -1      /* Invalid VMCB state */

/* Guest register context — passed to the handler from the assembly entry stub.
 * The assembly saves all GPRs before calling into C. VMCB saves RIP, RSP,
 * RFLAGS, and segment state; the assembly entry stub saves RBX, RCX, RDX,
 * RSI, RDI, RBP, R8-R15 (everything not in the VMCB save area). */
typedef struct _GUEST_CONTEXT {
    uint64_t  Rax;   /* from VMCB save area — already saved by hardware */
    uint64_t  Rcx;
    uint64_t  Rdx;
    uint64_t  Rbx;
    uint64_t  Rbp;
    uint64_t  Rsi;
    uint64_t  Rdi;
    uint64_t  R8;
    uint64_t  R9;
    uint64_t  R10;
    uint64_t  R11;
    uint64_t  R12;
    uint64_t  R13;
    uint64_t  R14;
    uint64_t  R15;
    VMCB     *Vmcb;   /* pointer to this core's VMCB */
} GUEST_CONTEXT;

/* Forward declarations */
static void Handle_Cpuid(GUEST_CONTEXT *ctx);
static void Handle_Msr(GUEST_CONTEXT *ctx);
static void Handle_Vmrun(GUEST_CONTEXT *ctx);
static void Handle_Vmmcall(GUEST_CONTEXT *ctx);
static void Handle_Npf(GUEST_CONTEXT *ctx);

/*
 * VMEXIT dispatcher — called from the assembly entry stub after hardware
 * has already saved guest state to the VMCB and restored host state.
 *
 * On return, the assembly stub executes VMRUN to resume the guest.
 * Before returning, this function must ensure VMCB.GuestState.RIP
 * points to the instruction *after* the one that caused the exit
 * (or VMCB.ControlArea.NextRip if the CPU filled it in).
 */
void VmExitHandler(GUEST_CONTEXT *ctx)
{
    VMCB    *vmcb    = ctx->Vmcb;
    int64_t  exitCode = (int64_t)vmcb->ControlArea.ExitCode;

    switch (exitCode) {

    case VMEXIT_CPUID:
        Handle_Cpuid(ctx);
        break;

    case VMEXIT_MSR:
        Handle_Msr(ctx);
        break;

    case VMEXIT_VMRUN:
        Handle_Vmrun(ctx);
        break;

    case VMEXIT_VMMCALL:
        Handle_Vmmcall(ctx);
        break;

    case VMEXIT_NPF:
        Handle_Npf(ctx);
        break;

    case VMEXIT_INVALID:
        /*
         * VMCB state is invalid — the CPU refused to enter guest mode.
         * Common cause: ASID is 0 (must be >= 1), or NPT enabled but
         * N_CR3 is 0, or guest EFER.LME=1 but CR0.PG=0.
         * No way to recover gracefully here — BSOD.
         */
        /* KeBugCheck(HYPERVISOR_ERROR); — would go here */
        break;

    default:
        /*
         * Unhandled exit — shouldn't happen if intercept bits are set correctly.
         * In a research hypervisor, log the exit code and inject #UD into the
         * guest, or just skip the instruction and continue.
         */
        break;
    }
}

/* --------------------------------------------------------------------------
 * CPUID handler
 *
 * ExitInfo1/ExitInfo2 are not used for CPUID — the leaf and subleaf
 * are in the guest's RAX and RCX at the time of the exit.
 *
 * The handler executes CPUID itself (on the host), then modifies the
 * result before writing it back to the guest register state in the VMCB.
 * -------------------------------------------------------------------------- */
static void Handle_Cpuid(GUEST_CONTEXT *ctx)
{
    uint32_t leaf    = (uint32_t)ctx->Rax;
    uint32_t subleaf = (uint32_t)ctx->Rcx;
    int      info[4]; /* EAX, EBX, ECX, EDX */

    /*
     * Execute CPUID in host context:
     *   __cpuidex(info, leaf, subleaf);   ← MSVC intrinsic
     *   __cpuid_count(leaf, subleaf, ...); ← GCC
     *
     * [actual __cpuidex call would go here]
     */

    /*
     * Leaf 0x00000001 — feature flags.
     *
     * ECX bit 31 is the "hypervisor-present" bit. Intel/AMD spec originally
     * reserved it as 0; it was repurposed by the hypervisor community as a
     * convention to signal virtualization. Most production hypervisors set it.
     *
     * Anti-tamper and anti-cheat software reads this to detect VMs.
     * Clearing it makes the guest believe it's running on bare metal.
     */
    if (leaf == 0x00000001) {
        info[2] &= ~(1u << 31);  /* clear hypervisor-present bit in ECX */
    }

    /*
     * Leaf 0x40000000 — hypervisor vendor string.
     *
     * On bare metal this leaf returns 0. Under Hyper-V it returns "Microsoft Hv",
     * under KVM "KVMKVMKVM\0\0\0", etc. If we return 0 here, software that
     * reads both leaf 0x1 bit 31 AND the vendor string finds nothing.
     *
     * Alternatively, a hypervisor can return a custom vendor string here
     * to allow trusted guest software to communicate with it (VMMCALL channel).
     */
    if (leaf == 0x40000000) {
        info[0] = 0x40000000;  /* max hypervisor leaf — say it's just this one */
        info[1] = 0;
        info[2] = 0;
        info[3] = 0;
    }

    /* Write results back to guest RAX/RBX/RCX/RDX in the VMCB save area */
    ctx->Vmcb->GuestState.RAX = (uint64_t)(uint32_t)info[0];
    ctx->Rbx                  = (uint64_t)(uint32_t)info[1];
    ctx->Rcx                  = (uint64_t)(uint32_t)info[2];
    ctx->Rdx                  = (uint64_t)(uint32_t)info[3];

    /* Advance RIP past the CPUID instruction (2 bytes: 0F A2) */
    ctx->Vmcb->GuestState.RIP = ctx->Vmcb->ControlArea.NextRip;
}

/* --------------------------------------------------------------------------
 * MSR handler
 *
 * ExitInfo1 bit 0: 0 = RDMSR, 1 = WRMSR
 * The MSR number is in guest RCX at exit time.
 * -------------------------------------------------------------------------- */
static void Handle_Msr(GUEST_CONTEXT *ctx)
{
    int      is_write = (int)(ctx->Vmcb->ControlArea.ExitInfo1 & 1);
    uint32_t msr_num  = (uint32_t)ctx->Rcx;

    if (!is_write) {
        /* RDMSR — read a model-specific register */
        switch (msr_num) {
        case 0xC0000080: /* EFER */
            /*
             * If we intercept EFER reads, we can hide the SVME bit from the guest.
             * The guest OS then doesn't know SVM mode is enabled — it can't
             * attempt to call VMRUN itself or check the EFER.SVME state.
             *
             * [__readmsr(msr_num) with SVME bit cleared would go here]
             */
            break;

        default:
            /*
             * Pass through all other RDMSR calls unmodified.
             * Return value goes in EDX:EAX (upper:lower 32 bits).
             *
             * [__readmsr(msr_num) split into EDX:EAX would go here]
             */
            break;
        }
    } else {
        /* WRMSR — write to MSR */
        switch (msr_num) {
        case 0xC0000080: /* EFER */
            /*
             * Block guest from clearing SVME bit (bit 12 of EFER).
             * If the guest clears SVME, it disables SVM mode and the hypervisor
             * loses control — effectively a guest escape.
             *
             * Force SVME to stay set before passing the write through.
             *
             * [__writemsr with SVME forced would go here]
             */
            break;

        default:
            /* Pass through */
            /* [__writemsr(msr_num, value) would go here] */
            break;
        }
    }

    /* Advance RIP past the RDMSR/WRMSR instruction (2 bytes: 0F 32 / 0F 30) */
    ctx->Vmcb->GuestState.RIP = ctx->Vmcb->ControlArea.NextRip;
}

/* --------------------------------------------------------------------------
 * VMRUN handler — guest tried to execute VMRUN (nested virtualization)
 *
 * SimpleSvm injects #GP (General Protection Fault) here to prevent the
 * guest from running its own nested hypervisor, which would complicate
 * intercept handling.
 * -------------------------------------------------------------------------- */
static void Handle_Vmrun(GUEST_CONTEXT *ctx)
{
    /*
     * Inject #GP(0) into the guest.
     *
     * EventInject field format (AMD APM 15.20):
     *   bits 7:0   — vector (13 = #GP)
     *   bits 10:8  — type (3 = exception)
     *   bit  11    — error code valid
     *   bit  31    — valid (inject this event on next VMRUN)
     *   bits 63:32 — error code
     *
     * Computed value: (1<<31)|(3<<8)|(1<<11)|13 = 0x80000B0D
     *   bit 31 set  = valid
     *   bits 10:8   = 3 (exception type)
     *   bit 11 set  = error code valid (error code = 0, in upper 32 bits)
     *   bits 7:0    = 13 (#GP vector)
     * #GP on VMRUN carries error code 0 per AMD APM.
     */
    ctx->Vmcb->ControlArea.EventInject =
        (1ULL << 31) |   /* valid */
        (3ULL <<  8) |   /* type: exception */
        (1ULL << 11) |   /* error code valid */
        13;              /* vector: #GP */
    /* Error code in upper 32 bits — 0 for this case */

    /* Do NOT advance RIP — the exception will restart at the VMRUN instruction */
}

/* --------------------------------------------------------------------------
 * VMMCALL handler — guest executed VMMCALL to call into the hypervisor.
 *
 * This is the intended hypercall interface. Guest software can pass a
 * "magic" value in RAX to request hypervisor services — e.g., devirtualization,
 * feature queries, or (in modified SimpleSvm) registering the game process PID
 * for targeted KUSER_SHARED_DATA spoofing.
 *
 * Example: the modified SimpleSvm used in Denuvo bypass checks RAX for magic
 * values like 0x69696969 and 0x1337 to register the target process.
 * -------------------------------------------------------------------------- */
static void Handle_Vmmcall(GUEST_CONTEXT *ctx)
{
    uint64_t magic = ctx->Rax;

    switch (magic) {
    case 0x1:
        /* Example: query hypervisor version */
        ctx->Rax = 0x00010000; /* version 1.0 */
        break;

    case 0x2:
        /* Example: request devirtualization (used to exit cleanly on driver unload) */
        /*
         * At this point the hypervisor would:
         * 1. Set a "stop" flag so the loop in the VMRUN-calling assembly exits
         * 2. The assembly then does NOT call VMRUN again — host keeps running
         * 3. The OS returns to native execution without the hypervisor
         *
         * [devirtualization trigger would go here]
         */
        break;

    default:
        /* Unknown hypercall — return error in RAX, continue guest */
        ctx->Rax = (uint64_t)-1;
        break;
    }

    ctx->Vmcb->GuestState.RIP = ctx->Vmcb->ControlArea.NextRip;
}

/* --------------------------------------------------------------------------
 * NPF (Nested Page Fault) handler
 *
 * Triggered when the guest accesses a guest physical address that has no
 * valid mapping in the nested page table (NPT), or when permissions are
 * violated (read from no-read page, execute from no-execute page, etc.).
 *
 * ExitInfo1 bits:
 *   bit 0 — present: 0 = page not present, 1 = protection violation
 *   bit 1 — write:   0 = read, 1 = write
 *   bit 2 — user:    0 = supervisor, 1 = user mode access
 *   bit 4 — execute: instruction fetch caused the fault
 *
 * ExitInfo2 — faulting guest physical address
 *
 * EPT violations on Intel work the same way with different bit positions.
 * -------------------------------------------------------------------------- */
static void Handle_Npf(GUEST_CONTEXT *ctx)
{
    uint64_t fault_gpa   = ctx->Vmcb->ControlArea.ExitInfo2;
    uint64_t fault_flags = ctx->Vmcb->ControlArea.ExitInfo1;

    int is_present = (int)(fault_flags & 1);
    int is_write   = (int)((fault_flags >> 1) & 1);
    int is_exec    = (int)((fault_flags >> 4) & 1);

    /*
     * Typical handling:
     *
     * 1. Map the faulting GPA in the NPT (allocate a new NPT page and map it)
     * 2. If this is a monitoring page (EPT hook equivalent) — record the access,
     *    temporarily remove the hook, single-step the instruction, restore hook
     * 3. If unexpected — log and inject #PF into the guest
     *
     * HyperDbg uses NPF as its primary mechanism for invisible memory breakpoints:
     * mark a physical page as no-execute in the NPT → any instruction fetch from
     * that page triggers NPF → the hypervisor logs it and resumes.
     * This is invisible to the guest because the NPT lives entirely in host memory.
     */

    (void)fault_gpa;
    (void)is_present;
    (void)is_write;
    (void)is_exec;

    /* [NPT mapping or hook handling would go here] */
}
