/*
 * cpuid_check.c
 *
 * Reads CPUID leaves relevant to virtualization research.
 * Completely user-mode, no privileges needed, no kernel interaction.
 *
 * Compile (MSVC):  cl cpuid_check.c
 * Compile (GCC):   gcc cpuid_check.c -o cpuid_check
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#ifdef _MSC_VER
#include <intrin.h>
static void cpuid(int leaf, int subleaf, int *eax, int *ebx, int *ecx, int *edx)
{
    int info[4];
    __cpuidex(info, leaf, subleaf);
    *eax = info[0]; *ebx = info[1]; *ecx = info[2]; *edx = info[3];
}
#else
#include <cpuid.h>
static void cpuid(int leaf, int subleaf, int *eax, int *ebx, int *ecx, int *edx)
{
    __cpuid_count(leaf, subleaf, *eax, *ebx, *ecx, *edx);
}
#endif

/* --- helpers ------------------------------------------------------------ */

static void print_vendor_string(int ebx, int ecx, int edx)
{
    /* CPUID returns vendor as three 4-byte chunks packed in EBX, EDX, ECX
     * (note the order: EBX, EDX, ECX — not EBX, ECX, EDX) */
    char vendor[13];
    memcpy(vendor + 0, &ebx, 4);
    memcpy(vendor + 4, &edx, 4);
    memcpy(vendor + 8, &ecx, 4);
    vendor[12] = '\0';
    printf("  Vendor string: \"%s\"\n", vendor);

    if (strcmp(vendor, "AuthenticAMD") == 0)
        printf("  -> AMD processor confirmed\n");
    else if (strcmp(vendor, "GenuineIntel") == 0)
        printf("  -> Intel processor confirmed\n");
    else
        printf("  -> Unknown vendor (VM? nested virt?)\n");
}

/* --- CPUID leaf analysis ------------------------------------------------- */

static void check_leaf_0(void)
{
    int eax, ebx, ecx, edx;
    cpuid(0x0, 0, &eax, &ebx, &ecx, &edx);
    printf("[Leaf 0x00000000] Max standard leaf: 0x%08X\n", eax);
    print_vendor_string(ebx, ecx, edx);
}

static void check_leaf_1(void)
{
    int eax, ebx, ecx, edx;
    cpuid(0x1, 0, &eax, &ebx, &ecx, &edx);

    printf("\n[Leaf 0x00000001] Feature flags\n");
    printf("  Family/Model/Stepping: 0x%08X\n", eax);

    /*
     * ECX bit 31 — hypervisor-present bit.
     *
     * The Intel/AMD spec originally reserved this bit as 0. Microsoft
     * repurposed it as a convention: any hypervisor (Hyper-V, VMware, KVM,
     * VirtualBox, etc.) is supposed to set it so guest software knows it's
     * running virtualized. Not all hypervisors comply, but most do.
     *
     * Denuvo Anti-Tamper reads this bit to detect analysis environments.
     * An intercepting hypervisor (SimpleSvm, HyperDbg) can clear it before
     * returning to the guest, making the guest believe no hypervisor is present.
     */
    int hv_present = (ecx >> 31) & 1;
    printf("  ECX bit 31 (hypervisor-present): %d", hv_present);
    if (hv_present)
        printf("  <- hypervisor detected\n");
    else
        printf("  <- bare metal (or HV hiding itself)\n");

    /* ECX bit 5 — VMX available (Intel VT-x) */
    printf("  ECX bit 5  (VMX / Intel VT-x):   %d\n", (ecx >> 5) & 1);

    /* ECX bit 28 — AVX available (unrelated to virt, but useful to log) */
    printf("  ECX bit 28 (AVX):                 %d\n", (ecx >> 28) & 1);
}

static void check_leaf_hv_vendor(void)
{
    int eax, ebx, ecx, edx;
    cpuid(0x40000000, 0, &eax, &ebx, &ecx, &edx);

    printf("\n[Leaf 0x40000000] Hypervisor vendor\n");
    printf("  Max hypervisor leaf: 0x%08X\n", eax);

    /*
     * If a hypervisor is present, leaf 0x40000000 returns a 12-byte vendor
     * string packed as EBX:ECX:EDX.
     *
     * Note: this is DIFFERENT from the CPU vendor string on leaf 0, which
     * uses EBX:EDX:ECX order (see print_vendor_string). The hypervisor vendor
     * leaf uses EBX:ECX:EDX — check the Hyper-V TLFS or KVM docs for confirmation.
     *
     * Known strings:
     *   "Microsoft Hv"  — Hyper-V
     *   "KVMKVMKVM\0\0\0" — KVM (Linux)
     *   "VMwareVMware"  — VMware
     *   "VBoxVBoxVBox"  — VirtualBox
     *   "XenVMMXenVMM"  — Xen
     *   "SimpleSvm    " — SimpleSvm (educational, tandasat)
     *
     * If eax == 0 and the string is zeros/garbage, no standard-compliant
     * hypervisor is present (or it's hiding this leaf too).
     */
    char hv_vendor[13];
    memcpy(hv_vendor + 0, &ebx, 4);
    memcpy(hv_vendor + 4, &ecx, 4);
    memcpy(hv_vendor + 8, &edx, 4);
    hv_vendor[12] = '\0';

    int all_zero = 1;
    for (int i = 0; i < 12; i++) if (hv_vendor[i]) { all_zero = 0; break; }

    if (all_zero)
        printf("  Hypervisor vendor string: (empty — no standard HV or HV hiding)\n");
    else
        printf("  Hypervisor vendor string: \"%s\"\n", hv_vendor);
}

static void check_leaf_8000000a(void)
{
    int eax, ebx, ecx, edx;
    cpuid(0x80000000, 0, &eax, &ebx, &ecx, &edx);
    printf("\n[Leaf 0x80000000] Max extended leaf: 0x%08X\n", eax);

    if ((unsigned int)eax < 0x8000000A) {
        printf("  Leaf 0x8000000A not supported (SVM info unavailable)\n");
        return;
    }

    cpuid(0x8000000A, 0, &eax, &ebx, &ecx, &edx);
    printf("\n[Leaf 0x8000000A] AMD SVM features\n");

    /*
     * EAX bits 7:0 — SVM revision number.
     * If this is 0, SVM is not supported (or CPUID is intercepted).
     *
     * EBX — number of address space identifiers (ASIDs) available.
     * Each VMCB can be assigned an ASID so the CPU can keep TLB entries
     * for multiple VMs without flushing everything on every VMEXIT.
     * More ASIDs = less TLB thrashing = better performance.
     *
     * EDX bit 0 — nested paging (NPT) supported.
     * NPT is AMD's second-level address translation (EPT on Intel).
     * Required for proper guest physical memory isolation.
     *
     * EDX bit 2 — VMCB clean bits supported.
     * Allows the hypervisor to mark unchanged VMCB fields so the CPU
     * can skip reloading them on VMRUN, reducing VMEXIT overhead.
     */
    int svm_rev = eax & 0xFF;
    int nasids  = ebx;
    int npt     = edx & 1;
    int clean   = (edx >> 2) & 1;
    int flush   = (edx >> 3) & 1; /* flush-by-ASID */

    printf("  SVM revision:         %d\n", svm_rev);
    printf("  Available ASIDs:      %d\n", nasids);
    printf("  Nested Paging (NPT):  %s\n", npt   ? "yes" : "no");
    printf("  VMCB Clean Bits:      %s\n", clean ? "yes" : "no");
    printf("  Flush-by-ASID:        %s\n", flush ? "yes" : "no");

    if (svm_rev == 0)
        printf("  -> SVM revision 0: processor does not support SVM\n");
}

/* --- main --------------------------------------------------------------- */

int main(void)
{
    printf("=== CPUID Virtualization Feature Check ===\n\n");

    check_leaf_0();
    check_leaf_1();
    check_leaf_hv_vendor();
    check_leaf_8000000a();

    printf("\n=== done ===\n");
    return 0;
}
