/*
 * cpuid_check.c
 *
 * User-mode CPUID / XCR0 diagnostics for virtualization research labs.
 * No privileges, no kernel driver, no guest modification. Output is meant to
 * document what the current environment reports, not to bypass or hide it.
 *
 * Compile (MSVC):  cl /W4 cpuid_check.c
 * Compile (GCC):   gcc -Wall -Wextra cpuid_check.c -o cpuid_check
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef _MSC_VER
#include <intrin.h>
static void cpuid(int leaf, int subleaf, int *eax, int *ebx, int *ecx, int *edx)
{
    int info[4];
    __cpuidex(info, leaf, subleaf);
    *eax = info[0]; *ebx = info[1]; *ecx = info[2]; *edx = info[3];
}
static uint64_t xgetbv0(void)
{
    return _xgetbv(0);
}
static uint64_t rdtsc(void)
{
    return __rdtsc();
}
#else
#include <cpuid.h>
static void cpuid(int leaf, int subleaf, int *eax, int *ebx, int *ecx, int *edx)
{
    __cpuid_count((unsigned int)leaf, (unsigned int)subleaf,
                  *eax, *ebx, *ecx, *edx);
}
static uint64_t xgetbv0(void)
{
    uint32_t eax, edx;
    __asm__ volatile(".byte 0x0f, 0x01, 0xd0" : "=a"(eax), "=d"(edx) : "c"(0));
    return ((uint64_t)edx << 32) | eax;
}
static uint64_t rdtsc(void)
{
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}
#endif

/* --- helpers ------------------------------------------------------------ */

static const char *yesno(int v)
{
    return v ? "yes" : "no";
}

static void copy_reg_string(char out[13], int r0, int r1, int r2)
{
    memcpy(out + 0, &r0, 4);
    memcpy(out + 4, &r1, 4);
    memcpy(out + 8, &r2, 4);
    out[12] = '\0';
}

static void print_cpu_vendor_string(int ebx, int ecx, int edx)
{
    /* CPU vendor leaf 0 packs the string in EBX, EDX, ECX order. */
    char vendor[13];
    copy_reg_string(vendor, ebx, edx, ecx);
    printf("  Vendor string: \"%s\"\n", vendor);

    if (strcmp(vendor, "AuthenticAMD") == 0)
        printf("  Vendor class:  AMD\n");
    else if (strcmp(vendor, "GenuineIntel") == 0)
        printf("  Vendor class:  Intel\n");
    else
        printf("  Vendor class:  other / virtualized / uncommon\n");
}

static unsigned int get_max_standard_leaf(void)
{
    int eax, ebx, ecx, edx;
    cpuid(0x0, 0, &eax, &ebx, &ecx, &edx);
    return (unsigned int)eax;
}

static unsigned int get_max_extended_leaf(void)
{
    int eax, ebx, ecx, edx;
    cpuid(0x80000000, 0, &eax, &ebx, &ecx, &edx);
    return (unsigned int)eax;
}

/* --- CPUID leaf analysis ------------------------------------------------- */

static void check_leaf_0(void)
{
    int eax, ebx, ecx, edx;
    cpuid(0x0, 0, &eax, &ebx, &ecx, &edx);

    printf("[Leaf 0x00000000] CPU vendor\n");
    printf("  Max standard leaf: 0x%08X\n", eax);
    print_cpu_vendor_string(ebx, ecx, edx);
}

static void check_cpu_brand(void)
{
    if (get_max_extended_leaf() < 0x80000004U) {
        printf("\n[CPU brand string]\n  Not supported\n");
        return;
    }

    int regs[12];
    cpuid(0x80000002, 0, &regs[0], &regs[1], &regs[2], &regs[3]);
    cpuid(0x80000003, 0, &regs[4], &regs[5], &regs[6], &regs[7]);
    cpuid(0x80000004, 0, &regs[8], &regs[9], &regs[10], &regs[11]);

    char brand[49];
    memcpy(brand, regs, 48);
    brand[48] = '\0';

    printf("\n[CPU brand string]\n");
    printf("  \"%s\"\n", brand);
}

static void check_leaf_1(void)
{
    int eax, ebx, ecx, edx;
    cpuid(0x1, 0, &eax, &ebx, &ecx, &edx);

    printf("\n[Leaf 0x00000001] Basic feature flags\n");
    printf("  Family/Model/Stepping raw EAX:    0x%08X\n", eax);

    int hv_present = (ecx >> 31) & 1;
    printf("  ECX bit 31 (hypervisor-present):  %d", hv_present);
    printf(hv_present ? "  <- reported by environment\n" : "  <- not reported\n");

    printf("  ECX bit 5  (VMX / Intel VT-x):    %s\n", yesno((ecx >> 5) & 1));
    printf("  ECX bit 27 (OSXSAVE):             %s\n", yesno((ecx >> 27) & 1));
    printf("  ECX bit 28 (AVX):                 %s\n", yesno((ecx >> 28) & 1));
    printf("  EDX bit 26 (SSE2):                %s\n", yesno((edx >> 26) & 1));

    if ((ecx >> 27) & 1) {
        uint64_t xcr0 = xgetbv0();
        printf("  XCR0:                             0x%016llX\n",
               (unsigned long long)xcr0);
        printf("    x87 state enabled:              %s\n", yesno((int)((xcr0 >> 0) & 1)));
        printf("    XMM state enabled:              %s\n", yesno((int)((xcr0 >> 1) & 1)));
        printf("    YMM state enabled:              %s\n", yesno((int)((xcr0 >> 2) & 1)));
        printf("    AVX usable by OS:               %s\n",
               yesno(((ecx >> 28) & 1) && ((xcr0 & 0x6) == 0x6)));
    }

    printf("  Note: VMX/SVM availability does not prove firmware enabled it;\n");
    printf("        that requires privileged MSR checks outside this user-mode sample.\n");
}

static void check_leaf_7(void)
{
    if (get_max_standard_leaf() < 0x7U) {
        printf("\n[Leaf 0x00000007:0] Not supported\n");
        return;
    }

    int eax, ebx, ecx, edx;
    cpuid(0x7, 0, &eax, &ebx, &ecx, &edx);

    printf("\n[Leaf 0x00000007:0] Structured extended features\n");
    printf("  EBX bit 5  (AVX2):                %s\n", yesno((ebx >> 5) & 1));
    printf("  EBX bit 7  (SMEP):                %s\n", yesno((ebx >> 7) & 1));
    printf("  EBX bit 16 (AVX-512F):            %s\n", yesno((ebx >> 16) & 1));
    printf("  EBX bit 18 (RDSEED):              %s\n", yesno((ebx >> 18) & 1));
    printf("  EBX bit 20 (SMAP):                %s\n", yesno((ebx >> 20) & 1));
    printf("  EBX bit 29 (SHA):                 %s\n", yesno((ebx >> 29) & 1));
    printf("  ECX bit 2  (UMIP):                %s\n", yesno((ecx >> 2) & 1));
    printf("  ECX bit 5  (WAITPKG):             %s\n", yesno((ecx >> 5) & 1));
    printf("  ECX bit 30 (SGX Launch Config):   %s\n", yesno((ecx >> 30) & 1));

    (void)eax;
    (void)edx;
}

static unsigned int check_leaf_hv_vendor(void)
{
    int eax, ebx, ecx, edx;
    cpuid(0x40000000, 0, &eax, &ebx, &ecx, &edx);

    printf("\n[Leaf 0x40000000] Hypervisor vendor leaf\n");
    printf("  Max hypervisor leaf:              0x%08X\n", eax);

    /* Hypervisor vendor leaf packs the string in EBX, ECX, EDX order. */
    char hv_vendor[13];
    copy_reg_string(hv_vendor, ebx, ecx, edx);

    int all_zero = 1;
    for (int i = 0; i < 12; i++) {
        if (hv_vendor[i] != '\0') { all_zero = 0; break; }
    }

    if (all_zero)
        printf("  Hypervisor vendor string:         (empty / not exposed)\n");
    else
        printf("  Hypervisor vendor string:         \"%s\"\n", hv_vendor);

    return (unsigned int)eax;
}

static void dump_hypervisor_leaves(unsigned int max_hv_leaf)
{
    if (max_hv_leaf < 0x40000000U || max_hv_leaf > 0x40000100U) {
        printf("\n[Hypervisor leaves dump]\n");
        printf("  No sane standard hypervisor leaf range exposed\n");
        return;
    }

    printf("\n[Hypervisor leaves dump]\n");
    for (unsigned int leaf = 0x40000000U; leaf <= max_hv_leaf; leaf++) {
        int eax, ebx, ecx, edx;
        cpuid((int)leaf, 0, &eax, &ebx, &ecx, &edx);
        printf("  Leaf 0x%08X: EAX=%08X EBX=%08X ECX=%08X EDX=%08X\n",
               leaf, eax, ebx, ecx, edx);
    }
}

static void check_leaf_80000001(void)
{
    if (get_max_extended_leaf() < 0x80000001U) {
        printf("\n[Leaf 0x80000001] Not supported\n");
        return;
    }

    int eax, ebx, ecx, edx;
    cpuid(0x80000001, 0, &eax, &ebx, &ecx, &edx);

    printf("\n[Leaf 0x80000001] Extended processor features\n");
    printf("  ECX bit 2  (SVM / AMD-V):         %s\n", yesno((ecx >> 2) & 1));
    printf("  EDX bit 20 (NX):                  %s\n", yesno((edx >> 20) & 1));
    printf("  EDX bit 27 (RDTSCP):              %s\n", yesno((edx >> 27) & 1));
    printf("  EDX bit 29 (Long Mode / x64):     %s\n", yesno((edx >> 29) & 1));

    (void)eax;
    (void)ebx;
}

static void check_leaf_8000000a(void)
{
    unsigned int max_ext = get_max_extended_leaf();
    printf("\n[Leaf 0x80000000] Max extended leaf: 0x%08X\n", max_ext);

    if (max_ext < 0x8000000AU) {
        printf("  Leaf 0x8000000A not supported (AMD SVM info unavailable)\n");
        return;
    }

    int eax, ebx, ecx, edx;
    cpuid(0x8000000A, 0, &eax, &ebx, &ecx, &edx);

    printf("\n[Leaf 0x8000000A] AMD SVM details\n");
    printf("  SVM revision:                     %u\n", (unsigned int)(eax & 0xFF));
    printf("  Available ASIDs:                  %u\n", (unsigned int)ebx);
    printf("  Nested Paging (NPT):              %s\n", yesno(edx & 1));
    printf("  LBR virtualization:               %s\n", yesno((edx >> 1) & 1));
    printf("  VMCB Clean Bits:                  %s\n", yesno((edx >> 2) & 1));
    printf("  Flush-by-ASID:                    %s\n", yesno((edx >> 3) & 1));
    printf("  Decode assists:                   %s\n", yesno((edx >> 7) & 1));

    (void)ecx;
}

static void timing_cpuid_cost(void)
{
    const int rounds = 1000;
    uint64_t total = 0;
    int eax, ebx, ecx, edx;

    for (int i = 0; i < rounds; i++) {
        uint64_t start = rdtsc();
        cpuid(0x0, 0, &eax, &ebx, &ecx, &edx);
        uint64_t end = rdtsc();
        total += (end - start);
    }

    printf("\n[Timing sanity check]\n");
    printf("  Average CPUID(0) cost:            %llu cycles over %d rounds\n",
           (unsigned long long)(total / rounds), rounds);
    printf("  Note: timing is noisy and should be treated only as a weak diagnostic signal.\n");
}

/* --- main --------------------------------------------------------------- */

int main(void)
{
    printf("=== CPUID Virtualization Feature Check ===\n\n");

    check_leaf_0();
    check_cpu_brand();
    check_leaf_1();
    check_leaf_7();
    unsigned int max_hv_leaf = check_leaf_hv_vendor();
    dump_hypervisor_leaves(max_hv_leaf);
    check_leaf_80000001();
    check_leaf_8000000a();
    timing_cpuid_cost();

    printf("\n=== done ===\n");
    return 0;
}
