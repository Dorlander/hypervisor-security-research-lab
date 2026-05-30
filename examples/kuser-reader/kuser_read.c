/*
 * kuser_read.c
 *
 * Reads fields from KUSER_SHARED_DATA (0x7FFE0000) in user mode.
 * This page is mapped read-only into every Windows process — no privileges
 * needed, no syscall required. The kernel writes it; we just read it.
 *
 * Useful for:
 *   - Verifying which fields anti-analysis tools check
 *   - Confirming what a hypervisor would need to spoof to pass those checks
 *   - Understanding what "KUSER_SHARED_DATA spoofing" actually changes
 *
 * Compile: cl kuser_read.c
 * Run:     kuser_read.exe (works as a normal user)
 */

#include <windows.h>
#include <stdio.h>
#include <stdint.h>

/*
 * Partial KUSER_SHARED_DATA layout.
 *
 * Full structure documented at geoffchappell.com/studies/windows/km/ntoskrnl/
 * inc/api/ntexapi_x/kuser_shared_data/index.htm
 *
 * The structure is ABI-stable — offsets have not moved since early NT versions,
 * which is exactly why code (including anti-tamper) hard-codes reads from 0x7FFE0000.
 * Microsoft proposed randomizing this address in 2022 (MSRC blog) but it has not
 * shipped in a stable release yet.
 */
typedef struct _KSYSTEM_TIME {
    ULONG  LowPart;
    LONG   High1Time;
    LONG   High2Time;
} KSYSTEM_TIME;

#pragma pack(push, 1)
typedef struct _KUSER_SHARED_DATA_PARTIAL {
    /* 0x000 */ ULONG         TickCountLowDeprecated;
    /* 0x004 */ ULONG         TickCountMultiplier;
    /* 0x008 */ KSYSTEM_TIME  InterruptTime;
    /* 0x014 */ KSYSTEM_TIME  SystemTime;
    /* 0x020 */ KSYSTEM_TIME  TimeZoneBias;
    /* 0x02c */ USHORT        ImageNumberLow;
    /* 0x02e */ USHORT        ImageNumberHigh;
    /* 0x030 */ WCHAR         NtSystemRoot[260];
    /* 0x238 */ ULONG         MaxStackTraceDepth;
    /* 0x23c */ ULONG         CryptoExponent;
    /* 0x240 */ ULONG         TimeZoneId;
    /* 0x244 */ ULONG         LargePageMinimum;
    /* 0x248 */ ULONG         AitSamplingValue;
    /* 0x24c */ ULONG         AppCompatFlag;
    /* 0x250 */ ULONGLONG     RNGSeedVersion;
    /* 0x258 */ ULONG         GlobalValidationRunlevel;
    /* 0x25c */ LONG          TimeZoneBiasStamp;
    /* 0x260 */ ULONG         NtBuildNumber;
    /* 0x264 */ ULONG         NtProductType;     /* 1=WinNT, 2=LanManNT, 3=Server */
    /* 0x268 */ BOOLEAN       ProductTypeIsValid;
    /* 0x269 */ BYTE          Reserved0[3];
    /* 0x26c */ ULONG         NativeProcessorArchitecture;
    /* 0x270 */ ULONG         NtMajorVersion;
    /* 0x274 */ ULONG         NtMinorVersion;

    /* ... many fields omitted for brevity ... */

    /*
     * 0x308 — KdDebuggerEnabled
     *
     * This byte is the primary kernel-debugger-detection field readable from user mode.
     * Bit 0: KdDebuggerNotPresent (inverted — 0 means debugger IS present)
     * Bit 1: KdDebuggerEnabled
     *
     * Anti-tamper typically checks: if ((*(BYTE*)0x7FFE0308) & 1) == 0 -> debugger detected
     *
     * nt!KdDebuggerNotPresent (the kernel global) is mirrored here.
     * A ring-0 driver or hypervisor can patch nt!KdDebuggerNotPresent to always
     * return 1 (no debugger), but the KUSER field also needs updating, which is why
     * KUSER-spoofing hypervisors run a background thread (CounterUpdater) to keep it in sync.
     */
} KUSER_SHARED_DATA_PARTIAL;
#pragma pack(pop)

#define KUSER_SHARED_DATA_VA  ((KUSER_SHARED_DATA_PARTIAL *)0x7FFE0000ULL)

static void print_product_type(ULONG pt)
{
    switch (pt) {
        case 1: printf("WinNT (Workstation)"); break;
        case 2: printf("LanManNT"); break;
        case 3: printf("Server"); break;
        default: printf("Unknown (%lu)", pt); break;
    }
}

int main(void)
{
    const KUSER_SHARED_DATA_PARTIAL *ksd = KUSER_SHARED_DATA_VA;

    printf("=== KUSER_SHARED_DATA (0x7FFE0000) ===\n\n");

    printf("NtBuildNumber:        %lu\n", ksd->NtBuildNumber);
    printf("NtMajorVersion:       %lu\n", ksd->NtMajorVersion);
    printf("NtMinorVersion:       %lu\n", ksd->NtMinorVersion);
    printf("NtProductType:        "); print_product_type(ksd->NtProductType); printf("\n");
    printf("TickCountMultiplier:  0x%08lX\n", ksd->TickCountMultiplier);
    printf("NtSystemRoot:         %ls\n", ksd->NtSystemRoot);

    /*
     * Read the debugger detection byte at offset 0x308.
     *
     * We can't include the full structure definition above because the offsets
     * between 0x278 and 0x308 contain many fields that vary across Windows versions.
     * Reading via raw pointer arithmetic is more reliable than a struct definition
     * that might be wrong for a specific build.
     */
    BYTE kd_byte = *(BYTE *)((ULONG_PTR)ksd + 0x308);
    printf("\n--- Kernel debugger detection (offset 0x308) ---\n");
    printf("Raw byte at 0x7FFE0308:   0x%02X\n", kd_byte);
    printf("KdDebuggerEnabled:        %s\n", (kd_byte & 0x02) ? "yes" : "no");
    printf("KdDebuggerNotPresent:     %s\n", (kd_byte & 0x01) ? "yes (no debugger)" : "no (debugger detected)");

    /*
     * What anti-tamper does with this:
     *   If bit 0 is clear (KdDebuggerNotPresent == 0), a debugger is attached.
     *   Anti-tamper treats this as a hostile environment and refuses to run,
     *   crashes, or behaves differently.
     *
     * What a spoofing hypervisor does:
     *   - Patches nt!KdDebuggerNotPresent in kernel memory to always be 1
     *   - Runs a background thread that keeps offset 0x308 in KUSER_SHARED_DATA
     *     updated to match (since it's a separate copy, changes to the kernel
     *     global don't automatically reflect here)
     *   - The background thread (CounterUpdater in SimpleSvm modifications and
     *     hyperkd.sys) runs continuously while the target process is alive
     */

    printf("\n--- InterruptTime (used for timing checks) ---\n");
    /*
     * RDTSC timing checks look for suspiciously large deltas between two
     * consecutive reads. If time appears to jump (because a hypervisor or
     * debugger paused execution), the check fails.
     *
     * InterruptTime is a 64-bit counter updated by the kernel ~100 times/sec
     * (or faster with high-resolution timers). Anti-tamper may read this as a
     * coarser timing source to cross-check RDTSC results.
     */
    ULONGLONG interrupt_time =
        ((ULONGLONG)(ULONG)ksd->InterruptTime.High1Time << 32) | ksd->InterruptTime.LowPart;
    printf("InterruptTime (100ns units): %llu\n", interrupt_time);
    printf("Approx seconds since boot:   %llu\n", interrupt_time / 10000000ULL);

    return 0;
}
