/*
 * kuser_read.c
 *
 * Read selected KUSER_SHARED_DATA fields from user mode.
 * The page at 0x7FFE0000 is mapped read-only into every Windows process.
 * This sample does not write memory, call undocumented syscalls, or require
 * administrative privileges.
 *
 * Compile (MSVC):  cl /W4 kuser_read.c
 * Run:             kuser_read.exe
 */

#include <windows.h>
#include <stdio.h>
#include <stdint.h>

/*
 * Partial KUSER_SHARED_DATA layout.
 *
 * This intentionally covers only stable, commonly documented offsets used for
 * passive environment diagnostics. Fields after 0x278 vary more between builds,
 * so this sample reads selected later offsets with byte arithmetic instead of
 * pretending to define the entire structure.
 */
typedef struct _KSYSTEM_TIME {
    ULONG LowPart;
    LONG  High1Time;
    LONG  High2Time;
} KSYSTEM_TIME;

#pragma pack(push, 1)
typedef struct _KUSER_SHARED_DATA_PARTIAL {
    /* 0x000 */ ULONG        TickCountLowDeprecated;
    /* 0x004 */ ULONG        TickCountMultiplier;
    /* 0x008 */ KSYSTEM_TIME InterruptTime;
    /* 0x014 */ KSYSTEM_TIME SystemTime;
    /* 0x020 */ KSYSTEM_TIME TimeZoneBias;
    /* 0x02c */ USHORT       ImageNumberLow;
    /* 0x02e */ USHORT       ImageNumberHigh;
    /* 0x030 */ WCHAR        NtSystemRoot[260];
    /* 0x238 */ ULONG        MaxStackTraceDepth;
    /* 0x23c */ ULONG        CryptoExponent;
    /* 0x240 */ ULONG        TimeZoneId;
    /* 0x244 */ ULONG        LargePageMinimum;
    /* 0x248 */ ULONG        AitSamplingValue;
    /* 0x24c */ ULONG        AppCompatFlag;
    /* 0x250 */ ULONGLONG    RNGSeedVersion;
    /* 0x258 */ ULONG        GlobalValidationRunlevel;
    /* 0x25c */ LONG         TimeZoneBiasStamp;
    /* 0x260 */ ULONG        NtBuildNumber;
    /* 0x264 */ ULONG        NtProductType;
    /* 0x268 */ BOOLEAN      ProductTypeIsValid;
    /* 0x269 */ BYTE         Reserved0[3];
    /* 0x26c */ ULONG        NativeProcessorArchitecture;
    /* 0x270 */ ULONG        NtMajorVersion;
    /* 0x274 */ ULONG        NtMinorVersion;
} KUSER_SHARED_DATA_PARTIAL;
#pragma pack(pop)

#define KUSER_SHARED_DATA_VA ((const KUSER_SHARED_DATA_PARTIAL *)0x7FFE0000ULL)

static ULONGLONG ksystem_time_to_u64(KSYSTEM_TIME t)
{
    /* Use High1Time as the stable high part. For a production reader, read until
     * High1Time == High2Time to avoid torn reads. This sample is diagnostic only. */
    return ((ULONGLONG)(ULONG)t.High1Time << 32) | t.LowPart;
}

static void print_product_type(ULONG pt)
{
    switch (pt) {
    case 1:  printf("WinNT (Workstation)"); break;
    case 2:  printf("LanManNT / Domain Controller"); break;
    case 3:  printf("Server"); break;
    default: printf("Unknown (%lu)", pt); break;
    }
}

static void print_architecture(ULONG arch)
{
    switch (arch) {
    case PROCESSOR_ARCHITECTURE_INTEL: printf("x86"); break;
    case PROCESSOR_ARCHITECTURE_AMD64: printf("x64"); break;
    case PROCESSOR_ARCHITECTURE_ARM:   printf("ARM"); break;
    case PROCESSOR_ARCHITECTURE_ARM64: printf("ARM64"); break;
    default: printf("Unknown (%lu)", arch); break;
    }
}

static void print_debugger_byte(BYTE kd_byte)
{
    /* Offset 0x308 contains the KdDebuggerEnabled byte mirrored by Windows.
     * Bit 0 is named KdDebuggerNotPresent, so its meaning is inverted:
     *   bit0 = 1 -> no kernel debugger present
     *   bit0 = 0 -> kernel debugger present
     * This is one signal among many; treat it as environment telemetry, not as
     * an authoritative security boundary. */
    printf("Raw byte at 0x7FFE0308:   0x%02X\n", kd_byte);
    printf("KdDebuggerEnabled:        %s\n", (kd_byte & 0x02) ? "yes" : "no");
    printf("KdDebuggerNotPresent:     %s\n", (kd_byte & 0x01) ? "yes" : "no");
}

int main(void)
{
    const KUSER_SHARED_DATA_PARTIAL *ksd = KUSER_SHARED_DATA_VA;

    printf("=== KUSER_SHARED_DATA passive reader ===\n\n");

    printf("--- Version / product ---\n");
    printf("NtBuildNumber:              %lu\n", ksd->NtBuildNumber);
    printf("NtMajorVersion:             %lu\n", ksd->NtMajorVersion);
    printf("NtMinorVersion:             %lu\n", ksd->NtMinorVersion);
    printf("NtProductType:              "); print_product_type(ksd->NtProductType); printf("\n");
    printf("ProductTypeIsValid:         %s\n", ksd->ProductTypeIsValid ? "yes" : "no");
    printf("NativeProcessorArchitecture:"); print_architecture(ksd->NativeProcessorArchitecture); printf("\n");
    printf("ImageNumberLow/High:        0x%04X / 0x%04X\n",
           ksd->ImageNumberLow, ksd->ImageNumberHigh);
    printf("NtSystemRoot:               %ls\n", ksd->NtSystemRoot);

    printf("\n--- Timing fields ---\n");
    ULONGLONG interrupt_time = ksystem_time_to_u64(ksd->InterruptTime);
    ULONGLONG system_time    = ksystem_time_to_u64(ksd->SystemTime);
    ULONGLONG timezone_bias  = ksystem_time_to_u64(ksd->TimeZoneBias);
    printf("InterruptTime (100ns):      %llu\n", interrupt_time);
    printf("Approx uptime seconds:      %llu\n", interrupt_time / 10000000ULL);
    printf("SystemTime (100ns):         %llu\n", system_time);
    printf("TimeZoneBias (100ns):       %llu\n", timezone_bias);
    printf("TickCountMultiplier:        0x%08lX\n", ksd->TickCountMultiplier);
    printf("GetTickCount64 seconds:     %llu\n", GetTickCount64() / 1000ULL);

    printf("\n--- Misc telemetry ---\n");
    printf("LargePageMinimum:           0x%08lX\n", ksd->LargePageMinimum);
    printf("TimeZoneId:                 %lu\n", ksd->TimeZoneId);
    printf("RNGSeedVersion:             %llu\n", ksd->RNGSeedVersion);
    printf("GlobalValidationRunlevel:   %lu\n", ksd->GlobalValidationRunlevel);

    printf("\n--- Kernel debugger byte (offset 0x308) ---\n");
    BYTE kd_byte = *(const BYTE *)((ULONG_PTR)ksd + 0x308);
    print_debugger_byte(kd_byte);

    printf("\n=== done ===\n");
    return 0;
}
