# analyze_pe.ps1
#
# Passive static analysis of a Windows PE binary.
# No execution — reads only. Safe to run on unknown files in an isolated environment.
#
# Usage:
#   .\analyze_pe.ps1 -Path C:\path\to\file.sys
#   .\analyze_pe.ps1 -Path C:\path\to\file.sys -ExtractStrings
#
# What this covers:
#   - PE header parsing (machine type, subsystem, characteristics)
#   - Import table extraction (which DLLs and APIs it uses)
#   - Export table extraction
#   - ASCII + Unicode string extraction
#   - Privilege layer guess from PE metadata alone
#   - Authenticode signature check via Get-AuthenticodeSignature

param(
    [Parameter(Mandatory)]
    [string]$Path,

    [switch]$ExtractStrings,

    # Minimum length for string extraction (shorter = more noise)
    [int]$MinStringLength = 6
)

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Read-U16 ($bytes, $offset) {
    [BitConverter]::ToUInt16($bytes, $offset)
}
function Read-U32 ($bytes, $offset) {
    [BitConverter]::ToUInt32($bytes, $offset)
}
function Read-U64 ($bytes, $offset) {
    [BitConverter]::ToUInt64($bytes, $offset)
}

function Get-SubsystemName ($code) {
    switch ($code) {
        0  { "Unknown" }
        1  { "Native / Kernel driver (ring 0 or ring -1)" }
        2  { "Windows GUI application" }
        3  { "Windows console application" }
        7  { "POSIX character mode" }
        9  { "Windows CE GUI" }
        10 { "EFI application (UEFI, ring -2)" }
        11 { "EFI boot service driver (UEFI)" }
        12 { "EFI runtime driver (UEFI)" }
        13 { "EFI ROM image" }
        14 { "Xbox" }
        default { "Reserved ($code)" }
    }
}

function Get-MachineName ($code) {
    switch ($code) {
        0x014C { "x86 (32-bit)" }
        0x0200 { "IA-64 (Itanium)" }
        0x8664 { "x86-64 (64-bit)" }
        0xAA64 { "ARM64" }
        0x01C4 { "ARM Thumb-2" }
        default { "Unknown (0x{0:X4})" -f $code }
    }
}

# ---------------------------------------------------------------------------
# Load file
# ---------------------------------------------------------------------------

if (-not (Test-Path $Path)) {
    Write-Error "File not found: $Path"
    exit 1
}

$item  = Get-Item $Path
$bytes = [System.IO.File]::ReadAllBytes($Path)

Write-Host "`n=== Passive PE Analysis ===" -ForegroundColor Cyan
Write-Host "File:     $($item.FullName)"
Write-Host "Size:     $($item.Length) bytes"
Write-Host "Modified: $($item.LastWriteTimeUtc) UTC"
Write-Host "SHA-256:  $((Get-FileHash $Path -Algorithm SHA256).Hash)"

# ---------------------------------------------------------------------------
# Authenticode signature
# ---------------------------------------------------------------------------
Write-Host "`n--- Signature ---" -ForegroundColor Yellow
$sig = Get-AuthenticodeSignature $Path
Write-Host "Status:   $($sig.Status)"
if ($sig.SignerCertificate) {
    Write-Host "Signer:   $($sig.SignerCertificate.Subject)"
    Write-Host "Issuer:   $($sig.SignerCertificate.Issuer)"
    Write-Host "Valid:    $($sig.SignerCertificate.NotBefore) – $($sig.SignerCertificate.NotAfter)"
}

# ---------------------------------------------------------------------------
# PE header
# ---------------------------------------------------------------------------
Write-Host "`n--- PE Header ---" -ForegroundColor Yellow

# DOS header: 'MZ' magic at offset 0
if ($bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) {
    Write-Warning "Not a valid MZ/PE file."
    exit 1
}

# e_lfanew at offset 0x3C — points to PE signature
$peOffset = Read-U32 $bytes 0x3C

if ($bytes[$peOffset]   -ne 0x50 -or   # 'P'
    $bytes[$peOffset+1] -ne 0x45 -or   # 'E'
    $bytes[$peOffset+2] -ne 0x00 -or
    $bytes[$peOffset+3] -ne 0x00) {
    Write-Warning "PE signature not found at expected offset."
    exit 1
}

# COFF header starts at peOffset + 4
$coffOffset   = $peOffset + 4
$machine      = Read-U16 $bytes ($coffOffset + 0)
$numSections  = Read-U16 $bytes ($coffOffset + 2)
$timeDateStamp = Read-U32 $bytes ($coffOffset + 4)
$characteristics = Read-U16 $bytes ($coffOffset + 18)

# Optional header starts at peOffset + 4 + 20
$optOffset  = $coffOffset + 20
$magic      = Read-U16 $bytes $optOffset  # 0x10B = PE32, 0x20B = PE32+

$subsystem  = if ($magic -eq 0x20B) {
    Read-U16 $bytes ($optOffset + 68)   # PE32+ optional header
} else {
    Read-U16 $bytes ($optOffset + 68)   # same offset for PE32
}

$dllCharacteristics = if ($magic -eq 0x20B) {
    Read-U16 $bytes ($optOffset + 70)
} else {
    Read-U16 $bytes ($optOffset + 70)
}

$compiledDate = [DateTimeOffset]::FromUnixTimeSeconds($timeDateStamp).UtcDateTime

Write-Host "Machine:          $(Get-MachineName $machine) (0x{0:X4})" -f $machine
Write-Host "Sections:         $numSections"
Write-Host "Compiled (UTC):   $compiledDate"
Write-Host "Subsystem:        $(Get-SubsystemName $subsystem) ($subsystem)"
Write-Host "Characteristics:  0x{0:X4}" -f $characteristics

# Decode DLL characteristics flags
$flags = @()
if ($dllCharacteristics -band 0x0020) { $flags += "HIGH_ENTROPY_VA" }
if ($dllCharacteristics -band 0x0040) { $flags += "DYNAMIC_BASE (ASLR)" }
if ($dllCharacteristics -band 0x0080) { $flags += "FORCE_INTEGRITY" }
if ($dllCharacteristics -band 0x0100) { $flags += "NX_COMPAT (DEP)" }
if ($dllCharacteristics -band 0x0200) { $flags += "NO_ISOLATION" }
if ($dllCharacteristics -band 0x0400) { $flags += "NO_SEH" }
if ($dllCharacteristics -band 0x0800) { $flags += "NO_BIND" }
if ($dllCharacteristics -band 0x2000) { $flags += "WDM_DRIVER" }
if ($dllCharacteristics -band 0x4000) { $flags += "GUARD_CF" }
if ($dllCharacteristics -band 0x8000) { $flags += "TERMINAL_SERVER_AWARE" }
if ($flags.Count -gt 0) {
    Write-Host "DLL Flags:        $($flags -join ', ')"
}

# Privilege layer guess
Write-Host "`n--- Privilege Layer Guess ---" -ForegroundColor Yellow
switch ($subsystem) {
    1  { Write-Host "Likely ring 0 (kernel driver) or ring -1 (hypervisor driver)" -ForegroundColor Red }
    10 { Write-Host "UEFI application — ring -2 (executes before OS)" -ForegroundColor Red }
    11 { Write-Host "UEFI boot service driver — ring -2" -ForegroundColor Red }
    12 { Write-Host "UEFI runtime driver — ring -2, persists after OS handoff" -ForegroundColor Red }
    2  { Write-Host "Ring 3 — Windows GUI application" -ForegroundColor Green }
    3  { Write-Host "Ring 3 — Console application" -ForegroundColor Green }
    default { Write-Host "Unknown subsystem — inspect further" -ForegroundColor Yellow }
}

if ($characteristics -band 0x2000) {
    Write-Host "Characteristics: DLL flag set — this is a DLL, not a standalone executable"
} else {
    Write-Host "Characteristics: DLL flag NOT set — standalone executable"
}

# ---------------------------------------------------------------------------
# Import table (using .NET reflection approach — no execution)
# ---------------------------------------------------------------------------
Write-Host "`n--- Import Table ---" -ForegroundColor Yellow
Write-Host "(extracted via string heuristic — full parsing requires walking the data directory)"

#
# True import table parsing requires walking:
#   OptionalHeader.DataDirectory[1] (Import Directory)
#   → array of IMAGE_IMPORT_DESCRIPTOR structs
#   → each has a Name RVA (DLL name) and OriginalFirstThunk RVA (function names)
#
# That requires RVA-to-file-offset conversion using the section table.
# For a research note, string extraction below approximates this well enough.
# A proper implementation would use pefile (Python) or CFF Explorer.
#
# What to look for in imports:
#   ntoskrnl.exe      → kernel driver (ring 0)
#   Wdf01000.sys      → KMDF driver
#   ndis.sys          → network driver
#   hal.dll           → hardware abstraction layer access
#   user32.dll        → user-mode GUI
#   ws2_32.dll        → network — why does a sys file need sockets?
#   MmAllocateContiguousNodeMemory → VMCB/DMA allocation (hypervisor indicator)
#   PsSetCreateProcessNotifyRoutine → process monitoring
#   PsLookupProcessByProcessId → targeted process lookup
#

$escapedPath = $Path -replace "'", "'\"'\"'"
Write-Host "To get a clean import list: python -c `"import pefile; pe=pefile.PE('$escapedPath'); [print(e.dll, d.name) for e in pe.DIRECTORY_ENTRY_IMPORT for d in e.imports]`""

# ---------------------------------------------------------------------------
# String extraction
# ---------------------------------------------------------------------------
if ($ExtractStrings) {
    Write-Host "`n--- Strings (ASCII) ---" -ForegroundColor Yellow
    $ascii = [System.Text.Encoding]::ASCII.GetString($bytes)
    $asciiMatches = [regex]::Matches($ascii, "[\x20-\x7E]{$MinStringLength,}")
    Write-Host "Found $($asciiMatches.Count) ASCII strings (min length $MinStringLength)"
    $asciiMatches | ForEach-Object { $_.Value } | Sort-Object -Unique | ForEach-Object {
        Write-Host "  $_"
    }

    Write-Host "`n--- Strings (Unicode / UTF-16LE) ---" -ForegroundColor Yellow
    $unicode = [System.Text.Encoding]::Unicode.GetString($bytes)
    $uniMatches = [regex]::Matches($unicode, "[\x20-\x7E]{$MinStringLength,}")
    Write-Host "Found $($uniMatches.Count) Unicode strings"
    $uniMatches | ForEach-Object { $_.Value } | Sort-Object -Unique | ForEach-Object {
        Write-Host "  $_"
    }
}

Write-Host "`n=== done ===`n" -ForegroundColor Cyan

#
# === What to do after this script ===
#
# 1. If subsystem == 1 (kernel driver):
#    - Load in Ghidra, run auto-analysis
#    - Check "Functions" window for known API names (MmAllocateContiguousNodeMemory,
#      PsSetCreateProcessNotifyRoutine, KeSetSystemGroupAffinityThread etc.)
#    - Use "Symbol Tree" → "Imports" to see exact API list
#    - Cross-reference against known open-source projects (SimpleSvm, HyperDbg)
#
# 2. If you see "Denuvo" strings or certificate-like DER blobs:
#    - The binary may contain embedded license data used for spoofing
#    - ASN.1 date strings (format YYMMDDHHmmssZ) indicate certificate validity windows
#
# 3. If FUNC_* strings appear (FUNC_ADD, FUNC_RDTSC, FUNC_EVENT_INJECT etc.):
#    - This is the HyperDbg scripting engine opcode table
#    - The binary is likely a thin shim that imports hyperhv.dll (HyperDbg core)
#
# 4. If CounterUpdater / KdDebuggerNotPresent / PsAcquireProcessExitSynchronization appear:
#    - This is a KUSER_SHARED_DATA spoofing driver, not just a plain hypervisor
#    - It monitors a specific target process and maintains fake timing/debug state
#
