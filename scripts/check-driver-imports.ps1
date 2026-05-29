<#
.SYNOPSIS
    Check whether every API a kernel driver imports is exported by the host's
    ntoskrnl.exe / netio.sys. Pinpoints which import causes
    STATUS_ENTRYPOINT_NOT_FOUND (sc start error 127).

.DESCRIPTION
    Pure PowerShell (no dumpbin, no WDK). Reads the PE import directory of
    the .sys, reads the export tables of the matching system modules, and
    diffs them. Any name printed under "[MISSING]" is the API the running
    kernel cannot resolve.

.PARAMETER Sys
    Path to the .sys file to inspect. Defaults to the path InstDrv uses.

.EXAMPLE
    # Copy this script to the target VM, then run as administrator:
    powershell -ExecutionPolicy Bypass -File .\check-driver-imports.ps1
#>
[CmdletBinding()]
param(
    [string]$Sys = 'C:\Users\Song\Desktop\InstDrv\NetDrv.sys'
)

# --- PE helpers ----------------------------------------------------------

function Read-PEImports {
    param([Parameter(Mandatory)][string]$Path)

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 0x40) { throw "File too small: $Path" }

    # DOS header -> e_lfanew at 0x3C
    $peOff = [BitConverter]::ToInt32($bytes, 0x3C)
    if ($bytes[$peOff] -ne 0x50 -or $bytes[$peOff+1] -ne 0x45) {
        throw "Not a PE file: $Path"
    }

    $fileHeaderOff = $peOff + 4
    $machine       = [BitConverter]::ToUInt16($bytes, $fileHeaderOff)
    $optHdrSize    = [BitConverter]::ToUInt16($bytes, $fileHeaderOff + 16)
    $optHdrOff     = $fileHeaderOff + 20

    # PE32+ magic == 0x20B (x64)
    $magic = [BitConverter]::ToUInt16($bytes, $optHdrOff)
    if ($magic -ne 0x20B) { throw "Only PE32+ (x64) supported in this script" }

    $imageBase    = [BitConverter]::ToUInt64($bytes, $optHdrOff + 24)
    $numDataDirs  = [BitConverter]::ToUInt32($bytes, $optHdrOff + 108)
    $dataDirsOff  = $optHdrOff + 112
    # Import dir is data directory index 1
    $importRva    = [BitConverter]::ToUInt32($bytes, $dataDirsOff + 1*8)
    $importSize   = [BitConverter]::ToUInt32($bytes, $dataDirsOff + 1*8 + 4)
    if ($importRva -eq 0) { return @{} }

    # Build section table -> RVA -> file offset
    $sectionTableOff = $optHdrOff + $optHdrSize
    $numSections     = [BitConverter]::ToUInt16($bytes, $fileHeaderOff + 2)
    $sections = for ($i = 0; $i -lt $numSections; ++$i) {
        $s = $sectionTableOff + $i * 40
        [pscustomobject]@{
            VirtualSize    = [BitConverter]::ToUInt32($bytes, $s + 8)
            VirtualAddress = [BitConverter]::ToUInt32($bytes, $s + 12)
            RawSize        = [BitConverter]::ToUInt32($bytes, $s + 16)
            RawOffset      = [BitConverter]::ToUInt32($bytes, $s + 20)
        }
    }

    function rvaToFile([uint32]$rva) {
        foreach ($s in $sections) {
            if ($rva -ge $s.VirtualAddress -and $rva -lt ($s.VirtualAddress + [Math]::Max($s.VirtualSize,$s.RawSize))) {
                return $s.RawOffset + ($rva - $s.VirtualAddress)
            }
        }
        return -1
    }

    function readAsciiZ([uint32]$off) {
        $end = $off
        while ($end -lt $bytes.Length -and $bytes[$end] -ne 0) { $end++ }
        return [System.Text.Encoding]::ASCII.GetString($bytes, $off, $end - $off)
    }

    # Walk IMPORT_DESCRIPTOR (5 ULONG = 20 bytes each, terminated by all-zero)
    $results = [ordered]@{}
    $impOff = rvaToFile $importRva
    while ($true) {
        $origThunkRva = [BitConverter]::ToUInt32($bytes, $impOff)
        $nameRva      = [BitConverter]::ToUInt32($bytes, $impOff + 12)
        $firstThunkRva= [BitConverter]::ToUInt32($bytes, $impOff + 16)
        if ($origThunkRva -eq 0 -and $nameRva -eq 0 -and $firstThunkRva -eq 0) { break }

        $dllName = readAsciiZ (rvaToFile $nameRva)
        $thunkRva = if ($origThunkRva -ne 0) { $origThunkRva } else { $firstThunkRva }
        $thunkOff = rvaToFile $thunkRva
        $names = New-Object System.Collections.Generic.List[string]
        while ($true) {
            $entry = [BitConverter]::ToUInt64($bytes, $thunkOff)
            if ($entry -eq 0) { break }
            if (($entry -band 0x8000000000000000) -eq 0) {
                # Hint/name table entry: skip 2-byte hint, read ASCIIZ
                $hintNameOff = rvaToFile ([uint32]($entry -band 0xFFFFFFFF))
                $names.Add( (readAsciiZ ($hintNameOff + 2)) )
            } else {
                $names.Add( ('#' + ($entry -band 0xFFFF)) )  # ordinal import (rare)
            }
            $thunkOff += 8
        }
        $results[$dllName.ToLower()] = $names
        $impOff += 20
    }
    return $results
}

function Read-PEExports {
    param([Parameter(Mandatory)][string]$Path)

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $peOff = [BitConverter]::ToInt32($bytes, 0x3C)
    $fileHeaderOff = $peOff + 4
    $optHdrSize    = [BitConverter]::ToUInt16($bytes, $fileHeaderOff + 16)
    $optHdrOff     = $fileHeaderOff + 20
    $magic         = [BitConverter]::ToUInt16($bytes, $optHdrOff)
    $dataDirsOff   = if ($magic -eq 0x20B) { $optHdrOff + 112 } else { $optHdrOff + 96 }
    $exportRva     = [BitConverter]::ToUInt32($bytes, $dataDirsOff + 0*8)
    if ($exportRva -eq 0) { return @() }

    $sectionTableOff = $optHdrOff + $optHdrSize
    $numSections     = [BitConverter]::ToUInt16($bytes, $fileHeaderOff + 2)
    $sections = for ($i = 0; $i -lt $numSections; ++$i) {
        $s = $sectionTableOff + $i * 40
        [pscustomobject]@{
            VirtualSize    = [BitConverter]::ToUInt32($bytes, $s + 8)
            VirtualAddress = [BitConverter]::ToUInt32($bytes, $s + 12)
            RawSize        = [BitConverter]::ToUInt32($bytes, $s + 16)
            RawOffset      = [BitConverter]::ToUInt32($bytes, $s + 20)
        }
    }
    function rvaToFile2([uint32]$rva) {
        foreach ($s in $sections) {
            if ($rva -ge $s.VirtualAddress -and $rva -lt ($s.VirtualAddress + [Math]::Max($s.VirtualSize,$s.RawSize))) {
                return $s.RawOffset + ($rva - $s.VirtualAddress)
            }
        }
        return -1
    }
    function readAsciiZ2([uint32]$off) {
        $end = $off
        while ($end -lt $bytes.Length -and $bytes[$end] -ne 0) { $end++ }
        return [System.Text.Encoding]::ASCII.GetString($bytes, $off, $end - $off)
    }

    $expOff = rvaToFile2 $exportRva
    $numNames     = [BitConverter]::ToUInt32($bytes, $expOff + 24)
    $namesRva     = [BitConverter]::ToUInt32($bytes, $expOff + 32)
    $namesArrOff  = rvaToFile2 $namesRva
    $names = New-Object System.Collections.Generic.HashSet[string]
    for ($i = 0; $i -lt $numNames; ++$i) {
        $rvaName = [BitConverter]::ToUInt32($bytes, $namesArrOff + $i*4)
        [void]$names.Add( (readAsciiZ2 (rvaToFile2 $rvaName)) )
    }
    return $names
}

# --- Main ----------------------------------------------------------------

if (-not (Test-Path $Sys)) { Write-Error "Driver not found: $Sys"; exit 1 }

Write-Host ""
Write-Host "================================================================"
Write-Host " Driver: $Sys"
Write-Host "         Size: $((Get-Item $Sys).Length)   Time: $((Get-Item $Sys).LastWriteTime)"
Write-Host "================================================================"

$imports = Read-PEImports $Sys

# Map dependency DLL -> file on the running system
$sysDir = [Environment]::SystemDirectory   # e.g. C:\Windows\System32
$dllPaths = @{
    'ntoskrnl.exe' = Join-Path $sysDir 'ntoskrnl.exe'
    'netio.sys'    = Join-Path $sysDir 'drivers\netio.sys'
    'fltmgr.sys'   = Join-Path $sysDir 'drivers\fltmgr.sys'
    'hal.dll'      = Join-Path $sysDir 'hal.dll'
    'ksecdd.sys'   = Join-Path $sysDir 'drivers\ksecdd.sys'
    'wdfldr.sys'   = Join-Path $sysDir 'drivers\wdfldr.sys'
}

$anyMissing = $false
foreach ($dll in $imports.Keys) {
    $needed = $imports[$dll]
    $sysFile = $dllPaths[$dll]
    if (-not $sysFile -or -not (Test-Path $sysFile)) {
        Write-Host ""
        Write-Host "[$dll] (cannot find system file -> skipped)"
        continue
    }
    $have = Read-PEExports $sysFile
    $missing = $needed | Where-Object { -not $have.Contains($_) }

    Write-Host ""
    Write-Host "[$dll]  needed=$($needed.Count)  exported by host=$($have.Count)"
    if ($missing) {
        $anyMissing = $true
        Write-Host "  [MISSING on this OS]:" -ForegroundColor Red
        $missing | ForEach-Object { Write-Host "    - $_" -ForegroundColor Red }
    } else {
        Write-Host "  All imports resolved." -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "================================================================"
if ($anyMissing) {
    Write-Host " RESULT: at least one import is NOT resolved on this kernel." -ForegroundColor Red
    Write-Host "         That is the cause of 'sc start' error 127."          -ForegroundColor Red
    exit 2
} else {
    Write-Host " RESULT: every import is resolvable on this kernel."          -ForegroundColor Green
    Write-Host "         Error 127 is NOT due to a missing API."              -ForegroundColor Yellow
    Write-Host "         Likely causes left: testsigning off, wrong .sys"     -ForegroundColor Yellow
    Write-Host "         on disk, or wrong service binPath."                  -ForegroundColor Yellow
}
Write-Host "================================================================"
