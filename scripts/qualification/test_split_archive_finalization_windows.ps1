<#
.SYNOPSIS
Test native archive-bit finalization on one disposable FAT32 Split directory.

.DESCRIPTION
The selected directory must start with Archive clear and Hidden set. The script
sets Archive twice through SetFileAttributesW, reads it through
GetFileAttributesW, and checks that the directory's other flags and two sibling
sentinels remain unchanged.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$QualificationRoot
)

$ErrorActionPreference = 'Stop'

if (-not ('NscbSplitAttributeApi' -as [type])) {
    Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;

public static class NscbSplitAttributeApi
{
    [DllImport("kernel32.dll", EntryPoint = "SetFileAttributesW", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    public static extern bool SetFileAttributes(string path, uint attributes);

    [DllImport("kernel32.dll", EntryPoint = "GetFileAttributesW", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    public static extern uint GetFileAttributes(string path);

    [DllImport("kernel32.dll", EntryPoint = "GetVolumePathNameW", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    public static extern bool GetVolumePathName(string path, System.Text.StringBuilder volumePath, uint bufferLength);

    [DllImport("kernel32.dll", EntryPoint = "GetVolumeInformationW", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    public static extern bool GetVolumeInformation(
        string rootPath,
        System.Text.StringBuilder volumeName,
        uint volumeNameLength,
        out uint volumeSerialNumber,
        out uint maximumComponentLength,
        out uint fileSystemFlags,
        System.Text.StringBuilder fileSystemName,
        uint fileSystemNameLength);
}
'@
}

function Get-AttributeMask([string]$Path) {
    [uint32]$mask = [NscbSplitAttributeApi]::GetFileAttributes($Path)
    if ($mask -eq [uint32]::MaxValue) {
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "GetFileAttributesW failed for $Path; Win32 error $errorCode"
    }
    return $mask
}

function Set-AttributeMask([string]$Path, [uint32]$Mask) {
    [uint32]$settableMask = $Mask -band [uint32]0xFFFFFFEF
    if (-not [NscbSplitAttributeApi]::SetFileAttributes($Path, $settableMask)) {
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "SetFileAttributesW failed for $Path; Win32 error $errorCode"
    }
}

$root = [IO.Path]::GetFullPath($QualificationRoot)
if (-not (Test-Path -LiteralPath $root -PathType Container)) {
    throw "Qualification root does not exist: $root"
}

$volumePath = [Text.StringBuilder]::new(32768)
if (-not [NscbSplitAttributeApi]::GetVolumePathName($root, $volumePath, [uint32]$volumePath.Capacity)) {
    $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    throw "GetVolumePathNameW failed for $root; Win32 error $errorCode"
}
$volumeName = [Text.StringBuilder]::new(261)
$fileSystemName = [Text.StringBuilder]::new(261)
[uint32]$volumeSerialNumber = 0
[uint32]$maximumComponentLength = 0
[uint32]$fileSystemFlags = 0
if (-not [NscbSplitAttributeApi]::GetVolumeInformation(
        $volumePath.ToString(),
        $volumeName,
        [uint32]$volumeName.Capacity,
        [ref]$volumeSerialNumber,
        [ref]$maximumComponentLength,
        [ref]$fileSystemFlags,
        $fileSystemName,
        [uint32]$fileSystemName.Capacity)) {
    $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    throw "GetVolumeInformationW failed for $($volumePath.ToString()); Win32 error $errorCode"
}
if ($fileSystemName.ToString() -ne 'FAT32') {
    throw "Expected FAT32 at $($volumePath.ToString()); found $($fileSystemName.ToString())"
}

$target = Join-Path $root 'qualification-source.nsp'
$sentinelFile = Join-Path $root 'preservation-sentinel.bin'
$sentinelDirectory = Join-Path $root 'preservation-sentinel-directory'
if (-not (Test-Path -LiteralPath $target -PathType Container)) {
    throw "Canonical Split directory does not exist: $target"
}
if (-not (Test-Path -LiteralPath $sentinelFile -PathType Leaf)) {
    throw "Sentinel file does not exist: $sentinelFile"
}
if (-not (Test-Path -LiteralPath $sentinelDirectory -PathType Container)) {
    throw "Sentinel directory does not exist: $sentinelDirectory"
}

[uint32]$archiveMask = 0x20
[uint32]$directoryMask = 0x10
[uint32]$hiddenMask = 0x02
[uint32]$reparsePointMask = 0x400
[uint32]$nonArchiveMask = 0xFFFFFFDF

[uint32]$before = Get-AttributeMask $target
if (($before -band $directoryMask) -eq 0 -or ($before -band $reparsePointMask) -ne 0) {
    throw "Selected path is not a regular directory: $target"
}
if (($before -band $archiveMask) -ne 0) {
    throw 'Clear the Archive bit on this disposable copy before the test.'
}
if (($before -band $hiddenMask) -eq 0) {
    throw 'Set the Hidden bit on this disposable directory before the test.'
}

$sentinelFileMaskBefore = Get-AttributeMask $sentinelFile
$sentinelDirectoryMaskBefore = Get-AttributeMask $sentinelDirectory
$sentinelHashBefore = (Get-FileHash -LiteralPath $sentinelFile -Algorithm SHA256).Hash

[uint32]$expected = $before -bor $archiveMask
Set-AttributeMask $target $expected
[uint32]$afterFirst = Get-AttributeMask $target
if ($afterFirst -ne $expected) {
    throw ('First readback mismatch: expected 0x{0:X8}, got 0x{1:X8}' -f $expected, $afterFirst)
}

Set-AttributeMask $target $afterFirst
[uint32]$afterSecond = Get-AttributeMask $target
if ($afterSecond -ne $afterFirst) {
    throw ('Idempotence check failed: first mask 0x{0:X8}, second mask 0x{1:X8}' -f $afterFirst, $afterSecond)
}

[uint32]$sentinelFileMaskAfter = Get-AttributeMask $sentinelFile
[uint32]$sentinelDirectoryMaskAfter = Get-AttributeMask $sentinelDirectory
$sentinelHashAfter = (Get-FileHash -LiteralPath $sentinelFile -Algorithm SHA256).Hash
if ($sentinelFileMaskAfter -ne $sentinelFileMaskBefore -or
    $sentinelDirectoryMaskAfter -ne $sentinelDirectoryMaskBefore -or
    $sentinelHashAfter -ne $sentinelHashBefore) {
    throw 'An unrelated sentinel changed during selected-directory finalization.'
}

[ordered]@{
    result = 'WINDOWS_FINALIZATION_PASS'
    filesystem = $fileSystemName.ToString()
    volume_mount_path = $volumePath.ToString()
    selected_path = $target
    selected_attributes_before = ('0x{0:X8}' -f $before)
    selected_attributes_after = ('0x{0:X8}' -f $afterSecond)
    archive_bit_set = (($afterSecond -band $archiveMask) -ne 0)
    other_selected_attributes_preserved = (($afterSecond -band $nonArchiveMask) -eq ($before -band $nonArchiveMask))
    idempotent = ($afterSecond -eq $afterFirst)
    sentinel_file_path = $sentinelFile
    sentinel_directory_path = $sentinelDirectory
    sentinel_file_attributes_before = ('0x{0:X8}' -f $sentinelFileMaskBefore)
    sentinel_file_attributes_after = ('0x{0:X8}' -f $sentinelFileMaskAfter)
    sentinel_directory_attributes_before = ('0x{0:X8}' -f $sentinelDirectoryMaskBefore)
    sentinel_directory_attributes_after = ('0x{0:X8}' -f $sentinelDirectoryMaskAfter)
    sentinel_file_attributes_unchanged = ($sentinelFileMaskAfter -eq $sentinelFileMaskBefore)
    sentinel_directory_attributes_unchanged = ($sentinelDirectoryMaskAfter -eq $sentinelDirectoryMaskBefore)
    sentinel_file_sha256_before = $sentinelHashBefore
    sentinel_file_sha256_unchanged = ($sentinelHashAfter -eq $sentinelHashBefore)
    sentinel_file_sha256 = $sentinelHashAfter
} | ConvertTo-Json -Compress
