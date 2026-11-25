<#
.SYNOPSIS
Test NSCB archive-attribute finalization on one disposable FAT32 Split directory.

.DESCRIPTION
The selected directory must start with Archive clear and Hidden set. The script
runs the supplied NSCB executable twice, checks its JSON results and exit codes,
then reads the directory attributes through GetFileAttributesW. It compares the
other directory flags and sibling sentinels and checks an isolated state
directory for an unexpected split-trust store.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$QualificationRoot,
    [Parameter(Mandatory = $true)]
    [string]$NscbExecutable
)

$ErrorActionPreference = 'Stop'

if (-not ('NscbSplitAttributeApi' -as [type])) {
    Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;

public static class NscbSplitAttributeApi
{
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

$root = [IO.Path]::GetFullPath($QualificationRoot)
if (-not (Test-Path -LiteralPath $root -PathType Container)) {
    throw "Qualification root does not exist: $root"
}
$nscbExecutable = [IO.Path]::GetFullPath($NscbExecutable)
if (-not (Test-Path -LiteralPath $nscbExecutable -PathType Leaf)) {
    throw "NSCB executable does not exist: $nscbExecutable"
}
$nscbExecutableSha256 = (Get-FileHash -LiteralPath $nscbExecutable -Algorithm SHA256).Hash

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
$sentinelFileLengthBefore = (Get-Item -LiteralPath $sentinelFile).Length
$sentinelDirectoryEntriesBefore = @(
    Get-ChildItem -LiteralPath $sentinelDirectory -Force |
        ForEach-Object { $_.Name } |
        Sort-Object
)
if ($sentinelDirectoryEntriesBefore.Count -ne 0) {
    throw 'The sentinel directory must be empty before the test.'
}

$previousStateDirectory = [Environment]::GetEnvironmentVariable('NSCB_STATE_DIR', 'Process')
$stateDirectory = Join-Path ([IO.Path]::GetTempPath()) (
    'nscb-split-finalization-' + [Guid]::NewGuid().ToString('N')
)
$trustStoreDirectory = Join-Path $stateDirectory 'split-trust'
if (Test-Path -LiteralPath $stateDirectory) {
    throw "Temporary NSCB state path already exists: $stateDirectory"
}
New-Item -ItemType Directory -Path $stateDirectory | Out-Null

function Invoke-NscbFinalizer {
    $output = & $nscbExecutable 'finalize-split-set' $target '--json'
    $exitCode = $LASTEXITCODE
    $jsonText = $output -join [Environment]::NewLine
    if ($exitCode -ne 0) {
        throw "NSCB finalizer exited $exitCode; output: $jsonText"
    }

    try {
        $document = ConvertFrom-Json -InputObject $jsonText -ErrorAction Stop
    }
    catch {
        throw "NSCB finalizer did not return valid JSON: $($_.Exception.Message)"
    }
    if ($document.kind -ne 'split_finalization.result' -or
        $document.result.manifest_consistency -ne 'verified' -or
        $document.result.source_backed_completeness -ne 'not_established' -or
        $document.result.consumer_interoperability -ne 'not_established' -or
        $null -ne $document.result.PSObject.Properties['trust_receipt']) {
        throw "NSCB finalizer returned an unexpected result: $jsonText"
    }
    return [pscustomobject]@{
        ExitCode = $exitCode
        Result = $document.result
    }
}

try {
    [Environment]::SetEnvironmentVariable('NSCB_STATE_DIR', $stateDirectory, 'Process')

    $firstResult = Invoke-NscbFinalizer
    if ($firstResult.Result.archive_attribute -ne 'set') {
        throw "Expected first archive_attribute=set; got $($firstResult.Result.archive_attribute)"
    }
    [uint32]$afterFirst = Get-AttributeMask $target
    $firstOtherAttributesPreserved =
        ($afterFirst -band $nonArchiveMask) -eq ($before -band $nonArchiveMask)
    if (($afterFirst -band $archiveMask) -eq 0 -or -not $firstOtherAttributesPreserved) {
        throw ('First independent readback mismatch: before 0x{0:X8}, after 0x{1:X8}' -f $before, $afterFirst)
    }

    $secondResult = Invoke-NscbFinalizer
    if ($secondResult.Result.archive_attribute -ne 'already_set') {
        throw "Expected second archive_attribute=already_set; got $($secondResult.Result.archive_attribute)"
    }
    [uint32]$afterSecond = Get-AttributeMask $target
    $secondOtherAttributesPreserved =
        ($afterSecond -band $nonArchiveMask) -eq ($before -band $nonArchiveMask)
    if ($afterSecond -ne $afterFirst -or -not $secondOtherAttributesPreserved) {
        throw ('Second independent readback mismatch: first 0x{0:X8}, second 0x{1:X8}' -f $afterFirst, $afterSecond)
    }

    [uint32]$sentinelFileMaskAfter = Get-AttributeMask $sentinelFile
    [uint32]$sentinelDirectoryMaskAfter = Get-AttributeMask $sentinelDirectory
    $sentinelHashAfter = (Get-FileHash -LiteralPath $sentinelFile -Algorithm SHA256).Hash
    $sentinelFileLengthAfter = (Get-Item -LiteralPath $sentinelFile).Length
    $sentinelDirectoryEntriesAfter = @(
        Get-ChildItem -LiteralPath $sentinelDirectory -Force |
            ForEach-Object { $_.Name } |
            Sort-Object
    )
    $sentinelDirectoryEntriesUnchanged =
        ($sentinelDirectoryEntriesBefore -join "`n") -ceq
        ($sentinelDirectoryEntriesAfter -join "`n")
    if ($sentinelFileMaskAfter -ne $sentinelFileMaskBefore -or
        $sentinelDirectoryMaskAfter -ne $sentinelDirectoryMaskBefore -or
        $sentinelHashAfter -ne $sentinelHashBefore -or
        $sentinelFileLengthAfter -ne $sentinelFileLengthBefore -or
        -not $sentinelDirectoryEntriesUnchanged) {
        throw 'An unrelated sentinel changed during selected-directory finalization.'
    }

    if (Test-Path -LiteralPath $trustStoreDirectory) {
        throw "Finalizer created an unexpected trust-receipt store: $trustStoreDirectory"
    }

    [ordered]@{
        result = 'WINDOWS_FINALIZATION_PASS'
        filesystem = $fileSystemName.ToString()
        volume_mount_path = $volumePath.ToString()
        nscb_executable_path = $nscbExecutable
        nscb_executable_sha256 = $nscbExecutableSha256
        selected_path = $target
        first_exit_code = $firstResult.ExitCode
        first_archive_attribute = $firstResult.Result.archive_attribute
        second_exit_code = $secondResult.ExitCode
        second_archive_attribute = $secondResult.Result.archive_attribute
        selected_attributes_before = ('0x{0:X8}' -f $before)
        selected_attributes_after_first = ('0x{0:X8}' -f $afterFirst)
        selected_attributes_after_second = ('0x{0:X8}' -f $afterSecond)
        archive_bit_set = (($afterSecond -band $archiveMask) -ne 0)
        other_selected_attributes_preserved = ($firstOtherAttributesPreserved -and $secondOtherAttributesPreserved)
        idempotent = ($afterSecond -eq $afterFirst)
        trust_receipt_store_path = $trustStoreDirectory
        trust_receipt_store_absent = $true
        sentinel_file_path = $sentinelFile
        sentinel_directory_path = $sentinelDirectory
        sentinel_file_attributes_before = ('0x{0:X8}' -f $sentinelFileMaskBefore)
        sentinel_file_attributes_after = ('0x{0:X8}' -f $sentinelFileMaskAfter)
        sentinel_directory_attributes_before = ('0x{0:X8}' -f $sentinelDirectoryMaskBefore)
        sentinel_directory_attributes_after = ('0x{0:X8}' -f $sentinelDirectoryMaskAfter)
        sentinel_file_attributes_unchanged = ($sentinelFileMaskAfter -eq $sentinelFileMaskBefore)
        sentinel_directory_attributes_unchanged = ($sentinelDirectoryMaskAfter -eq $sentinelDirectoryMaskBefore)
        sentinel_directory_entries_before = $sentinelDirectoryEntriesBefore
        sentinel_directory_entries_after = $sentinelDirectoryEntriesAfter
        sentinel_directory_entries_unchanged = $sentinelDirectoryEntriesUnchanged
        sentinel_file_byte_length = $sentinelFileLengthAfter
        sentinel_file_sha256_before = $sentinelHashBefore
        sentinel_file_sha256_unchanged = ($sentinelHashAfter -eq $sentinelHashBefore)
        sentinel_file_sha256 = $sentinelHashAfter
    } | ConvertTo-Json -Compress
}
finally {
    [Environment]::SetEnvironmentVariable('NSCB_STATE_DIR', $previousStateDirectory, 'Process')
    if (-not (Test-Path -LiteralPath $trustStoreDirectory)) {
        Remove-Item -LiteralPath $stateDirectory -Force -Recurse
    }
}
