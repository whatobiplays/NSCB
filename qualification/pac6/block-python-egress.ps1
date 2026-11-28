param(
    [Parameter(Mandatory = $true)][string]$Python,
    [Parameter(Mandatory = $true)][string]$EvidencePath
)

$ErrorActionPreference = 'Stop'
$ruleName = 'NSCB-PAC6-Python-Egress-Block'
$pythonPath = (Resolve-Path -LiteralPath $Python).Path
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

public static class Pac6NtPathResolver
{
    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern SafeFileHandle CreateFile(string path, uint desiredAccess, uint shareMode, IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern uint GetFinalPathNameByHandle(SafeFileHandle handle, StringBuilder path, uint pathLength, uint flags);

    public static string Resolve(string path)
    {
        using (SafeFileHandle handle = CreateFile(path, 0x80, 0x7, IntPtr.Zero, 3, 0, IntPtr.Zero))
        {
            if (handle.IsInvalid)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            StringBuilder result = new StringBuilder(32768);
            uint length = GetFinalPathNameByHandle(handle, result, (uint)result.Capacity, 0x2);
            if (length == 0 || length >= (uint)result.Capacity)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to resolve the executable NT device path.");
            return result.ToString();
        }
    }
}
'@
$pythonNtPath = [Pac6NtPathResolver]::Resolve($pythonPath)
if ($pythonNtPath -notmatch '^\\Device\\HarddiskVolume[0-9]+\\') {
    throw 'The isolated interpreter did not resolve to a local NT device path.'
}
$profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | Where-Object { $_.Enabled })
if ($profiles.Count -eq 0) {
    throw 'Windows Firewall is disabled for every active profile.'
}

$existing = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
if ($null -ne $existing) {
    throw 'The PAC-6 firewall rule already exists on this runner.'
}

$interpreterCheck = "import sys; print(sys.version)"
& $pythonPath -E -s -c $interpreterCheck 2>$null | Out-Null
$interpreterExit = $LASTEXITCODE
if ($interpreterExit -ne 0) {
    throw 'The isolated Python interpreter failed its local execution check.'
}

$probeHost = '1.1.1.1'
$probePort = 443
$probeCode = "import os,socket; print(os.getpid(), flush=True); socket.create_connection(('$probeHost', $probePort), timeout=3).close()"
$baselineOutput = & $pythonPath -E -s -c $probeCode 2>$null
$baselineProbeExit = $LASTEXITCODE
if ($baselineProbeExit -ne 0) {
    throw 'The pre-rule network probe failed, so outbound blocking cannot be verified.'
}

$auditSubcategory = '{0CCE9226-69AE-11D9-BED3-505054503030}'
$auditQuery = & auditpol.exe /get /subcategory:$auditSubcategory /r
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to read the Filtering Platform Connection audit policy.'
}
$auditRows = @($auditQuery | ConvertFrom-Csv)
if ($auditRows.Count -ne 1) {
    throw 'The Filtering Platform Connection audit policy could not be identified.'
}
$priorAuditSetting = [string]$auditRows[0].'Inclusion Setting'
$priorFailureAudit = $priorAuditSetting -match '(?i)failure'
$priorSuccessAudit = $priorAuditSetting -match '(?i)success'
$auditChanged = $false
$probeExit = $null
$probeProcessId = $null
$verification = $null

try {
    if (-not $priorFailureAudit -or -not $priorSuccessAudit) {
        $auditChanged = $true
        & auditpol.exe /set /subcategory:$auditSubcategory /success:enable /failure:enable | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw 'Unable to enable Filtering Platform Connection auditing.'
        }
    }

    $activeAuditQuery = & auditpol.exe /get /subcategory:$auditSubcategory /r
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to verify the Filtering Platform Connection audit policy.'
    }
    $activeAuditRows = @($activeAuditQuery | ConvertFrom-Csv)
    $activeAuditSetting = if ($activeAuditRows.Count -eq 1) {
        [string]$activeAuditRows[0].'Inclusion Setting'
    } else {
        ''
    }
    if ($activeAuditSetting -notmatch '(?i)failure' -or $activeAuditSetting -notmatch '(?i)success') {
        throw 'Filtering Platform Connection success and failure auditing are not enabled.'
    }

    New-NetFirewallRule `
        -Name $ruleName `
        -DisplayName 'PAC-6 block pinned Python outbound traffic' `
        -Direction Outbound `
        -Program $pythonPath `
        -Action Block `
        -Profile Any `
        -Enabled True | Out-Null

    $rule = Get-NetFirewallRule -Name $ruleName -PolicyStore ActiveStore
    $application = $rule | Get-NetFirewallApplicationFilter
    if ($rule.Enabled -ne 'True' -or $rule.Direction -ne 'Outbound' -or $rule.Action -ne 'Block') {
        throw 'The PAC-6 outbound block rule is not enabled with the expected action.'
    }
    if (
        [IO.Path]::GetFullPath($application.Program) -ne [IO.Path]::GetFullPath($pythonPath) -or
        [Pac6NtPathResolver]::Resolve($application.Program) -ine $pythonNtPath
    ) {
        throw 'The PAC-6 outbound rule does not target the isolated consumer interpreter.'
    }

    $probeStarted = Get-Date
    $probeOutput = @(& $pythonPath -E -s -c $probeCode 2>$null)
    $probeExit = $LASTEXITCODE
    $probePidText = [string]($probeOutput | Select-Object -First 1)
    $parsedProcessId = 0
    if (-not [int]::TryParse($probePidText, [ref]$parsedProcessId)) {
        throw 'The Python network probe did not report its process ID.'
    }
    $probeProcessId = $parsedProcessId
    if ($probeExit -eq 0) {
        try {
            $diagnosticEnded = Get-Date
            $successWfpEvents = @()
            try {
                $successWfpEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 5156; StartTime = $probeStarted; EndTime = $diagnosticEnded } -MaxEvents 256 -ErrorAction Stop)
            } catch {
                if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound,*') {
                    throw
                }
            }
            $successEventRows = @(
                foreach ($wfpEvent in $successWfpEvents) {
                    $eventXml = [xml]$wfpEvent.ToXml()
                    $fields = @{}
                    foreach ($field in $eventXml.Event.EventData.Data) {
                        $fields[[string]$field.Name] = [string]$field.InnerText
                    }
                    if ($fields['ProcessID'] -eq [string]$probeProcessId -and
                        $fields['DestAddress'] -eq $probeHost -and
                        $fields['DestPort'] -eq [string]$probePort) {
                        [ordered]@{
                            event_id = $wfpEvent.Id
                            process_id = $fields['ProcessID']
                            application = $fields['Application']
                            source_address = $fields['SourceAddress']
                            source_port = $fields['SourcePort']
                            destination_address = $fields['DestAddress']
                            destination_port = $fields['DestPort']
                            protocol = $fields['Protocol']
                            filter_runtime_id = $fields['FilterRTID']
                            filter_origin = $fields['FilterOrigin']
                            time_created_utc = $wfpEvent.TimeCreated.ToUniversalTime().ToString('o')
                        }
                    }
                }
            )
            $diagnostic = [ordered]@{
                windows = Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber
                python_path = $pythonPath
                python_nt_path = $pythonNtPath
                firewall_rule = [ordered]@{
                    name = $rule.Name
                    enabled = $rule.Enabled
                    direction = $rule.Direction
                    action = $rule.Action
                    profile = $rule.Profile
                    policy_store_source = $rule.PolicyStoreSource
                    policy_store_source_type = $rule.PolicyStoreSourceType
                    primary_status = $rule.PrimaryStatus
                    application_program = $application.Program
                }
                active_firewall_profiles = @(
                    Get-NetFirewallProfile -PolicyStore ActiveStore |
                        Select-Object Name, Enabled, DefaultOutboundAction, AllowLocalFirewallRules
                )
                probe_process_id = $probeProcessId
                probe_exit_status = $probeExit
                matching_success_events = $successEventRows
                audit_policy_before = $priorAuditSetting
                audit_policy_during_probe = $activeAuditSetting
            }
            Write-Output "PAC6_PREFLIGHT_DIAGNOSTIC=$($diagnostic | ConvertTo-Json -Compress -Depth 6)"
        } catch {
            try {
                $diagnosticErrorType = $_.Exception.GetType().FullName
                $diagnosticCommand = [string]$_.InvocationInfo.MyCommand.Name
                $allowedDiagnosticCommands = @('Get-WinEvent', 'Get-CimInstance', 'Get-NetFirewallProfile', 'ConvertTo-Json')
                if ($diagnosticCommand -notin $allowedDiagnosticCommands) {
                    $diagnosticCommand = 'Other'
                }
                $diagnosticErrorId = 'Other'
                if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound,*') {
                    $diagnosticErrorId = 'NoMatchingEventsFound'
                }
                $diagnosticCategory = [string]$_.CategoryInfo.Category
                $diagnosticFailure = [ordered]@{
                    probe_process_id = $probeProcessId
                    probe_exit_status = $probeExit
                    diagnostic_collection_error_type = $diagnosticErrorType
                    diagnostic_collection_command = $diagnosticCommand
                    diagnostic_collection_error_id = $diagnosticErrorId
                    diagnostic_collection_category = $diagnosticCategory
                } | ConvertTo-Json -Compress -Depth 4
                Write-Output "PAC6_PREFLIGHT_DIAGNOSTIC=$diagnosticFailure"
            } catch {
                # Diagnostics are best-effort; the explicit isolation failure below remains authoritative.
            }
        }
        throw 'The Python network probe succeeded after the firewall rule was installed.'
    }

    $eventRows = @()
    $eventDeadline = [DateTime]::UtcNow.AddSeconds(5)
    $eventFile = Join-Path $env:RUNNER_TEMP 'pac6-wfp-events.json'
    $verifierPath = Join-Path $PSScriptRoot 'wfp_audit.py'
    do {
        $verificationEnded = Get-Date
        $eventRows = @(
            foreach ($wfpEvent in @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 5157; StartTime = $probeStarted; EndTime = $verificationEnded } -MaxEvents 256 -ErrorAction SilentlyContinue)) {
                $eventXml = [xml]$wfpEvent.ToXml()
                $fields = @{}
                foreach ($field in $eventXml.Event.EventData.Data) {
                    $fields[[string]$field.Name] = [string]$field.InnerText
                }
                [ordered]@{
                    event_id = $wfpEvent.Id
                    process_id = $fields['ProcessID']
                    application = $fields['Application']
                    destination_address = $fields['DestAddress']
                    destination_port = $fields['DestPort']
                    protocol = $fields['Protocol']
                    filter_origin = $fields['FilterOrigin']
                    time_created_utc = $wfpEvent.TimeCreated.ToUniversalTime().ToString('o')
                }
            }
        )
        $eventsJson = ConvertTo-Json -InputObject $eventRows -AsArray -Compress -Depth 4
        [IO.File]::WriteAllText($eventFile, $eventsJson, [Text.UTF8Encoding]::new($false))
        $verificationOutput = & $pythonPath -E -s $verifierPath `
            --events $eventFile `
            --process-id $probeProcessId `
            --python-nt-path $pythonNtPath `
            --destination-address $probeHost `
            --destination-port $probePort `
            --firewall-rule-name $ruleName 2>$null
        $verificationExit = $LASTEXITCODE
        if ($verificationExit -eq 0) {
            $verification = ($verificationOutput -join [Environment]::NewLine) | ConvertFrom-Json
            break
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $eventDeadline)

    if ($null -eq $verification -or -not $verification.matched) {
        throw 'No matching Windows Filtering Platform block event confirmed the Python probe.'
    }
} finally {
    if ($auditChanged) {
        $restoreFailureAudit = if ($priorFailureAudit) { 'enable' } else { 'disable' }
        $restoreSuccessAudit = if ($priorSuccessAudit) { 'enable' } else { 'disable' }
        & auditpol.exe /set /subcategory:$auditSubcategory "/success:$restoreSuccessAudit" "/failure:$restoreFailureAudit" | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw 'Unable to restore the prior Filtering Platform Connection audit policy.'
        }
        $restoredAuditQuery = & auditpol.exe /get /subcategory:$auditSubcategory /r
        if ($LASTEXITCODE -ne 0) {
            throw 'Unable to verify restoration of the Filtering Platform Connection audit policy.'
        }
        $restoredAuditRows = @($restoredAuditQuery | ConvertFrom-Csv)
        $restoredAuditSetting = if ($restoredAuditRows.Count -eq 1) {
            [string]$restoredAuditRows[0].'Inclusion Setting'
        } else {
            ''
        }
        if (
            ($restoredAuditSetting -match '(?i)success') -ne $priorSuccessAudit -or
            ($restoredAuditSetting -match '(?i)failure') -ne $priorFailureAudit
        ) {
            throw 'The Filtering Platform Connection audit policy was not restored to its prior state.'
        }
    }
}

$evidence = [ordered]@{
    rule_name = $ruleName
    program = $pythonPath
    program_nt_path = $pythonNtPath
    direction = 'Outbound'
    action = 'Block'
    enabled = $true
    active_firewall_profiles = @($profiles | ForEach-Object { $_.Name })
    interpreter_check_exit_status = $interpreterExit
    baseline_network_probe_exit_status = $baselineProbeExit
    audit_subcategory = $auditSubcategory
    failure_auditing_previously_enabled = $priorFailureAudit
    success_auditing_previously_enabled = $priorSuccessAudit
    probe_process_id = $probeProcessId
    probe_address = $probeHost
    probe_port = $probePort
    probe_endpoint = "${probeHost}:$probePort"
    network_probe_exit_status = $probeExit
    network_probe_result = 'blocked-by-matching-wfp-event'
    wfp_block_event = $verification.matching_event
}
$evidence | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $EvidencePath -Encoding utf8
Add-Content -LiteralPath $env:GITHUB_ENV -Value 'PAC6_ISOLATION_VERIFIED=1'
Add-Content -LiteralPath $env:GITHUB_ENV -Value "PAC6_EGRESS_RULE=$ruleName"
Add-Content -LiteralPath $env:GITHUB_ENV -Value "PAC6_EGRESS_PROGRAM=$pythonPath"
Write-Output 'Python outbound block installed and verified.'
