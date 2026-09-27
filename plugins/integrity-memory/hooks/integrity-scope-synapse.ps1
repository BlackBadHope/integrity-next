[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('SessionStart', 'UserPromptSubmit', 'PreCompact', 'PostCompact', 'PreToolUse')]
    [string]$Event
)

# Windows entry for the harness-neutral Integrity scope synapse (integrity_scope_synapse.py).
$ErrorActionPreference = 'Stop'
$utf8NoBom = [Text.UTF8Encoding]::new($false)
[Console]::InputEncoding = $utf8NoBom
[Console]::OutputEncoding = $utf8NoBom
$OutputEncoding = $utf8NoBom

function Write-Fallback {
    param([string]$Message)
    [Console]::Error.WriteLine("Integrity scope synapse fault: $Message")
    if ($Event -eq 'PreToolUse') {
        $reason = "INTEGRITY SCOPE SYNAPSE fault: $Message. Actions stay blocked until the owner repairs the scope synapse."
        $deny = @{ hookSpecificOutput = @{ hookEventName = 'PreToolUse'; permissionDecision = 'deny'; permissionDecisionReason = $reason } }
        [Console]::Out.WriteLine(($deny | ConvertTo-Json -Compress -Depth 4))
    } else {
        [Console]::Out.WriteLine('{}')
    }
}

try {
    $runtime = Join-Path $PSScriptRoot 'integrity_scope_synapse.py'
    if (-not [IO.File]::Exists($runtime)) { throw 'scope_synapse_runtime_unavailable' }
    $item = Get-Item -LiteralPath $runtime -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'scope_synapse_runtime_unsafe' }
    $python = Get-Command python.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $python) {
        $python = Get-Command python -CommandType Application -ErrorAction Stop | Select-Object -First 1
    }
    $payload = [Console]::In.ReadToEnd()
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $python.Source
    $info.UseShellExecute = $false
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    $info.StandardInputEncoding = $utf8
    $info.StandardOutputEncoding = $utf8
    $info.StandardErrorEncoding = $utf8
    foreach ($argument in @('-X', 'utf8', $runtime, '--harness', 'codex', '--event', $Event)) {
        [void]$info.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    try {
        if (-not $process.Start()) { throw 'scope_synapse_spawn_failed' }
        $process.StandardInput.Write($payload)
        $process.StandardInput.Close()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(15000)) {
            $process.Kill($true)
            throw 'scope_synapse_timeout'
        }
        $output = $stdout.GetAwaiter().GetResult()
        $errorText = $stderr.GetAwaiter().GetResult()
        if (-not [string]::IsNullOrWhiteSpace($errorText)) { [Console]::Error.Write($errorText) }
        if ($process.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($output)) { throw 'scope_synapse_failed' }
        [Console]::Out.Write($output)
    }
    finally { $process.Dispose() }
}
catch {
    Write-Fallback -Message ([string]$_.Exception.Message)
}
exit 0
