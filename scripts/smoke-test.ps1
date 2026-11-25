param(
    [Parameter(Mandatory = $true)]
    [string]$ExecutablePath,

    [string]$ArtifactsDir = "smoke-artifacts",

    [int]$TimeoutSeconds = 30
)

$ErrorActionPreference = "Stop"

$resolvedExe = (Resolve-Path -Path $ExecutablePath).Path
if (-not (Test-Path -Path $resolvedExe -PathType Leaf)) {
    throw "Executable not found: $ExecutablePath"
}

$logsDir = Join-Path $ArtifactsDir "logs"
$fixtureDir = Join-Path $ArtifactsDir "fixture-src"
New-Item -ItemType Directory -Path $logsDir -Force | Out-Null
New-Item -ItemType Directory -Path $fixtureDir -Force | Out-Null

# Build a self-authored .NET 7 class library fixture on the fly.
# This fixture is NEVER executed; it is only passed as a static input file to de4vmp.
$fixtureCsproj = @'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net7.0</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
  </PropertyGroup>
</Project>
'@

$fixtureCode = @'
namespace SmokeFixture;

public static class SampleTarget {
    public static int Add(int a, int b) => a + b;
}
'@

Set-Content -Path (Join-Path $fixtureDir "SmokeFixture.csproj") -Value $fixtureCsproj -Encoding utf8
Set-Content -Path (Join-Path $fixtureDir "SampleTarget.cs") -Value $fixtureCode -Encoding utf8

Write-Host "Building self-authored .NET fixture..."
& dotnet build (Join-Path $fixtureDir "SmokeFixture.csproj") -c Release -o (Join-Path $ArtifactsDir "fixture-bin") | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Failed to build self-authored SmokeFixture.csproj (exit code $LASTEXITCODE)."
}

$fixtureDll = (Resolve-Path (Join-Path $ArtifactsDir "fixture-bin/SmokeFixture.dll")).Path

# Create a plain-text non-PE fixture to validate malformed PE handling.
$nonPeFile = Join-Path $ArtifactsDir "not-a-pe.txt"
Set-Content -Path $nonPeFile -Value "This is not a PE binary." -Encoding utf8

$results = [System.Collections.Generic.List[object]]::new()

function Invoke-SmokeCase {
    param(
        [string]$Name,
        [string[]]$Arguments,
        [int]$ExpectedExitCode,
        [string]$ExpectedStdoutPattern = "",
        [string]$ExpectedStderrPattern = ""
    )

    $stdoutPath = Join-Path $logsDir "$Name.stdout.log"
    $stderrPath = Join-Path $logsDir "$Name.stderr.log"

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $resolvedExe
    foreach ($arg in $Arguments) {
        [void]$psi.ArgumentList.Add($arg)
    }
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = $true
    $psi.CreateNoWindow = $true

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $proc = [System.Diagnostics.Process]::Start($psi)
    $proc.StandardInput.Close()

    $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
    $stderrTask = $proc.StandardError.ReadToEndAsync()

    $waitMs = [Math]::Max(($TimeoutSeconds + 15) * 1000, 30000)
    $exited = $proc.WaitForExit($waitMs)
    $sw.Stop()

    if (-not $exited) {
        try { $proc.Kill($true) } catch {}
        $actualExit = -1
        $stdout = ""
        $stderr = "Process exceeded harness timeout of ${waitMs}ms and was terminated."
    }
    else {
        $actualExit = $proc.ExitCode
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
    }

    Set-Content -Path $stdoutPath -Value $stdout -Encoding utf8
    Set-Content -Path $stderrPath -Value $stderr -Encoding utf8

    $failures = [System.Collections.Generic.List[string]]::new()
    if ($actualExit -ne $ExpectedExitCode) {
        $failures.Add("Expected exit code $ExpectedExitCode, got $actualExit.")
    }
    if (-not [string]::IsNullOrEmpty($ExpectedStdoutPattern) -and ($stdout -notmatch $ExpectedStdoutPattern)) {
        $failures.Add("Stdout did not match expected pattern '$ExpectedStdoutPattern'.")
    }
    if (-not [string]::IsNullOrEmpty($ExpectedStderrPattern) -and ($stderr -notmatch $ExpectedStderrPattern)) {
        $failures.Add("Stderr did not match expected pattern '$ExpectedStderrPattern'.")
    }

    $passed = ($failures.Count -eq 0)
    $status = if ($passed) { "PASS" } else { "FAIL" }
    Write-Host "[$status] $Name (exit=$actualExit, expected=$ExpectedExitCode, $($sw.ElapsedMilliseconds)ms)"
    if (-not $passed) {
        foreach ($f in $failures) {
            Write-Host "  - $f"
        }
    }

    $results.Add([pscustomobject]@{
        name             = $Name
        passed           = $passed
        expectedExitCode = $ExpectedExitCode
        actualExitCode   = $actualExit
        durationMs       = $sw.ElapsedMilliseconds
        failures         = @($failures)
        stdoutLog        = $stdoutPath
        stderrLog        = $stderrPath
    })
}

Invoke-SmokeCase -Name "01-help" `
    -Arguments @("--help") `
    -ExpectedExitCode 0 `
    -ExpectedStdoutPattern "Usage:"

Invoke-SmokeCase -Name "02-version" `
    -Arguments @("--version") `
    -ExpectedExitCode 0 `
    -ExpectedStdoutPattern "de4vmp"

Invoke-SmokeCase -Name "03-missing-input" `
    -Arguments @("--ci", "--no-banner") `
    -ExpectedExitCode 2 `
    -ExpectedStderrPattern "Missing input file path"

Invoke-SmokeCase -Name "04-unknown-option" `
    -Arguments @("--ci", "--definitely-invalid-flag") `
    -ExpectedExitCode 2 `
    -ExpectedStderrPattern "Unknown option"

Invoke-SmokeCase -Name "05-nonexistent-file" `
    -Arguments @("--ci", "--no-banner", (Join-Path $ArtifactsDir "does-not-exist.dll")) `
    -ExpectedExitCode 2 `
    -ExpectedStderrPattern "does not exist"

Invoke-SmokeCase -Name "06-invalid-timeout" `
    -Arguments @("--ci", "--timeout", "-5", $fixtureDll) `
    -ExpectedExitCode 2 `
    -ExpectedStderrPattern "Invalid timeout"

Invoke-SmokeCase -Name "07-non-pe-input" `
    -Arguments @("--ci", "--no-banner", "--timeout", "$TimeoutSeconds", $nonPeFile) `
    -ExpectedExitCode 2 `
    -ExpectedStderrPattern "BadImageFormatException|ArgumentException"

Invoke-SmokeCase -Name "08-dotnet-fixture-static-analysis" `
    -Arguments @("--ci", "--no-banner", "--timeout", "$TimeoutSeconds", $fixtureDll) `
    -ExpectedExitCode 3 `
    -ExpectedStdoutPattern "Searching for functions" `
    -ExpectedStderrPattern "HandlerResolverException"

$resultsJsonPath = Join-Path $ArtifactsDir "smoke-results.json"
$results | ConvertTo-Json -Depth 5 | Set-Content -Path $resultsJsonPath -Encoding utf8

$passedCount = ($results | Where-Object { $_.passed }).Count
$failedCount = ($results | Where-Object { -not $_.passed }).Count

$summaryLines = [System.Collections.Generic.List[string]]::new()
$summaryLines.Add("## de4vmp Smoke Test Results")
$summaryLines.Add("")
$summaryLines.Add("- **Total:** $($results.Count)")
$summaryLines.Add("- **Passed:** $passedCount")
$summaryLines.Add("- **Failed:** $failedCount")
$summaryLines.Add("")
$summaryLines.Add("| Test | Status | Exit Code | Expected | Duration (ms) |")
$summaryLines.Add("|------|--------|-----------|----------|---------------|")
foreach ($r in $results) {
    $badge = if ($r.passed) { "PASS" } else { "FAIL" }
    $summaryLines.Add("| $($r.name) | $badge | $($r.actualExitCode) | $($r.expectedExitCode) | $($r.durationMs) |")
}
$summaryPath = Join-Path $ArtifactsDir "smoke-summary.md"
Set-Content -Path $summaryPath -Value $summaryLines -Encoding utf8

if ($failedCount -gt 0) {
    Write-Error "Smoke test suite failed: $failedCount of $($results.Count) test(s) failed."
    exit 1
}

Write-Host "All $passedCount smoke tests passed."
exit 0
