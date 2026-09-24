<#
.SYNOPSIS
    Lint, manifest check and tests. Run before every commit; CI runs it with -CI.
#>
[CmdletBinding()]
param(
    [switch]$CI
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$modulePath = Join-Path $root 'MailHeaderAnalyzer'

Write-Host '== PSScriptAnalyzer' -ForegroundColor Cyan
$issues = @(Invoke-ScriptAnalyzer -Path $modulePath -Recurse -Severity Warning, Error)
if ($issues.Count -gt 0) {
    $issues | Format-Table RuleName, Severity, ScriptName, Line, Message -Wrap | Out-String -Width 200 | Write-Host
    throw ('PSScriptAnalyzer reported {0} issue(s).' -f $issues.Count)
}
Write-Host 'no findings'

Write-Host '== Test-ModuleManifest' -ForegroundColor Cyan
$manifest = Test-ModuleManifest -Path (Join-Path $modulePath 'MailHeaderAnalyzer.psd1')
Write-Host ('{0} {1}' -f $manifest.Name, $manifest.Version)

Write-Host '== Pester' -ForegroundColor Cyan
$config = New-PesterConfiguration
$config.Run.Path = Join-Path $root 'tests'
$config.Run.Exit = $CI.IsPresent
$config.Output.Verbosity = 'Detailed'
if ($CI) {
    $config.TestResult.Enabled = $true
    $config.TestResult.OutputPath = Join-Path $root 'TestResults\results.xml'
}
Invoke-Pester -Configuration $config
