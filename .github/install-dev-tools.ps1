# Installs the tools build.ps1 needs. Used by the CI workflows; works in
# Windows PowerShell 5.1 and PowerShell 7.
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser | Out-Null
}
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
Install-Module -Name Pester -MinimumVersion 5.5 -Force -SkipPublisherCheck -Scope CurrentUser
Install-Module -Name PSScriptAnalyzer -Force -Scope CurrentUser
Write-Host ('PowerShell {0}, Pester {1}, PSScriptAnalyzer {2}' -f $PSVersionTable.PSVersion,
    (Get-Module -ListAvailable Pester | Sort-Object Version -Descending | Select-Object -First 1).Version,
    (Get-Module -ListAvailable PSScriptAnalyzer | Sort-Object Version -Descending | Select-Object -First 1).Version)
