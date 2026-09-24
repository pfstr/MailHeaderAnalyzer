# MailHeaderAnalyzer: loads the private helpers and the public cmdlets.
# All parsing runs locally; the module never opens a network connection.
Set-StrictMode -Version 2.0

foreach ($folder in 'Private', 'Public') {
    $dir = Join-Path -Path $PSScriptRoot -ChildPath $folder
    foreach ($file in Get-ChildItem -Path $dir -Filter '*.ps1' -File | Sort-Object Name) {
        . $file.FullName
    }
}

Export-ModuleMember -Function 'Get-MailHeaderAnalysis', 'ConvertTo-MailHeaderReport'
