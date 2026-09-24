@{
    RootModule           = 'MailHeaderAnalyzer.psm1'
    ModuleVersion        = '0.1.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    GUID                 = 'f6d83373-3d5d-43c8-b287-3dbd25e93cfc'
    Author               = 'Rafael Pfister'
    CompanyName          = 'adeptio gmbh'
    Copyright            = '(c) 2026 Rafael Pfister. MIT License.'
    Description          = 'Analyzes email headers offline: delivery chain with delays and TLS, SPF/DKIM/DMARC/ARC results and whether they really come from the receiving server, DMARC alignment, Exchange Online hybrid classification (AuthAs, AuthMechanism, CrossTenant), Microsoft Defender/EOP verdicts (SCL, BCL, CAT), SpamAssassin, Rspamd and anomalies such as duplicate From lines or Unicode direction controls. No DNS lookups, no network requests.'
    PowerShellVersion    = '5.1'
    FunctionsToExport    = @('Get-MailHeaderAnalysis', 'ConvertTo-MailHeaderReport')
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    FormatsToProcess     = @('MailHeaderAnalyzer.Format.ps1xml')
    PrivateData          = @{
        PSData = @{
            Tags         = @('Email', 'Mail', 'Header', 'Exchange', 'ExchangeOnline', 'Microsoft365', 'Office365', 'SMTP', 'SPF', 'DKIM', 'DMARC', 'ARC', 'Phishing', 'Security', 'Forensics', 'Troubleshooting', 'PSEdition_Desktop', 'PSEdition_Core', 'Windows', 'Linux', 'MacOS')
            LicenseUri   = 'https://github.com/pfstr/MailHeaderAnalyzer/blob/main/LICENSE'
            ProjectUri   = 'https://rafaelpfister.ch/blog/mailheaderanalyzer-powershell-modul'
            IconUri      = 'https://rafaelpfister.ch/apple-touch-icon.png'
            ReleaseNotes = 'https://github.com/pfstr/MailHeaderAnalyzer/blob/main/CHANGELOG.md'
        }
    }
    HelpInfoURI          = 'https://rafaelpfister.ch/en/tools/header-analyzer'
}
