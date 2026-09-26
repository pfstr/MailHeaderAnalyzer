function ConvertTo-MailHeaderReport {
    <#
    .SYNOPSIS
        Renders an analysis as a Markdown or plain-text report, for tickets and hand-overs.

    .DESCRIPTION
        Takes the object returned by Get-MailHeaderAnalysis and produces a compact report:
        message facts, authentication results, findings and the delivery chain as a table.
        Direction control characters stay visible as <U+...> so that the report cannot be
        used to smuggle them into a ticket.

    .PARAMETER Analysis
        The analysis object from Get-MailHeaderAnalysis. Accepts pipeline input.

    .PARAMETER Format
        Markdown (default) or Text.

    .EXAMPLE
        Get-MailHeaderAnalysis -Path .\message.eml | ConvertTo-MailHeaderReport

    .EXAMPLE
        Get-MailHeaderAnalysis -FromClipboard | ConvertTo-MailHeaderReport -Format Text | Set-Clipboard

    .OUTPUTS
        System.String

    .LINK
        https://rafaelpfister.ch/en/tools/header-analyzer
    #>
    [CmdletBinding(HelpUri = 'https://rafaelpfister.ch/en/tools/header-analyzer')]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSTypeName('MailHeaderAnalyzer.Analysis')]
        $Analysis,

        [ValidateSet('Markdown', 'Text')]
        [string]$Format = 'Markdown'
    )

    process {
        $markdown = ($Format -eq 'Markdown')
        $lines = New-Object System.Collections.Generic.List[string]
        $h1 = { param($t) if ($markdown) { '# ' + $t } else { $t.ToUpperInvariant() } }
        $h2 = { param($t) if ($markdown) { '## ' + $t } else { $t } }
        $bullet = { param($t) if ($markdown) { '- ' + $t } else { '  ' + $t } }
        $safe = { param($t) if ($null -eq $t) { return '' }; Show-ControlCharacter -Text ([string]$t) }
        $stamp = { param($d) if ($null -eq $d) { return '-' }; $d.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
        $dur = { param($ts) if ($null -eq $ts) { return '-' }; Format-Duration -Seconds ([int64]$ts.TotalSeconds) }

        $lines.Add((& $h1 'Email header analysis'))
        $lines.Add('')
        if ($Analysis.Subject) { $lines.Add((& $bullet ('Subject: ' + (& $safe $Analysis.Subject)))) }
        if ($Analysis.From) { $lines.Add((& $bullet ('From: ' + (& $safe $Analysis.From.Display)))) }
        if ($Analysis.Date) { $lines.Add((& $bullet ('Date: ' + (& $stamp $Analysis.Date)))) }
        if ($Analysis.MessageId) { $lines.Add((& $bullet ('Message-ID: ' + (& $safe $Analysis.MessageId)))) }
        if ($Analysis.Source -and $Analysis.Source -notin @('Text', 'Clipboard')) { $lines.Add((& $bullet ('Source: ' + $Analysis.Source))) }

        $lines.Add('')
        $lines.Add((& $h2 'Authentication'))
        $lines.Add('')
        $any = $false
        foreach ($key in 'Spf', 'Dkim', 'Dmarc', 'Arc', 'CompAuth') {
            $value = $Analysis.$key
            if ($null -eq $value) { continue }
            $any = $true
            $detail = ''
            if ($key -eq 'CompAuth' -and $Analysis.CompAuthReason) {
                $detail = ' (reason={0}' -f $Analysis.CompAuthReason
                if ($Analysis.CompAuthReasonMeaning) { $detail += ': ' + $Analysis.CompAuthReasonMeaning }
                $detail += ')'
            }
            if ($key -eq 'Arc') { $detail = ' (receiver verdict)' }
            $lines.Add((& $bullet ('{0}: {1}{2}' -f $key.ToLowerInvariant(), $value, $detail)))
        }
        if (-not $any) { $lines.Add((& $bullet 'No Authentication-Results found.')) }
        switch ($Analysis.AuthTrust) {
            'Trusted' { $lines.Add((& $bullet ('Results from: {0} (trusted authserv-id)' -f $Analysis.AuthServId))) }
            'Matched' { $lines.Add((& $bullet ('Results from: {0} (appears in the delivery chain; plausible, not proof)' -f $Analysis.AuthServId))) }
            'Unmatched' { $lines.Add((& $bullet ('Not verifiable: results carry {0}, which is neither trusted nor in the delivery chain' -f $Analysis.AuthServId))) }
            'Absent' { $lines.Add((& $bullet 'Results without authserv-id (Microsoft 365 style)')) }
        }
        if ($Analysis.ArcStructure) { $lines.Add((& $bullet ('ARC chain structure: {0} (structure only, signatures not verified)' -f $Analysis.ArcStructure))) }
        if ($Analysis.SpfAlignment) { $lines.Add((& $bullet ('DMARC alignment: SPF {0}, DKIM {1}' -f $Analysis.SpfAlignment, $(if ($Analysis.DkimAlignment) { $Analysis.DkimAlignment } else { '-' })))) }

        if ($Analysis.Findings.Count -gt 0) {
            $lines.Add('')
            $lines.Add((& $h2 'Findings'))
            $lines.Add('')
            foreach ($f in $Analysis.Findings) {
                $lines.Add((& $bullet ('[{0}] {1}: {2}' -f $f.Severity, $f.Code, (& $safe $f.Message))))
            }
        }

        if ($Analysis.Hops.Count -gt 0) {
            $lines.Add('')
            $title = 'Delivery chain'
            if ($null -ne $Analysis.TotalDuration) { $title += ' (total: {0})' -f (& $dur $Analysis.TotalDuration) }
            $lines.Add((& $h2 $title))
            $lines.Add('')
            if ($markdown) {
                $lines.Add('| # | From | By | Protocol | TLS | Time (UTC) | Delay |')
                $lines.Add('|---|---|---|---|---|---|---|')
            }
            foreach ($hop in $Analysis.Hops) {
                $fromParts = @()
                if ($hop.ReverseDns) { $fromParts += $hop.ReverseDns } elseif ($hop.FromHost) { $fromParts += $hop.FromHost }
                if ($hop.IPAddress) { $fromParts += ('({0})' -f $hop.IPAddress) }
                $fromText = $fromParts -join ' '
                if (-not $fromText) { $fromText = '-' }
                $byText = $hop.ByHost
                if (-not $byText) { $byText = '-' }
                $protoText = $hop.Protocol
                if (-not $protoText) { $protoText = '-' }
                $tlsText = $hop.TlsVersion
                if (-not $tlsText) { $tlsText = '-' }
                if ($markdown) {
                    $lines.Add(('| {0} | {1} | {2} | {3} | {4} | {5} | {6} |' -f $hop.Index, (& $safe $fromText), (& $safe $byText), (& $safe $protoText), $tlsText, (& $stamp $hop.Date), (& $dur $hop.Delay)))
                } else {
                    $delayText = ''
                    if ($null -ne $hop.Delay) { $delayText = ' (+{0})' -f (& $dur $hop.Delay) }
                    $lines.Add(('  {0,2}. {1} -> {2} [{3}, {4}] {5}{6}' -f $hop.Index, (& $safe $fromText), (& $safe $byText), (& $safe $protoText), $tlsText, (& $stamp $hop.Date), $delayText))
                }
            }
        }

        if ($null -ne $Analysis.Exchange) {
            $x = $Analysis.Exchange
            $lines.Add('')
            $lines.Add((& $h2 'Exchange hybrid classification'))
            $lines.Add('')
            if ($x.Directionality) { $lines.Add((& $bullet ('MessageDirectionality: ' + $x.Directionality))) }
            if ($x.AuthAs) { $lines.Add((& $bullet ('AuthAs: ' + $x.AuthAs))) }
            if ($x.AuthMechanism) { $lines.Add((& $bullet ('AuthMechanism: ' + $x.AuthMechanism))) }
            if ($x.AuthSource) { $lines.Add((& $bullet ('AuthSource: ' + $x.AuthSource))) }
            if ($x.OriginatorOrg) { $lines.Add((& $bullet ('X-OriginatorOrg: ' + $x.OriginatorOrg))) }
            if ($x.CrossTenantFromEntity) { $lines.Add((& $bullet ('CrossTenant-FromEntityHeader: ' + $x.CrossTenantFromEntity))) }
            if ($x.CrossTenantId) { $lines.Add((& $bullet ('CrossTenant-Id: ' + $x.CrossTenantId))) }
        }

        if ($null -ne $Analysis.Spam) {
            $s = $Analysis.Spam
            $lines.Add('')
            $lines.Add((& $h2 'Spam filter'))
            $lines.Add('')
            if ($null -ne $s.Scl) { $lines.Add((& $bullet ('SCL: {0}{1}' -f $s.Scl, $(if ($s.SclMeaning) { ' (' + $s.SclMeaning + ')' } else { '' })))) }
            if ($null -ne $s.Bcl) { $lines.Add((& $bullet ('BCL: ' + $s.Bcl))) }
            if ($s.Category) { $lines.Add((& $bullet ('CAT: {0}{1}' -f $s.Category, $(if ($s.CategoryMeaning) { ' (' + $s.CategoryMeaning + ')' } else { '' })))) }
            if ($s.SpamFilterVerdict) { $lines.Add((& $bullet ('SFV: {0}{1}' -f $s.SpamFilterVerdict, $(if ($s.SpamFilterMeaning) { ' (' + $s.SpamFilterMeaning + ')' } else { '' })))) }
            if ($s.SpamAssassinScore) { $lines.Add((& $bullet ('SpamAssassin score: {0}; tests: {1}' -f $s.SpamAssassinScore, ($s.SpamAssassinTests -join ', ')))) }
            if ($s.RspamdSymbols.Count -gt 0) { $lines.Add((& $bullet ('Rspamd: ' + (($s.RspamdSymbols | ForEach-Object { '{0}({1})' -f $_.Name, $_.Score }) -join ' ')))) }
        }

        $version = '?'
        $module = Get-Module -Name MailHeaderAnalyzer
        if ($module) { $version = $module.Version.ToString() }
        $lines.Add('')
        if ($markdown) { $lines.Add(('> Generated by MailHeaderAnalyzer {0} (offline analysis)' -f $version)) }
        else { $lines.Add(('Generated by MailHeaderAnalyzer {0} (offline analysis)' -f $version)) }

        return ($lines -join "`n")
    }
}
