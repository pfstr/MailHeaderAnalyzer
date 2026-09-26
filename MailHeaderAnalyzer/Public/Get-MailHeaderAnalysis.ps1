function Get-MailHeaderAnalysis {
    <#
    .SYNOPSIS
        Analyzes an email header: delivery chain, SPF/DKIM/DMARC/ARC results, Exchange hybrid
        classification, spam filter verdicts and anomalies. Runs entirely offline.

    .DESCRIPTION
        Parses the raw header of an email message (or a whole .eml file; the body is ignored)
        and returns an analysis object. Nothing leaves the machine: the cmdlet performs no DNS
        lookups and no HTTP requests, which makes it safe for headers that contain customer data.

        What it reads:
        - Received chain in chronological order, with delays per hop, TLS version and cipher,
          protocol class (RFC 3848), private IPs and provider detection.
        - Authentication-Results (RFC 8601), including the Microsoft variant without authserv-id,
          Received-SPF, DKIM-Signature tags, the ARC chain and compauth reason codes.
        - The origin of the verification results (AuthTrust). Without -TrustedAuthServId the
          module can only check plausibility: an authserv-id that appears as "by" host in the
          delivery chain is reported as Matched. A sender can forge both lines, so Matched is
          not proof. With -TrustedAuthServId, only lines carrying one of those ids count
          (Trusted); everything else is an unverified claim.
        - The ARC chain structure (instance numbering, one header set per instance, cv=
          sequence). Signatures are not verified; the cryptographic verdict is the receiver's
          arc= result.
        - DMARC alignment (strict/relaxed) of SPF and DKIM against the From domain.
        - Exchange Online hybrid headers (MessageDirectionality, AuthAs, AuthMechanism,
          CrossTenant-*), Microsoft Defender/EOP verdicts (SCL, BCL, CAT, SFV, IPV),
          SpamAssassin and Rspamd.
        - Anomalies: duplicate singleton fields, Unicode direction controls, weak DKIM hashes,
          expired signatures, clock skew, Reply-To mismatches and more, as Findings.

    .PARAMETER Header
        The raw header text. Accepts pipeline input line by line (for example from Get-Content),
        all lines are joined into one header.

    .PARAMETER Path
        Path to a file with the raw header or a complete .eml message. Accepts pipeline input
        from Get-ChildItem.

    .PARAMETER FromClipboard
        Reads the header from the clipboard (Windows). Copy the header in Outlook
        (File > Properties > Internet headers) or the webmail client, then run the cmdlet.

    .PARAMETER TrustedAuthServId
        The authserv-id(s) your inbound gateway writes into Authentication-Results, for example
        'mx.contoso.com'. Compared exactly, no subdomains. Only lines carrying one of these ids
        count as evidence. This is sound only if the gateway removes incoming
        Authentication-Results that claim the same id (RFC 8601 section 5); the module cannot
        check that from a header. Set it once per session with
        $PSDefaultParameterValues['Get-MailHeaderAnalysis:TrustedAuthServId'] = 'mx.contoso.com'.

    .EXAMPLE
        Get-MailHeaderAnalysis -Path .\message.eml

        Analyzes the header of a saved message and shows the summary.

    .EXAMPLE
        Get-MailHeaderAnalysis -Path .\message.eml -TrustedAuthServId 'mx.contoso.com'

        Counts only verification results written by your own gateway.

    .EXAMPLE
        Get-MailHeaderAnalysis -FromClipboard | Select-Object -ExpandProperty Hops | Format-Table

        Shows the delivery chain of the header currently in the clipboard.

    .EXAMPLE
        Get-Content .\header.txt | Get-MailHeaderAnalysis | Select-Object -ExpandProperty Findings

        Lists only the anomalies.

    .EXAMPLE
        Get-ChildItem .\samples\*.eml | Get-MailHeaderAnalysis | Select-Object Source, Spf, Dkim, Dmarc, AuthTrust

        Batch check of several messages.

    .EXAMPLE
        Get-MailHeaderAnalysis -Path .\message.eml | ConvertTo-MailHeaderReport | Set-Clipboard

        Builds a Markdown report for a ticket.

    .OUTPUTS
        MailHeaderAnalyzer.Analysis

    .LINK
        https://rafaelpfister.ch/en/tools/header-analyzer
    #>
    [CmdletBinding(DefaultParameterSetName = 'Text', HelpUri = 'https://rafaelpfister.ch/en/tools/header-analyzer')]
    [OutputType('MailHeaderAnalyzer.Analysis')]
    param(
        [Parameter(ParameterSetName = 'Text', Mandatory, ValueFromPipeline, Position = 0)]
        [AllowEmptyString()]
        [Alias('Text', 'Raw', 'InputObject')]
        [string[]]$Header,

        [Parameter(ParameterSetName = 'Path', Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('FullName', 'PSPath', 'LiteralPath')]
        [string[]]$Path,

        [Parameter(ParameterSetName = 'Clipboard', Mandatory)]
        [switch]$FromClipboard,

        [string[]]$TrustedAuthServId = @()
    )

    begin {
        $collected = New-Object System.Collections.Generic.List[string]
    }

    process {
        switch ($PSCmdlet.ParameterSetName) {
            'Text' {
                foreach ($chunk in $Header) { $collected.Add($chunk) }
            }
            'Path' {
                foreach ($p in $Path) {
                    $resolved = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($p)
                    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
                        Write-Error -Message ('File not found: {0}' -f $p) -Category ObjectNotFound -TargetObject $p
                        continue
                    }
                    # ReadAllText honours a byte order mark and defaults to UTF-8.
                    $text = [System.IO.File]::ReadAllText($resolved)
                    Invoke-HeaderAnalysis -Text $text -Source $resolved -TrustedAuthServId $TrustedAuthServId
                }
            }
            'Clipboard' {
                if (-not $FromClipboard) { return }
                if (-not (Get-Command -Name Get-Clipboard -ErrorAction SilentlyContinue)) {
                    throw 'Get-Clipboard is not available on this platform. Use -Path or -Header instead.'
                }
                $text = Get-Clipboard -Raw
                if ([string]::IsNullOrWhiteSpace($text)) {
                    throw 'The clipboard is empty. Copy the message header first.'
                }
                Invoke-HeaderAnalysis -Text $text -Source 'Clipboard' -TrustedAuthServId $TrustedAuthServId
            }
        }
    }

    end {
        if ($PSCmdlet.ParameterSetName -eq 'Text') {
            $text = $collected -join "`n"
            if ([string]::IsNullOrWhiteSpace($text)) {
                throw 'No header text given.'
            }
            Invoke-HeaderAnalysis -Text $text -Source 'Text' -TrustedAuthServId $TrustedAuthServId
        }
    }
}
