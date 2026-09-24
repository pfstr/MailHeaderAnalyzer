# Authentication-Results (RFC 8601), Received-SPF, DKIM/ARC tag lists.

function Split-TopLevel {
    <#
    .SYNOPSIS
        Splits at a separator, ignoring separators inside parentheses and quotes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][char]$Separator
    )

    $parts = New-Object System.Collections.Generic.List[string]
    $depth = 0
    $inQuote = $false
    $buffer = ''
    foreach ($ch in $Text.ToCharArray()) {
        if ($inQuote) { $buffer += $ch; if ($ch -eq '"') { $inQuote = $false }; continue }
        if ($ch -eq '"') { $inQuote = $true; $buffer += $ch; continue }
        if ($ch -eq '(') { $depth++ }
        if ($ch -eq ')') { $depth = [math]::Max(0, $depth - 1) }
        if ($ch -eq $Separator -and $depth -eq 0) { $parts.Add($buffer); $buffer = ''; continue }
        $buffer += $ch
    }
    if ($buffer.Trim()) { $parts.Add($buffer) }
    return ,$parts.ToArray()
}

function Split-HeaderComment {
    <#
    .SYNOPSIS
        Strips parenthesised comments and collects them into the given list.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$Comments
    )

    $depth = 0
    $out = ''
    $comment = ''
    foreach ($ch in $Text.ToCharArray()) {
        if ($ch -eq '(') {
            if ($depth -eq 0) { $comment = '' } else { $comment += $ch }
            $depth++
            continue
        }
        if ($ch -eq ')') {
            $depth = [math]::Max(0, $depth - 1)
            if ($depth -eq 0) { if ($comment.Trim()) { $Comments.Add(([regex]::Replace($comment, '\s+', ' ')).Trim()) } }
            else { $comment += $ch }
            continue
        }
        if ($depth -gt 0) { $comment += $ch } else { $out += $ch }
    }
    return $out
}

function ConvertFrom-AuthenticationResults {
    <#
    .SYNOPSIS
        Parses an Authentication-Results field (also the Microsoft variant without authserv-id).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Named after the Authentication-Results header field.')]
    param([Parameter(Mandatory)]$Field)

    $parts = @(Split-TopLevel -Text $Field.Value -Separator ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $authserv = $null
    $start = 0
    if ($parts.Count -gt 0) {
        $headComments = New-Object System.Collections.Generic.List[string]
        $head = (Split-HeaderComment -Text $parts[0] -Comments $headComments).Trim()
        # Only an authserv-id when the first part is no method=result pattern
        # (Microsoft omits the authserv-id and starts directly with spf=...).
        if ($head) {
            $firstToken = ($head -split '\s+')[0]
            if ($firstToken -notmatch '=') { $authserv = $firstToken; $start = 1 }
        }
    }

    $methods = New-Object System.Collections.Generic.List[object]
    for ($i = $start; $i -lt $parts.Count; $i++) {
        $comments = New-Object System.Collections.Generic.List[string]
        $clean = (Split-HeaderComment -Text $parts[$i] -Comments $comments).Trim()
        if (-not $clean -or $clean.ToLowerInvariant() -eq 'none') { continue }
        $m = [regex]::Match($clean, '^([\w/.-]+)\s*=\s*(\S+)\s*(.*)$', 'Singleline')
        if (-not $m.Success) { continue }
        $props = [ordered]@{}
        foreach ($pm in [regex]::Matches($m.Groups[3].Value, '([\w-]+(?:\.[\w-]+)?)\s*=\s*("[^"]*"|[^\s;]+)')) {
            $props[$pm.Groups[1].Value.ToLowerInvariant()] = $pm.Groups[2].Value -replace '^"|"$', ''
        }
        $methods.Add([pscustomobject]@{
            PSTypeName = 'MailHeaderAnalyzer.AuthMethod'
            Method     = ($m.Groups[1].Value -split '/')[0].ToLowerInvariant()
            Result     = [regex]::Replace($m.Groups[2].Value.ToLowerInvariant(), '[.,]+$', '')
            Properties = $props
            Comments   = $comments.ToArray()
        })
    }

    $trust = 'Absent'
    if ($authserv) { $trust = 'Unmatched' }
    [pscustomobject]@{
        PSTypeName = 'MailHeaderAnalyzer.AuthenticationResults'
        AuthServId = $authserv
        Methods    = $methods.ToArray()
        Trust      = $trust
        Raw        = $Field.Raw
    }
}

function Get-AuthTrust {
    <#
    .SYNOPSIS
        Does a verification line come from the receiving system? Its authserv-id must match a
        station of the delivery chain (RFC 8601 section 5); otherwise it is an unverified claim.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()][AllowEmptyString()][string]$AuthServId,
        [AllowEmptyCollection()][string[]]$ByHosts
    )

    if (-not (ConvertTo-NormalizedDomain -Domain $AuthServId)) { return 'Absent' }
    foreach ($h in $ByHosts) {
        if (Test-HostMatch -A $AuthServId -B $h) { return 'Matched' }
    }
    return 'Unmatched'
}

function ConvertFrom-ReceivedSpf {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)]$Field)

    $comments = New-Object System.Collections.Generic.List[string]
    $clean = (Split-HeaderComment -Text $Field.Value -Comments $comments).Trim()
    $result = ''
    if ($clean) { $result = ($clean -split '\s+')[0].ToLowerInvariant() }
    $props = [ordered]@{}
    foreach ($pm in [regex]::Matches($clean, '([\w-]+)\s*=\s*("[^"]*"|[^\s;]+)')) {
        $props[$pm.Groups[1].Value.ToLowerInvariant()] = (($pm.Groups[2].Value -replace '^"|"$', '') -replace ';$', '')
    }
    [pscustomobject]@{
        PSTypeName = 'MailHeaderAnalyzer.ReceivedSpf'
        Result     = $result
        Properties = $props
        Comments   = $comments.ToArray()
        Raw        = $Field.Raw
    }
}

function ConvertFrom-TagList {
    <#
    .SYNOPSIS
        Parses a DKIM/ARC tag list (k=v; k=v; ...) into an ordered dictionary.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)

    $tags = [ordered]@{}
    foreach ($part in (Split-TopLevel -Text $Value -Separator ';')) {
        $m = [regex]::Match($part, '^\s*([a-z][a-z0-9_-]*)\s*=\s*([\s\S]*)$', 'IgnoreCase')
        if ($m.Success) {
            $key = $m.Groups[1].Value.ToLowerInvariant()
            $replacement = ' '
            if ($key -eq 'h') { $replacement = '' }
            $tags[$key] = ([regex]::Replace($m.Groups[2].Value, '\s+', $replacement)).Trim()
        }
    }
    return $tags
}
