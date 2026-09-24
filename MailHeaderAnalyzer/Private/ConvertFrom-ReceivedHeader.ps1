# Received chain: tokenizer (comment-aware), one hop per Received field.

function Split-ReceivedSegment {
    <#
    .SYNOPSIS
        Splits a Received value into words and parenthesised comments (comments may nest).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)

    $segments = New-Object System.Collections.Generic.List[object]
    $depth = 0
    $word = ''
    $comment = ''
    foreach ($ch in $Value.ToCharArray()) {
        if ($depth -eq 0) {
            if ($ch -eq '(') {
                if ($word) { $segments.Add(@{ Kind = 'word'; Text = $word }); $word = '' }
                $depth = 1
                $comment = ''
            } elseif ([char]::IsWhiteSpace($ch)) {
                if ($word) { $segments.Add(@{ Kind = 'word'; Text = $word }); $word = '' }
            } else {
                $word += $ch
            }
        } else {
            if ($ch -eq '(') { $depth++; $comment += $ch }
            elseif ($ch -eq ')') {
                $depth--
                if ($depth -eq 0) { $segments.Add(@{ Kind = 'comment'; Text = ([regex]::Replace($comment, '\s+', ' ')).Trim() }) }
                else { $comment += $ch }
            } else {
                $comment += $ch
            }
        }
    }
    if ($word) { $segments.Add(@{ Kind = 'word'; Text = $word }) }
    if ($depth -gt 0 -and $comment.Trim()) { $segments.Add(@{ Kind = 'comment'; Text = ([regex]::Replace($comment, '\s+', ' ')).Trim() }) }
    return ,$segments
}

function Get-LastTopLevelSemicolon {
    <#
    .SYNOPSIS
        Position of the last semicolon outside parentheses (the date separator), or -1.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)

    $depth = 0
    for ($i = $Text.Length - 1; $i -ge 0; $i--) {
        $ch = $Text[$i]
        if ($ch -eq ')') { $depth++ }
        elseif ($ch -eq '(') { $depth = [math]::Max(0, $depth - 1) }
        elseif ($ch -eq ';' -and $depth -eq 0) { return $i }
    }
    return -1
}

function Test-PrivateIPAddress {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$IPAddress)

    $v4 = [regex]::Match($IPAddress, '^(\d+)\.(\d+)\.')
    if ($v4.Success) {
        $a = [int]$v4.Groups[1].Value
        $b = [int]$v4.Groups[2].Value
        return ($a -eq 10 -or $a -eq 127 -or ($a -eq 172 -and $b -ge 16 -and $b -le 31) -or ($a -eq 192 -and $b -eq 168) -or
            ($a -eq 169 -and $b -eq 254) -or ($a -eq 100 -and $b -ge 64 -and $b -le 127))
    }
    $low = $IPAddress.ToLowerInvariant()
    return ($low -eq '::1' -or $low.StartsWith('fe80:') -or $low.StartsWith('fc') -or $low.StartsWith('fd'))
}

function ConvertTo-TlsVersionLabel {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Version)

    $v = [regex]::Replace($Version, '^TLSv?', 'TLS ', 'IgnoreCase')
    $v = $v -replace '_', '.'
    $v = [regex]::Replace($v, '^TLS \.', 'TLS 1.')
    $v = ([regex]::Replace($v, '\s+', ' ')).Trim()
    return [regex]::Replace($v, '^TLS ?1\.?([0-3])$', 'TLS 1.$1')
}

function ConvertFrom-ReceivedHeader {
    <#
    .SYNOPSIS
        Parses one Received field into a hop object.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Value,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Raw
    )

    $semi = Get-LastTopLevelSemicolon -Text $Value
    $dateRaw = ''
    $rest = $Value
    if ($semi -ge 0) {
        $dateRaw = $Value.Substring($semi + 1).Trim()
        $rest = $Value.Substring(0, $semi)
    }

    $keywords = @('from', 'by', 'via', 'with', 'id', 'for')
    $groups = @{}
    $current = $null
    foreach ($segment in (Split-ReceivedSegment -Value $rest)) {
        $low = $segment.Text.ToLowerInvariant()
        $emptyCurrent = ($null -ne $current -and $groups[$current].Count -eq 0)
        if ($segment.Kind -eq 'word' -and $keywords -contains $low -and -not $emptyCurrent) {
            $current = $low
            if (-not $groups.ContainsKey($current)) { $groups[$current] = New-Object System.Collections.Generic.List[object] }
        } elseif ($null -ne $current) {
            $groups[$current].Add($segment)
        }
    }

    $words = {
        param($key)
        if (-not $groups.ContainsKey($key)) { return @() }
        return @($groups[$key] | Where-Object { $_.Kind -eq 'word' } | ForEach-Object { $_.Text })
    }
    $comments = {
        param($key)
        if (-not $groups.ContainsKey($key)) { return @() }
        return @($groups[$key] | Where-Object { $_.Kind -eq 'comment' } | ForEach-Object { $_.Text })
    }

    $fromWords = @(& $words 'from')
    $fromHost = $null
    if ($fromWords.Count -gt 0) { $fromHost = $fromWords[0] }
    $fromComments = (& $comments 'from') -join ' '
    $byWords = @(& $words 'by')
    $byHost = $null
    if ($byWords.Count -gt 0) { $byHost = $byWords[0] -replace '\.$', '' }
    $software = (& $comments 'by') -join ' '
    if (-not $software) { $software = $null }
    $protocol = (& $words 'with') -join ' '
    if (-not $protocol) { $protocol = $null }
    $id = (& $words 'id') -join ' '
    if (-not $id) { $id = $null }
    $forWords = @(& $words 'for')
    $forAddress = $null
    if ($forWords.Count -gt 0) { $forAddress = $forWords[0] -replace '[<>]', '' }
    $via = (& $words 'via') -join ' '
    if (-not $via) { $via = $null }

    # IP: preferably from square brackets in the from comment, otherwise a bare
    # IPv4, otherwise an IP literal as HELO name.
    $ip = $null
    $ipMatch = [regex]::Match($fromComments, '\[(?:IPv6:)?([0-9a-fA-F:.]+)\]')
    if ($ipMatch.Success) { $ip = $ipMatch.Groups[1].Value }
    else {
        $v4Match = [regex]::Match($fromComments, '\b((?:\d{1,3}\.){3}\d{1,3})\b')
        if ($v4Match.Success) { $ip = $v4Match.Groups[1].Value }
    }
    if (-not $ip -and $fromHost) {
        $literal = [regex]::Match($fromHost, '^\[(?:IPv6:)?([0-9a-fA-F:.]+)\]$')
        if ($literal.Success) { $ip = $literal.Groups[1].Value }
        elseif ($fromHost -match '^(?:\d{1,3}\.){3}\d{1,3}$') { $ip = $fromHost }
    }

    # rDNS: first host name in the from comment that is not the IP itself.
    $reverseDns = $null
    $rd = [regex]::Match($fromComments, '(?:^|[\s(])([a-z0-9][a-z0-9._-]*\.[a-z][a-z0-9-]*)\.?(?=\s*\[)', 'IgnoreCase')
    if ($rd.Success -and $rd.Groups[1].Value.ToLowerInvariant() -ne 'unknown') { $reverseDns = $rd.Groups[1].Value.ToLowerInvariant() }
    $helo = $fromHost
    $heloMatch = [regex]::Match($fromComments, '\bhelo=([^\s)]+)', 'IgnoreCase')
    if ($heloMatch.Success) { $helo = $heloMatch.Groups[1].Value }

    # TLS details from the whole line (Microsoft, Postfix and Exim spellings).
    $rawOne = [regex]::Replace($Raw, '\s+', ' ')
    $tlsVersion = $null
    $tlsCipher = $null
    $msTls = [regex]::Match($rawOne, 'version=([A-Za-z0-9_.]+)[,\s)]+cipher=([A-Za-z0-9_-]+)')
    $pfTls = [regex]::Match($rawOne, 'using\s+(TLSv?[0-9._]+)(?:\s+with\s+cipher\s+([A-Z0-9_-]+))?', 'IgnoreCase')
    $anyTls = [regex]::Match($rawOne, '\b(TLSv?1[._][0-3])\b')
    if ($msTls.Success) { $tlsVersion = ConvertTo-TlsVersionLabel -Version $msTls.Groups[1].Value; $tlsCipher = $msTls.Groups[2].Value }
    elseif ($pfTls.Success) {
        $tlsVersion = ConvertTo-TlsVersionLabel -Version $pfTls.Groups[1].Value
        if ($pfTls.Groups[2].Success) { $tlsCipher = $pfTls.Groups[2].Value }
    } elseif ($anyTls.Success) { $tlsVersion = ConvertTo-TlsVersionLabel -Version $anyTls.Groups[1].Value }
    if (-not $tlsCipher) {
        $cipherMatch = [regex]::Match($rawOne, '\bcipher[= ]([A-Z0-9_-]{8,})', 'IgnoreCase')
        if ($cipherMatch.Success) { $tlsCipher = $cipherMatch.Groups[1].Value }
    }

    # Protocol class (RFC 3848 "with" values plus Microsoft variants).
    $p = ''
    if ($protocol) { $p = $protocol.ToUpperInvariant() }
    $protocolClass = $null
    if ($p) {
        if ($p.Contains('HTTP')) { $protocolClass = 'Http' }
        elseif ($p.Contains('MAPI')) { $protocolClass = 'Mapi' }
        elseif ($p.Contains('LOCAL')) { $protocolClass = 'Local' }
        elseif ($p -match 'SMTPSA$|LMTPSA$') { $protocolClass = 'TlsAuthenticated' }
        elseif ($p -match 'SMTPS$|LMTPS$') { $protocolClass = 'Tls' }
        elseif ($p -match 'SMTPA$|LMTPA$') { $protocolClass = 'Authenticated' }
        elseif ($p.Contains('SMTP') -or $p.Contains('LMTP')) { if ($tlsVersion) { $protocolClass = 'Tls' } else { $protocolClass = 'Plain' } }
    } elseif ($tlsVersion) {
        $protocolClass = 'Tls'
    }

    $hostsForProvider = @($reverseDns, $fromHost, $byHost) | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() }
    $isPrivate = $false
    if ($ip) { $isPrivate = Test-PrivateIPAddress -IPAddress $ip }

    [pscustomobject]@{
        PSTypeName    = 'MailHeaderAnalyzer.Hop'
        Index         = 0
        FromHost      = $fromHost
        Helo          = $helo
        ReverseDns    = $reverseDns
        IPAddress     = $ip
        IsPrivateIP   = $isPrivate
        ByHost        = $byHost
        Software      = $software
        Protocol      = $protocol
        ProtocolClass = $protocolClass
        TlsVersion    = $tlsVersion
        TlsCipher     = $tlsCipher
        Id            = $id
        For           = $forAddress
        Via           = $via
        Date          = (ConvertFrom-MailDate -Text $dateRaw)
        Delay         = $null
        Provider      = (Get-MailProvider -Hosts @($hostsForProvider))
        # Written by the receiving system itself. Only the topmost Received line
        # qualifies; every line below was already in the message and is an
        # unverified claim of the sender.
        Attested      = $false
        Raw           = $Raw
    }
}
