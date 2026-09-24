# Domain helpers: organisational domain (heuristic without a full public suffix list),
# normalisation, exact and subdomain matches, DMARC alignment, address parsing.

$script:MultiLabelSuffixes = @(
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'net.uk', 'ltd.uk', 'plc.uk',
    'com.au', 'net.au', 'org.au', 'co.nz', 'com.br', 'com.mx', 'com.ar',
    'com.tr', 'com.cn', 'com.tw', 'com.hk', 'com.sg', 'co.jp', 'or.jp', 'ne.jp',
    'co.in', 'co.za', 'com.pl', 'co.il', 'com.ua'
)

function Get-OrganizationalDomain {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Domain)

    $parts = ($Domain.ToLowerInvariant() -replace '\.$', '') -split '\.'
    if ($parts.Count -le 2) { return ($parts -join '.') }
    $last2 = $parts[-2..-1] -join '.'
    if ($script:MultiLabelSuffixes -contains $last2) { return ($parts[-3..-1] -join '.') }
    return $last2
}

function ConvertTo-NormalizedDomain {
    <#
    .SYNOPSIS
        Lower-case, trimmed, without trailing dot or angle brackets. $null if nothing comparable remains.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][AllowEmptyString()][string]$Domain)

    if ([string]::IsNullOrEmpty($Domain)) { return $null }
    $s = $Domain.Trim().ToLowerInvariant()
    $s = [regex]::Replace($s, '^[<"'']+|[>"'',;]+$', '')
    $s = [regex]::Replace($s, '\.+$', '')
    if (-not $s) { return $null }
    return $s
}

function Test-SameDomain {
    <#
    .SYNOPSIS
        Exact domain comparison. No substring, no pattern.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()][string]$A, [AllowNull()][string]$B)

    $x = ConvertTo-NormalizedDomain -Domain $A
    $y = ConvertTo-NormalizedDomain -Domain $B
    return ($null -ne $x -and $x -eq $y)
}

function Test-HostMatch {
    <#
    .SYNOPSIS
        Same domain or real subdomain, always at a dot boundary.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()][string]$A, [AllowNull()][string]$B)

    $x = ConvertTo-NormalizedDomain -Domain $A
    $y = ConvertTo-NormalizedDomain -Domain $B
    if ($null -eq $x -or $null -eq $y) { return $false }
    if ($x -eq $y) { return $true }
    return ($x.EndsWith('.' + $y) -or $y.EndsWith('.' + $x))
}

function Get-DmarcAlignment {
    <#
    .SYNOPSIS
        Strict, Relaxed or None; $null when one side is missing.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][string]$A, [AllowNull()][string]$B)

    if (-not $A -or -not $B) { return $null }
    $x = $A.ToLowerInvariant() -replace '\.$', ''
    $y = $B.ToLowerInvariant() -replace '\.$', ''
    if ($x -eq $y) { return 'Strict' }
    if ((Get-OrganizationalDomain -Domain $x) -eq (Get-OrganizationalDomain -Domain $y)) { return 'Relaxed' }
    return 'None'
}

function ConvertFrom-MailAddress {
    <#
    .SYNOPSIS
        Display name, address and domain from a From/Reply-To/Return-Path value.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)

    $decoded = ([regex]::Replace((ConvertFrom-EncodedWord -Text $Value), '\s+', ' ')).Trim()
    $m = [regex]::Match($decoded, '<([^<>\s@]+@[^<>\s@]+)>')
    $address = $null
    if ($m.Success) { $address = $m.Groups[1].Value }
    else {
        $bare = [regex]::Match($decoded, '[\w.+=-]+@[\w.-]+')
        if ($bare.Success) { $address = $bare.Value }
    }
    $name = $null
    if ($m.Success -and $m.Index -gt 0) {
        $name = $decoded.Substring(0, $m.Index).Trim()
        $name = [regex]::Replace($name, '^"(.*)"$', '$1').Trim()
        if (-not $name) { $name = $null }
    }
    $domain = $null
    if ($address) {
        $domain = ($address -split '@')[-1].ToLowerInvariant().TrimEnd('>', ';', ',')
        if (-not $domain) { $domain = $null }
    }
    $display = $decoded
    if ($name -and $address) { $display = '{0} <{1}>' -f $name, $address }
    elseif ($address) { $display = $address }

    [pscustomobject]@{
        PSTypeName = 'MailHeaderAnalyzer.Address'
        Name       = $name
        Address    = $address
        Domain     = $domain
        Display    = $display
    }
}
