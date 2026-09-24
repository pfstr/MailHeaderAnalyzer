# Spam filter headers: Microsoft Defender / EOP, SpamAssassin, Rspamd.
# The values are set by third parties, so they are decoded but never trusted.

$script:SclMeaning = @{
    '-1' = 'trusted: filtering bypassed (allow list, connection rule or internal sender)'
    '0'  = 'not spam'
    '1'  = 'not spam'
    '5'  = 'suspected spam: usually delivered to the junk folder'
    '6'  = 'suspected spam: usually delivered to the junk folder'
    '9'  = 'very likely spam: quarantine depending on policy'
}
$script:CatMeaning = @{
    NONE = 'no classification'; SPM = 'spam'; HSPM = 'spam (high confidence)'; PHSH = 'phishing'
    HPHSH = 'phishing (high confidence)'; MALW = 'malware'; SPOOF = 'spoofing'; DIMP = 'domain impersonation'
    UIMP = 'user impersonation'; GIMP = 'impersonation per mailbox intelligence'; BULK = 'bulk mail'
    AMP = 'malware caught by the anti-malware engine'; SAP = 'safe attachment (detonation)'
    FTBP = 'blocked by the attachment filter'; OSPM = 'outbound spam'; INTOS = 'intra-organization classified as phishing'
}
$script:SfvMeaning = @{
    NSPM = 'evaluated as not spam'; SPM = 'evaluated as spam'; BLK = "sender is on the recipient's block list"
    SKA = 'filtering skipped: sender on allow list'; SKB = 'filtering skipped: sender on block list'
    SKN = 'filtering skipped: pre-marked as not spam (e.g. transport rule)'; SKS = 'filtering skipped: pre-marked as spam'
    SKI = 'filtering skipped: intra-organization'; SKQ = 'released from quarantine'
}
$script:IpvMeaning = @{ CAL = 'submitting IP on the connection allow list'; NLI = 'IP without reputation entry' }
$script:DirMeaning = @{ INB = 'inbound'; OUT = 'outbound'; INT = 'internal' }

function ConvertFrom-ForefrontReport {
    <#
    .SYNOPSIS
        "CIP:203.0.113.25;CTRY:CH;..." into an ordered dictionary.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)

    $out = [ordered]@{}
    foreach ($part in ($Value -split ';')) {
        $idx = $part.IndexOf(':')
        if ($idx -le 0) { continue }
        $key = $part.Substring(0, $idx).Trim()
        if ($key -notmatch '^[A-Z]+$') { continue }
        $out[$key] = $part.Substring($idx + 1).Trim()
    }
    return $out
}

function Get-SpamAssassinTest {
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)

    $idx = $Value.ToLowerInvariant().IndexOf('tests=')
    if ($idx -lt 0) { return @() }
    $collected = New-Object System.Collections.Generic.List[string]
    foreach ($token in ($Value.Substring($idx + 6) -split '\s+')) {
        # The next "key=" ends the list.
        if ($token -match '^[A-Za-z_][A-Za-z0-9_]*=') { break }
        $collected.Add($token)
    }
    return @(($collected -join ' ') -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Get-RspamdSymbol {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)

    $out = New-Object System.Collections.Generic.List[object]
    foreach ($m in [regex]::Matches($Value, '[A-Z][A-Z0-9_]{2,}(\(([-\d.]+)\))?')) {
        if ($m.Groups[2].Success) {
            $out.Add([pscustomobject]@{ Name = $m.Value.Substring(0, $m.Value.IndexOf('(')); Score = $m.Groups[2].Value })
        }
    }
    return ,$out.ToArray()
}

function Get-SpamAssessment {
    <#
    .SYNOPSIS
        Decodes the spam filter headers present; $null when none are found.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Fields)

    $forefrontValue = Get-HeaderValue -Fields $Fields -Name 'X-Forefront-Antispam-Report'
    $antispamValue = Get-HeaderValue -Fields $Fields -Name 'X-Microsoft-Antispam'
    $spamStatus = Get-HeaderValue -Fields $Fields -Name 'X-Spam-Status'
    $rspamdValue = Get-HeaderValue -Fields $Fields -Name 'X-Spamd-Result'
    if (-not $rspamdValue) { $rspamdValue = Get-HeaderValue -Fields $Fields -Name 'X-Spam-Report' }

    if (-not $forefrontValue -and -not $antispamValue -and -not $spamStatus -and -not $rspamdValue) { return $null }

    $forefront = [ordered]@{}
    if ($forefrontValue) { $forefront = ConvertFrom-ForefrontReport -Value $forefrontValue }

    $scl = $null
    if ($forefront.Contains('SCL')) { $scl = $forefront['SCL'] }
    elseif ($antispamValue -and $antispamValue -match 'SCL:(-?\d+)') { $scl = $Matches[1] }
    $bcl = $null
    if ($antispamValue -and $antispamValue -match 'BCL:(\d+)') { $bcl = $Matches[1] }
    elseif ($forefront.Contains('BCL')) { $bcl = $forefront['BCL'] }

    $lookup = {
        param($table, $key)
        if ($null -eq $key) { return $null }
        if ($table.ContainsKey([string]$key)) { return $table[[string]$key] }
        return $null
    }

    $category = $null
    if ($forefront.Contains('CAT')) { $category = $forefront['CAT'] }
    $sfv = $null
    if ($forefront.Contains('SFV')) { $sfv = $forefront['SFV'] }
    $ipv = $null
    if ($forefront.Contains('IPV')) { $ipv = $forefront['IPV'] }
    $dir = $null
    if ($forefront.Contains('DIR')) { $dir = $forefront['DIR'] }
    $cip = $null
    if ($forefront.Contains('CIP')) { $cip = $forefront['CIP'] }
    $ctry = $null
    if ($forefront.Contains('CTRY')) { $ctry = $forefront['CTRY'] }

    $saScore = $null
    $saTests = @()
    if ($spamStatus) {
        if ($spamStatus -match 'score=(-?[\d.]+)') { $saScore = $Matches[1] }
        $saTests = Get-SpamAssassinTest -Value $spamStatus
    }
    $rspamdSymbols = @()
    if ($rspamdValue) { $rspamdSymbols = Get-RspamdSymbol -Value $rspamdValue }

    [pscustomobject]@{
        PSTypeName            = 'MailHeaderAnalyzer.SpamAssessment'
        Scl                   = $scl
        SclMeaning            = (& $lookup $script:SclMeaning $scl)
        Bcl                   = $bcl
        Category              = $category
        CategoryMeaning       = (& $lookup $script:CatMeaning $category)
        SpamFilterVerdict     = $sfv
        SpamFilterMeaning     = (& $lookup $script:SfvMeaning $sfv)
        IPVerdict             = $ipv
        IPVerdictMeaning      = (& $lookup $script:IpvMeaning $ipv)
        Direction             = $dir
        DirectionMeaning      = (& $lookup $script:DirMeaning $dir)
        ConnectingIP          = $cip
        Country               = $ctry
        Forefront             = $forefront
        SpamAssassinScore     = $saScore
        SpamAssassinTests     = @($saTests)
        RspamdSymbols         = @($rspamdSymbols)
    }
}
