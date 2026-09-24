# RFC 5322 date-time including obsolete zone abbreviations. Returns a UTC [datetime] or $null.

$script:ObsoleteZones = @{
    UT = '+0000'; GMT = '+0000'; EST = '-0500'; EDT = '-0400'; CST = '-0600'
    CDT = '-0500'; MST = '-0700'; MDT = '-0600'; PST = '-0800'; PDT = '-0700'
}

function ConvertFrom-MailDate {
    [CmdletBinding()]
    [OutputType([datetime])]
    param([AllowNull()][AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }

    $t = [regex]::Replace($Text, '\([^()]*\)', ' ')
    $t = [regex]::Replace($t, '\([^()]*\)', ' ')
    $t = ([regex]::Replace($t, '\s+', ' ')).Trim()
    $zoneEvaluator = [System.Text.RegularExpressions.MatchEvaluator] {
        param($m)
        $zone = $script:ObsoleteZones[$m.Groups[1].Value.ToUpperInvariant()]
        if ($null -eq $zone) { return '+0000' }
        return $zone
    }
    $t = [regex]::Replace($t, '\b(UT|GMT|EST|EDT|CST|CDT|MST|MDT|PST|PDT)\b\s*$', $zoneEvaluator, 'IgnoreCase')

    # A numeric offset without colon ("+0200") is not accepted by every .NET parser: normalize it.
    $t = [regex]::Replace($t, '([+-])(\d{2})(\d{2})\s*$', '$1$2:$3')

    $parsed = [DateTimeOffset]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AllowWhiteSpaces -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
    if ([DateTimeOffset]::TryParse($t, [cultureinfo]::InvariantCulture, $styles, [ref]$parsed)) {
        return $parsed.UtcDateTime
    }

    $m = [regex]::Match($t, '(\d{1,2})\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+(\d{2,4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*([+-]\d{2}:?\d{2})?', 'IgnoreCase')
    if (-not $m.Success) { return $null }

    $months = @('jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec')
    $year = [int]$m.Groups[3].Value
    if ($year -lt 100) { if ($year -ge 70) { $year += 1900 } else { $year += 2000 } }
    $month = [array]::IndexOf($months, $m.Groups[2].Value.ToLowerInvariant()) + 1
    $second = 0
    if ($m.Groups[6].Success) { $second = [int]$m.Groups[6].Value }
    $offset = '+00:00'
    if ($m.Groups[7].Success) { $offset = $m.Groups[7].Value -replace ':', '' }
    $offset = $offset -replace ':', ''
    $sign = 1
    if ($offset[0] -eq '-') { $sign = -1 }
    $offsetMinutes = $sign * ([int]$offset.Substring(1, 2) * 60 + [int]$offset.Substring(3, 2))

    try {
        $utc = New-Object DateTime ($year, $month, [int]$m.Groups[1].Value, [int]$m.Groups[4].Value, [int]$m.Groups[5].Value, $second, [DateTimeKind]::Utc)
        return $utc.AddMinutes(-$offsetMinutes)
    } catch {
        return $null
    }
}

function Format-Duration {
    <#
    .SYNOPSIS
        Human-readable duration ("3 s", "2 min 10 s", "1 h 05 min").
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][int64]$Seconds)

    $s = [math]::Abs($Seconds)
    if ($s -lt 1) { $out = '< 1 s' }
    elseif ($s -lt 90) { $out = '{0} s' -f $s }
    elseif ($s -lt 3600) { $out = '{0} min {1} s' -f [math]::Floor($s / 60), ($s % 60) }
    elseif ($s -lt 86400) { $out = '{0} h {1:00} min' -f [math]::Floor($s / 3600), [math]::Floor(($s % 3600) / 60) }
    else { $out = '{0} d {1} h' -f [math]::Floor($s / 86400), [math]::Floor(($s % 86400) / 3600) }
    if ($Seconds -lt 0) { return '-' + $out }
    return $out
}
