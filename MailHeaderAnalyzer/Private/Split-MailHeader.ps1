function Split-MailHeader {
    <#
    .SYNOPSIS
        Splits raw header text into fields (unfolding, tolerant of hard-wrapped copies).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Text
    )

    # Strip a byte order mark: exports from Windows tools and copies from Notepad
    # carry one regularly, and without this cut the first line fails the
    # field-name test and silently disappears.
    $normalized = [regex]::Replace($Text, '^\uFEFF', '')
    $normalized = [regex]::Replace($normalized, '\r\n?', "`n")
    $lines = $normalized -split "`n"

    $rawFields = New-Object System.Collections.Generic.List[string]
    $current = $null
    $hadBody = $false

    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ($line.Trim() -eq '') {
            # The first blank line after fields separates header and body (.eml pasted).
            if ($rawFields.Count -gt 0 -or $null -ne $current) {
                for ($j = $i + 1; $j -lt $lines.Count; $j++) {
                    if ($lines[$j].Trim() -ne '') { $hadBody = $true; break }
                }
                break
            }
            continue
        }
        if ($line -match '^[ \t]') {
            # Classic folding whitespace.
            if ($null -ne $current) { $current += "`n" + $line }
            continue
        }
        if ($line -match '^[\x21-\x39\x3B-\x7E]+:') {
            if ($null -ne $current) { $rawFields.Add($current) }
            $current = $line
            continue
        }
        # mbox separator "From ..." before the first field is skipped.
        if ($null -eq $current) { continue }
        # A line without field name and without leading whitespace: hard-wrapped
        # copy (for example from a mail client dialog); it belongs to the predecessor.
        $current += ' ' + $line.Trim()
    }
    if ($null -ne $current) { $rawFields.Add($current) }

    $fields = foreach ($raw in $rawFields) {
        $idx = $raw.IndexOf(':')
        [pscustomobject]@{
            PSTypeName = 'MailHeaderAnalyzer.HeaderField'
            Name       = $raw.Substring(0, $idx).Trim()
            Value      = ([regex]::Replace($raw.Substring($idx + 1), '\n[ \t]+', ' ')).Trim()
            Raw        = $raw
        }
    }

    [pscustomobject]@{
        Fields  = @($fields)
        HadBody = $hadBody
    }
}

function Get-HeaderField {
    <#
    .SYNOPSIS
        Returns the header fields with the given name (case-insensitive); -First returns only the first.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Fields,

        [Parameter(Mandatory)]
        [string]$Name,

        [switch]$First
    )

    $found = @($Fields | Where-Object { $_.Name -ieq $Name })
    if ($First) {
        if ($found.Count -gt 0) { return $found[0] }
        return $null
    }
    return $found
}

function Get-HeaderValue {
    <#
    .SYNOPSIS
        Value of the first field with the given name, or $null.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Fields,

        [Parameter(Mandatory)]
        [string]$Name
    )

    $field = Get-HeaderField -Fields $Fields -Name $Name -First
    if ($null -eq $field) { return $null }
    return $field.Value
}
