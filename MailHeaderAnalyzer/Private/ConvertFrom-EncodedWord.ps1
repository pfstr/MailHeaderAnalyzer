# RFC 2047 encoded-words and Unicode direction controls.

function ConvertFrom-QuotedPrintableWord {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)

    $out = New-Object System.Collections.Generic.List[byte]
    for ($i = 0; $i -lt $Text.Length; $i++) {
        $ch = $Text[$i]
        if ($ch -eq '_') { $out.Add(0x20); continue }
        if ($ch -eq '=' -and ($i + 2) -lt $Text.Length -and $Text.Substring($i + 1, 2) -match '^[0-9a-fA-F]{2}$') {
            $out.Add([Convert]::ToByte($Text.Substring($i + 1, 2), 16))
            $i += 2
            continue
        }
        $out.Add([byte]([int][char]$ch -band 0xff))
    }
    return ,$out.ToArray()
}

function ConvertFrom-EncodedWord {
    <#
    .SYNOPSIS
        Decodes RFC 2047 encoded-words (B and Q) in a header value.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrEmpty($Text)) { return $Text }

    # Adjacent encoded-words: the whitespace between them is dropped (RFC 2047 section 6.2).
    $joined = [regex]::Replace($Text, '(=\?[^?\s]+\?[BbQq]\?[^?]*\?=)\s+(?==\?)', '$1')

    $evaluator = [System.Text.RegularExpressions.MatchEvaluator] {
        param($m)
        # RFC 2231 allows a language suffix on the charset ("utf-8*de").
        $charset = [regex]::Replace($m.Groups[1].Value, '\*.*$', '')
        $encodingKind = $m.Groups[2].Value.ToUpperInvariant()
        $data = $m.Groups[3].Value
        try {
            if ($encodingKind -eq 'B') {
                $bytes = [Convert]::FromBase64String(([regex]::Replace($data, '\s+', '')))
            } else {
                $bytes = ConvertFrom-QuotedPrintableWord -Text $data
            }
            $encoding = [System.Text.Encoding]::GetEncoding($charset)
            return $encoding.GetString($bytes)
        } catch {
            return $m.Value
        }
    }

    return [regex]::Replace($joined, '=\?([^?\s]+)\?([BbQq])\?([^?]*)\?=', $evaluator)
}

# Bidi controls: LRM/RLM, ALM, the embedded overrides U+202A to U+202E and
# the isolates U+2066 to U+2069. "Invoice <U+202E>fdp.exe" otherwise reads
# as "Invoice exe.pdf": exactly the deception this tool exposes.
# Written as escapes on purpose: the characters themselves would reorder this
# source file when read (Trojan Source).
$script:BidiPattern = '[\u200E\u200F\u061C\u202A-\u202E\u2066-\u2069]'

function Test-BidiControl {
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()][AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrEmpty($Text)) { return $false }
    return [regex]::IsMatch($Text, $script:BidiPattern)
}

function Show-ControlCharacter {
    <#
    .SYNOPSIS
        Replaces direction control characters with their code point notation.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    if (-not [regex]::IsMatch($Text, $script:BidiPattern)) { return $Text }
    $evaluator = [System.Text.RegularExpressions.MatchEvaluator] {
        param($m)
        return ('<U+{0:X4}>' -f [int][char]$m.Value[0])
    }
    return [regex]::Replace($Text, $script:BidiPattern, $evaluator)
}
