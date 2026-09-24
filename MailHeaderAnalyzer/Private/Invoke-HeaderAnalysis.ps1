# Core analysis: builds the analysis object from parsed fields. No DOM, no network.

# Header fields RFC 5322 section 3.6 limits to at most one instance.
$script:SingletonFields = @('From', 'Sender', 'Reply-To', 'To', 'Cc', 'Bcc',
    'Subject', 'Date', 'Message-ID', 'Return-Path', 'In-Reply-To', 'References')

# Upper bound for evaluated Received lines. A real delivery needs fewer than 30
# stations; RFC 5321 section 6.3 recommends 100 as loop protection. Counted from
# the top, i.e. from delivery: the youngest stations are the reliable ones.
$script:MaxHops = 200

$script:CompAuthReasonMeaning = @{
    '000' = 'failed explicit authentication: DMARC fail with a reject or quarantine policy'
    '001' = 'failed implicit authentication: the sending domain publishes no authentication records'
    '002' = 'the organization has a policy for the sender/domain pair that prohibits spoofed messages'
    '010' = 'DMARC fail with reject or quarantine, and the sending domain is one of your accepted domains'
    '1'   = 'passed authentication'
    '2'   = 'soft-passed implicit authentication'
    '3'   = 'not checked for composite authentication'
    '4'   = 'bypassed composite authentication (for example intra-organization or allow list)'
    '6'   = 'failed implicit authentication, and the sending domain is one of your accepted domains'
    '7'   = 'passed authentication'
    '9'   = 'bypassed composite authentication'
}

function Get-CompAuthReasonMeaning {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][AllowEmptyString()][string]$Reason)

    if (-not $Reason) { return $null }
    if ($script:CompAuthReasonMeaning.ContainsKey($Reason)) { return $script:CompAuthReasonMeaning[$Reason] }
    $bucket = $Reason.Substring(0, 1)
    if ($script:CompAuthReasonMeaning.ContainsKey($bucket)) { return $script:CompAuthReasonMeaning[$bucket] }
    return $null
}

function New-Finding {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Creates an in-memory object only.')]
    param(
        [Parameter(Mandatory)][ValidateSet('Info', 'Warning', 'Fail')][string]$Severity,
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Message
    )
    [pscustomobject]@{
        PSTypeName = 'MailHeaderAnalyzer.Finding'
        Severity   = $Severity
        Code       = $Code
        Message    = $Message
    }
}

function Invoke-HeaderAnalysis {
    [CmdletBinding()]
    [OutputType('MailHeaderAnalyzer.Analysis')]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [string]$Source = 'Text'
    )

    $split = Split-MailHeader -Text $Text
    $fields = @($split.Fields)
    $findings = New-Object System.Collections.Generic.List[object]

    # Hops: in the header the last one is on top; chronologically it is the other way round.
    $received = @(Get-HeaderField -Fields $fields -Name 'Received')
    $hopOverflow = [math]::Max(0, $received.Count - $script:MaxHops)
    $hopList = New-Object System.Collections.Generic.List[object]
    $limit = [math]::Min($received.Count, $script:MaxHops)
    for ($i = $limit - 1; $i -ge 0; $i--) {
        $hopList.Add((ConvertFrom-ReceivedHeader -Value $received[$i].Value -Raw $received[$i].Raw))
    }
    $hops = $hopList.ToArray()
    for ($i = 0; $i -lt $hops.Count; $i++) {
        $hops[$i].Index = $i + 1
        # Only the line added last comes from the receiving system.
        $hops[$i].Attested = ($i -eq $hops.Count - 1)
    }
    $hasSkew = $false
    $slowestIndex = -1
    $slowest = -1
    for ($i = 1; $i -lt $hops.Count; $i++) {
        $a = $hops[$i - 1].Date
        $b = $hops[$i].Date
        if ($null -ne $a -and $null -ne $b) {
            $seconds = [math]::Round(($b - $a).TotalSeconds)
            $hops[$i].Delay = [timespan]::FromSeconds($seconds)
            if ($seconds -lt 0) { $hasSkew = $true }
            if ($seconds -gt $slowest) { $slowest = $seconds; $slowestIndex = $i }
        }
    }
    $dated = @($hops | Where-Object { $null -ne $_.Date })
    $totalDuration = $null
    if ($dated.Count -ge 2) {
        $totalDuration = [timespan]::FromSeconds([math]::Round(($dated[-1].Date - $dated[0].Date).TotalSeconds))
    }

    $authResults = @(
        @(Get-HeaderField -Fields $fields -Name 'Authentication-Results') +
        @(Get-HeaderField -Fields $fields -Name 'Authentication-Results-Original')
    ) | ForEach-Object { ConvertFrom-AuthenticationResults -Field $_ }
    $authResults = @($authResults)

    $spfField = Get-HeaderField -Fields $fields -Name 'Received-SPF' -First
    $receivedSpf = $null
    if ($null -ne $spfField) { $receivedSpf = ConvertFrom-ReceivedSpf -Field $spfField }

    # Check the origin of verification lines against the delivery chain: a line
    # whose authserv-id never appears as "by" host can be written by anyone.
    $byHosts = @($hops | ForEach-Object { ConvertTo-NormalizedDomain -Domain $_.ByHost } | Where-Object { $_ })
    $deliveredBy = $null
    if ($hops.Count -gt 0) { $deliveredBy = ConvertTo-NormalizedDomain -Domain $hops[-1].ByHost }
    foreach ($set in $authResults) { $set.Trust = Get-AuthTrust -AuthServId $set.AuthServId -ByHosts $byHosts }

    # If there is a verified line, only that one counts (RFC 8601 section 5).
    $trusted = @($authResults | Where-Object { $_.Trust -eq 'Matched' })
    $ranked = $authResults
    if ($trusted.Count -gt 0) { $ranked = $trusted }
    $summary = [ordered]@{ spf = $null; dkim = $null; dmarc = $null; arc = $null; compauth = $null }
    foreach ($set in $ranked) {
        foreach ($m in $set.Methods) {
            if ($summary.Contains($m.Method) -and $null -eq $summary[$m.Method]) { $summary[$m.Method] = $m }
        }
    }
    $authoritative = $null
    foreach ($set in $ranked) { if ($set.Methods.Count -gt 0) { $authoritative = $set; break } }
    $withMethods = @($authResults | Where-Object { $_.Methods.Count -gt 0 })
    $origins = @($withMethods | ForEach-Object { $n = ConvertTo-NormalizedDomain -Domain $_.AuthServId; if ($n) { $n } else { '' } } | Sort-Object -Unique)
    $authMixedOrigins = $origins.Count -gt 1

    $receivedSpfTrust = 'None'
    if ($null -ne $receivedSpf) {
        $receiver = $null
        if ($receivedSpf.Properties.Contains('receiver')) { $receiver = $receivedSpf.Properties['receiver'] }
        $receivedSpfTrust = Get-AuthTrust -AuthServId $receiver -ByHosts $byHosts
    }
    $spfFromReceivedSpf = ($null -eq $summary['spf'] -and $null -ne $receivedSpf)
    if ($spfFromReceivedSpf) {
        $summary['spf'] = [pscustomobject]@{
            PSTypeName = 'MailHeaderAnalyzer.AuthMethod'
            Method     = 'spf'
            Result     = $receivedSpf.Result
            Properties = $receivedSpf.Properties
            Comments   = $receivedSpf.Comments
        }
    }

    # DKIM signatures; receiver result matched via header.d (and header.s if present).
    $dkimResults = @($ranked | ForEach-Object { $_.Methods } | Where-Object { $_.Method -eq 'dkim' })
    $usedResults = New-Object System.Collections.Generic.List[object]
    $now = [datetime]::UtcNow
    $epoch = New-Object DateTime (1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
    $dkimSignatures = @(Get-HeaderField -Fields $fields -Name 'DKIM-Signature') | ForEach-Object {
        $tags = ConvertFrom-TagList -Value $_.Value
        $d = $null
        if ($tags.Contains('d')) { $d = $tags['d'].ToLowerInvariant() }
        $s = $null
        if ($tags.Contains('s')) { $s = $tags['s'].ToLowerInvariant() }
        $match = $null
        foreach ($r in $dkimResults) {
            if ($usedResults.Contains($r)) { continue }
            $rd = $null
            if ($r.Properties.Contains('header.d')) { $rd = $r.Properties['header.d'].ToLowerInvariant() }
            $rs = $null
            if ($r.Properties.Contains('header.s')) { $rs = $r.Properties['header.s'].ToLowerInvariant() }
            if (-not $rd -or $rd -ne $d) { continue }
            if ($rs -and $s -and $rs -ne $s) { continue }
            $match = $r
            break
        }
        $receiverResult = $null
        if ($null -ne $match) {
            $usedResults.Add($match)
            if ($match.Result -eq 'pass') { $receiverResult = 'pass' } else { $receiverResult = 'fail' }
        }
        $expires = $null
        if ($tags.Contains('x') -and $tags['x'] -match '^\d+$') { $expires = $epoch.AddSeconds([double]$tags['x']) }
        $timestamp = $null
        if ($tags.Contains('t') -and $tags['t'] -match '^\d+$') { $timestamp = $epoch.AddSeconds([double]$tags['t']) }
        $signedHeaders = @()
        if ($tags.Contains('h')) { $signedHeaders = @($tags['h'] -split ':' | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ }) }
        $algorithm = $null
        if ($tags.Contains('a')) { $algorithm = $tags['a'] }
        $canonicalization = $null
        if ($tags.Contains('c')) { $canonicalization = $tags['c'] }
        $bodyLength = $null
        if ($tags.Contains('l')) { $bodyLength = $tags['l'] }
        [pscustomobject]@{
            PSTypeName       = 'MailHeaderAnalyzer.DkimSignature'
            Domain           = $d
            Selector         = $s
            Algorithm        = $algorithm
            Canonicalization = $canonicalization
            SignedHeaders    = $signedHeaders
            BodyLength       = $bodyLength
            Timestamp        = $timestamp
            Expires          = $expires
            ReceiverResult   = $receiverResult
            Tags             = $tags
            Raw              = $_.Raw
        }
    }
    $dkimSignatures = @($dkimSignatures)

    # ARC chain grouped from the seals.
    $arcMap = @{}
    foreach ($seal in @(Get-HeaderField -Fields $fields -Name 'ARC-Seal')) {
        $t = ConvertFrom-TagList -Value $seal.Value
        $i = 0
        if ($t.Contains('i') -and $t['i'] -match '^\d+$') { $i = [int]$t['i'] }
        $sealDomain = $null
        if ($t.Contains('d')) { $sealDomain = $t['d'] }
        $cv = $null
        if ($t.Contains('cv')) { $cv = $t['cv'].ToLowerInvariant() }
        $arcMap[$i] = [pscustomobject]@{
            PSTypeName = 'MailHeaderAnalyzer.ArcInstance'
            Instance   = $i
            SealDomain = $sealDomain
            ChainValidation = $cv
            Results    = $null
            Methods    = @()
        }
    }
    foreach ($aar in @(Get-HeaderField -Fields $fields -Name 'ARC-Authentication-Results')) {
        $im = [regex]::Match($aar.Value, '^\s*i\s*=\s*(\d+)')
        $i = 0
        if ($im.Success) { $i = [int]$im.Groups[1].Value }
        if ($arcMap.ContainsKey($i)) {
            $inner = [regex]::Replace($aar.Value, '^\s*i\s*=\s*\d+\s*;\s*', '')
            $arcMap[$i].Results = $inner
            $parsed = ConvertFrom-AuthenticationResults -Field ([pscustomobject]@{ Name = $aar.Name; Value = $inner; Raw = $aar.Raw })
            $arcMap[$i].Methods = @($parsed.Methods)
        }
    }
    $arc = @($arcMap.Values | Sort-Object Instance)
    $arcValid = $null
    if ($arc.Count -gt 0) {
        $arcValid = $true
        foreach ($inst in $arc) {
            if ($inst.Instance -eq 1) { if ($inst.ChainValidation -ne 'none' -and $inst.ChainValidation -ne 'pass') { $arcValid = $false } }
            elseif ($inst.ChainValidation -ne 'pass') { $arcValid = $false }
        }
    }

    $fromField = Get-HeaderField -Fields $fields -Name 'From' -First
    $from = $null
    if ($null -ne $fromField) { $from = ConvertFrom-MailAddress -Value $fromField.Value }
    $replyToField = Get-HeaderField -Fields $fields -Name 'Reply-To' -First
    $replyTo = $null
    if ($null -ne $replyToField) { $replyTo = ConvertFrom-MailAddress -Value $replyToField.Value }
    $returnPathField = Get-HeaderField -Fields $fields -Name 'Return-Path' -First
    $returnPath = $null
    if ($null -ne $returnPathField) { $returnPath = ConvertFrom-MailAddress -Value $returnPathField.Value }
    $subjectField = Get-HeaderField -Fields $fields -Name 'Subject' -First
    $subject = $null
    if ($null -ne $subjectField) { $subject = ConvertFrom-EncodedWord -Text $subjectField.Value }

    $mailFromDomain = $null
    if ($null -ne $summary['spf'] -and $summary['spf'].Properties.Contains('smtp.mailfrom')) {
        $mailFromDomain = ($summary['spf'].Properties['smtp.mailfrom'] -split '@')[-1].ToLowerInvariant()
    } elseif ($null -ne $returnPath) {
        $mailFromDomain = $returnPath.Domain
    }

    $bidiFields = @($fields | Where-Object { Test-BidiControl -Text $_.Raw } | ForEach-Object { $_.Name } | Sort-Object -Unique)
    $duplicates = @(foreach ($name in $script:SingletonFields) {
        $values = @(Get-HeaderField -Fields $fields -Name $name | ForEach-Object { $_.Value })
        if ($values.Count -gt 1) { [pscustomobject]@{ Name = $name; Values = $values } }
    })

    $fromDomain = $null
    if ($null -ne $from) { $fromDomain = $from.Domain }
    $dkimDomain = $null
    if ($null -ne $summary['dkim'] -and $summary['dkim'].Properties.Contains('header.d')) { $dkimDomain = $summary['dkim'].Properties['header.d'] }
    $spfAlignment = Get-DmarcAlignment -A $fromDomain -B $mailFromDomain
    $dkimAlignment = Get-DmarcAlignment -A $fromDomain -B $dkimDomain

    $exchange = Get-ExchangeClassification -Fields $fields
    $spam = Get-SpamAssessment -Fields $fields

    $listUnsubscribe = Get-HeaderValue -Fields $fields -Name 'List-Unsubscribe'
    $listPost = Get-HeaderValue -Fields $fields -Name 'List-Unsubscribe-Post'
    $listId = Get-HeaderValue -Fields $fields -Name 'List-Id'
    $list = $null
    if ($listUnsubscribe -or $listId) {
        $list = [pscustomobject]@{
            PSTypeName  = 'MailHeaderAnalyzer.ListInfo'
            ListId      = $listId
            Unsubscribe = $listUnsubscribe
            OneClick    = ($null -ne $listPost -and $listPost -match 'One-Click')
        }
    }

    $result = { param($key) if ($null -ne $summary[$key]) { return $summary[$key].Result }; return $null }
    $authTrust = 'None'
    if ($null -ne $authoritative) { $authTrust = $authoritative.Trust }

    # ---- Findings -------------------------------------------------------
    foreach ($dup in $duplicates) {
        $findings.Add((New-Finding -Severity Warning -Code 'DuplicateField' -Message ('The header field {0} occurs {1} times. RFC 5322 section 3.6 allows exactly one; several lines are a known spoofing pattern because mail clients and filters may pick different ones.' -f $dup.Name, $dup.Values.Count)))
    }
    if ($bidiFields.Count -gt 0) {
        $findings.Add((New-Finding -Severity Warning -Code 'BidiControls' -Message ('Unicode direction controls in these header fields: {0}. Such characters reverse the reading direction and make, for example, "fdp.exe" appear as "exe.pdf".' -f ($bidiFields -join ', '))))
    }
    if ($hopOverflow -gt 0) {
        $findings.Add((New-Finding -Severity Warning -Code 'HopOverflow' -Message ('{0} Received lines beyond the limit of {1} were not evaluated.' -f $hopOverflow, $script:MaxHops)))
    }
    if ($authTrust -eq 'Unmatched') {
        $findings.Add((New-Finding -Severity Warning -Code 'AuthUnverified' -Message ('The verification results carry the identifier {0}, which does not appear anywhere in the delivery chain. A sender can prepend such a line themselves; the results are not evidence.' -f $authoritative.AuthServId)))
    }
    if ($authMixedOrigins) {
        $findings.Add((New-Finding -Severity Warning -Code 'AuthMixedOrigins' -Message 'Verification results of several origins are present. Only the line of the receiving organization is authoritative.'))
    }
    if ($receivedSpfTrust -eq 'Unmatched') {
        $findings.Add((New-Finding -Severity Warning -Code 'ReceivedSpfForeign' -Message ('The Received-SPF line names {0} as the checking server; that host does not appear in the delivery chain.' -f $receivedSpf.Properties['receiver'])))
    }
    if ($spfFromReceivedSpf) {
        $findings.Add((New-Finding -Severity Info -Code 'ReceivedSpfOnly' -Message 'The SPF result comes only from a Received-SPF line, not from an Authentication-Results line of the receiving server.'))
    }
    if ($null -eq $summary['spf'] -and $null -eq $summary['dkim'] -and $null -eq $summary['dmarc']) {
        $findings.Add((New-Finding -Severity Info -Code 'NoAuthResults' -Message 'No Authentication-Results found: the receiving server left no verification results in the header.'))
    }
    $dmarcResult = & $result 'dmarc'
    if ($dmarcResult -eq 'fail') {
        $findings.Add((New-Finding -Severity Fail -Code 'DmarcFail' -Message 'DMARC failed according to the receiving server: depending on the policy the message could have been rejected or quarantined.'))
    }
    $spfResult = & $result 'spf'
    if ($spfResult -in @('fail', 'softfail', 'permerror', 'temperror')) {
        $findings.Add((New-Finding -Severity Warning -Code 'SpfNotPass' -Message ('SPF result: {0}.' -f $spfResult)))
    }
    $dkimResult = & $result 'dkim'
    if ($dkimResult -in @('fail', 'permerror', 'temperror')) {
        $arcWitness = $false
        foreach ($inst in $arc) {
            foreach ($m in $inst.Methods) {
                if ($m.Method -eq 'dkim' -and $m.Result -eq 'pass' -and $m.Properties.Contains('header.d') -and (Test-SameDomain -A $m.Properties['header.d'] -B $dkimDomain)) { $arcWitness = $true }
            }
        }
        if ($arcWitness) {
            $findings.Add((New-Finding -Severity Info -Code 'DkimBrokenAfterForward' -Message 'DKIM failed at the receiver, but an ARC seal attests that the signature was valid earlier: typical for a forwarding or mailing list that modified the message.'))
        } else {
            $findings.Add((New-Finding -Severity Warning -Code 'DkimNotPass' -Message ('DKIM result: {0}.' -f $dkimResult)))
        }
    }
    foreach ($sig in $dkimSignatures) {
        if ($sig.Algorithm -and $sig.Algorithm -match 'sha1') {
            $findings.Add((New-Finding -Severity Warning -Code 'DkimWeakHash' -Message ('DKIM signature of {0} uses {1}: SHA-1 is deprecated (RFC 8301), receivers may ignore the signature.' -f $sig.Domain, $sig.Algorithm)))
        }
        if ($null -ne $sig.BodyLength) {
            $findings.Add((New-Finding -Severity Warning -Code 'DkimBodyLength' -Message ('DKIM signature of {0} limits the signed body length (l={1}): content appended afterwards is not covered.' -f $sig.Domain, $sig.BodyLength)))
        }
        if ($null -ne $sig.Expires -and $sig.Expires -lt $now) {
            $findings.Add((New-Finding -Severity Warning -Code 'DkimExpired' -Message ('DKIM signature of {0} expired on {1:u}.' -f $sig.Domain, $sig.Expires)))
        }
        if ($sig.SignedHeaders.Count -gt 0 -and $sig.SignedHeaders -notcontains 'from') {
            $findings.Add((New-Finding -Severity Warning -Code 'DkimFromUnsigned' -Message ('DKIM signature of {0} does not cover the From field (RFC 6376 requires it).' -f $sig.Domain)))
        }
    }
    if ($hasSkew) {
        $findings.Add((New-Finding -Severity Info -Code 'ClockSkew' -Message 'At least one hop carries an earlier timestamp than its predecessor: clock skew between the servers, the delays are only approximate.'))
    }
    if ($null -ne $replyTo -and $null -ne $from -and $replyTo.Domain -and $from.Domain -and -not (Test-SameDomain -A $replyTo.Domain -B $from.Domain)) {
        $findings.Add((New-Finding -Severity Info -Code 'ReplyToMismatch' -Message ('Reply-To domain ({0}) differs from the From domain ({1}). Replies go elsewhere; common with newsletters, also a phishing pattern.' -f $replyTo.Domain, $from.Domain)))
    }
    if ($spfAlignment -eq 'None') {
        $findings.Add((New-Finding -Severity Info -Code 'SpfNotAligned' -Message ('The envelope sender domain ({0}) is not aligned with the From domain ({1}): SPF cannot contribute to DMARC.' -f $mailFromDomain, $fromDomain)))
    }
    if ($null -ne $exchange) {
        if ($exchange.WrongTenantAttribution) {
            $findings.Add((New-Finding -Severity Warning -Code 'ExchangeWrongTenant' -Message 'The message was attributed to a different tenant (X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp). Classic cause: another tenant''s inbound connector uses the same TLS certificate or sender IPs.'))
        }
        if ($exchange.CrossPremisesHeadersFiltered) {
            $findings.Add((New-Finding -Severity Warning -Code 'ExchangeHeadersFiltered' -Message 'The send connector stripped the cross-premises headers: the message loses its internal classification (see KB3212872).'))
        }
        if ($exchange.AuthMechanism -and $exchange.AuthMechanism -match '^0*10$') {
            $findings.Add((New-Finding -Severity Warning -Code 'ExchangeExternallySecured' -Message 'AuthMechanism 10: the message entered through an "externally secured" receive connector and bypassed EOP filtering as Internal.'))
        }
    }
    if ($null -ne $spam) {
        if ($spam.Category -and $spam.Category -ne 'NONE') {
            $findings.Add((New-Finding -Severity Warning -Code 'SpamCategory' -Message ('Microsoft classified the message as {0} ({1}).' -f $spam.Category, $spam.CategoryMeaning)))
        }
        if ($spam.Scl -and [int]$spam.Scl -ge 5) {
            $findings.Add((New-Finding -Severity Warning -Code 'SpamConfidence' -Message ('Spam confidence level {0}: {1}.' -f $spam.Scl, $spam.SclMeaning)))
        }
    }

    $compAuth = $summary['compauth']
    $compAuthReason = $null
    if ($null -ne $compAuth -and $compAuth.Properties.Contains('reason')) { $compAuthReason = $compAuth.Properties['reason'] }

    [pscustomobject]@{
        PSTypeName            = 'MailHeaderAnalyzer.Analysis'
        Source                = $Source
        Subject               = $subject
        From                  = $from
        ReplyTo               = $replyTo
        ReturnPath            = $returnPath
        Date                  = (ConvertFrom-MailDate -Text (Get-HeaderValue -Fields $fields -Name 'Date'))
        MessageId             = (Get-HeaderValue -Fields $fields -Name 'Message-ID')
        MailFromDomain        = $mailFromDomain
        Spf                   = (& $result 'spf')
        Dkim                  = (& $result 'dkim')
        Dmarc                 = (& $result 'dmarc')
        Arc                   = (& $result 'arc')
        CompAuth              = (& $result 'compauth')
        CompAuthReason        = $compAuthReason
        CompAuthReasonMeaning = (Get-CompAuthReasonMeaning -Reason $compAuthReason)
        AuthTrust             = $authTrust
        AuthServId            = $(if ($null -ne $authoritative) { $authoritative.AuthServId } else { $null })
        AuthenticationResults = $authResults
        ReceivedSpf           = $receivedSpf
        SpfAlignment          = $spfAlignment
        DkimAlignment         = $dkimAlignment
        Hops                  = $hops
        HopCount              = $hops.Count
        TotalDuration         = $totalDuration
        SlowestHopIndex       = $(if ($slowestIndex -ge 0) { $slowestIndex + 1 } else { $null })
        HasClockSkew          = $hasSkew
        DeliveredBy           = $deliveredBy
        DkimSignatures        = $dkimSignatures
        ArcChain              = $arc
        ArcValid              = $arcValid
        Exchange              = $exchange
        Spam                  = $spam
        List                  = $list
        Findings              = $findings.ToArray()
        Fields                = $fields
        HadBody               = $split.HadBody
    }
}
