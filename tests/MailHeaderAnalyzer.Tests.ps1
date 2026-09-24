BeforeAll {
    $script:ModulePath = Join-Path -Path $PSScriptRoot -ChildPath '..\MailHeaderAnalyzer\MailHeaderAnalyzer.psd1'
    Import-Module $script:ModulePath -Force
    $script:Fixtures = Join-Path -Path $PSScriptRoot -ChildPath 'fixtures'
    function Get-Fixture([string]$Name) { Join-Path -Path $script:Fixtures -ChildPath $Name }
}

Describe 'Module' {
    It 'exports exactly the two public cmdlets' {
        $exported = (Get-Module MailHeaderAnalyzer).ExportedFunctions.Keys | Sort-Object
        $exported | Should -Be @('ConvertTo-MailHeaderReport', 'Get-MailHeaderAnalysis')
    }

    It 'ships format views for the analysis object' {
        Get-FormatData -TypeName 'MailHeaderAnalyzer.Analysis' | Should -Not -BeNullOrEmpty
        Get-FormatData -TypeName 'MailHeaderAnalyzer.Hop' | Should -Not -BeNullOrEmpty
    }

    It 'contains no network or DNS calls (offline promise)' {
        $moduleDir = Split-Path -Path $script:ModulePath -Parent
        $source = Get-ChildItem -Path $moduleDir -Recurse -Include '*.ps1', '*.psm1' | Get-Content -Raw
        $source -join "`n" | Should -Not -Match 'Invoke-WebRequest|Invoke-RestMethod|Resolve-DnsName|System\.Net\.(Http|Dns|WebClient|Sockets)|nslookup'
    }
}

Describe 'Get-MailHeaderAnalysis: baseline Microsoft 365 message' {
    BeforeAll { $script:a = Get-MailHeaderAnalysis -Path (Get-Fixture 'baseline-m365.eml') }

    It 'orders the hops chronologically and attests only the last one' {
        $a.HopCount | Should -Be 3
        $a.Hops[0].ReverseDns | Should -Be 'client.example.net'
        $a.Hops[0].IPAddress | Should -Be '198.51.100.34'
        $a.Hops[0].ProtocolClass | Should -Be 'TlsAuthenticated'
        $a.Hops[2].ByHost | Should -Be 'ZR0P278MB0570.CHEP278.PROD.OUTLOOK.COM'
        @($a.Hops | Where-Object Attested).Count | Should -Be 1
        $a.Hops[2].Attested | Should -BeTrue
    }

    It 'reads TLS version, cipher and delays' {
        $a.Hops[1].TlsVersion | Should -Be 'TLS 1.3'
        $a.Hops[1].TlsCipher | Should -Be 'TLS_AES_256_GCM_SHA384'
        $a.Hops[1].Delay.TotalSeconds | Should -Be 41
        $a.TotalDuration.TotalSeconds | Should -Be 42
        $a.Hops[1].Provider | Should -Be 'Microsoft 365 (Exchange Online Protection)'
    }

    It 'summarizes the authentication results' {
        $a.Spf | Should -Be 'pass'
        $a.Dkim | Should -Be 'pass'
        $a.Dmarc | Should -Be 'pass'
        $a.CompAuth | Should -Be 'pass'
        $a.CompAuthReason | Should -Be '100'
        $a.AuthTrust | Should -Be 'Absent'
        $a.SpfAlignment | Should -Be 'Strict'
        $a.DkimAlignment | Should -Be 'Strict'
        $a.Findings.Count | Should -Be 0
    }

    It 'decodes the RFC 2047 subject and the addresses' {
        $a.Subject | Should -Be ('Service-Report f{0}r M{1}rz' -f [char]0xFC, [char]0xE4)
        $a.From.Name | Should -Be 'Beispiel Newsletter'
        $a.From.Domain | Should -Be 'example.org'
        $a.ReplyTo.Address | Should -Be 'support@example.org'
        $a.MailFromDomain | Should -Be 'example.org'
        $a.Date | Should -Be (Get-Date -Date '2026-08-03T09:14:27Z').ToUniversalTime()
    }

    It 'matches the DKIM signature with the receiver result' {
        $a.DkimSignatures.Count | Should -Be 1
        $a.DkimSignatures[0].Selector | Should -Be 'mail2026'
        $a.DkimSignatures[0].ReceiverResult | Should -Be 'pass'
        $a.DkimSignatures[0].SignedHeaders | Should -Contain 'from'
    }
}

Describe 'Get-MailHeaderAnalysis: Exchange hybrid and spam headers' {
    BeforeAll { $script:x = Get-MailHeaderAnalysis -Path (Get-Fixture 'sample-exchange-hybrid.eml') }

    It 'ignores the body of a .eml file' {
        $x.HadBody | Should -BeTrue
        $x.HopCount | Should -Be 5
    }

    It 'decodes the Exchange classification' {
        $x.Exchange | Should -Not -BeNullOrEmpty
        $x.Exchange.Directionality | Should -Be 'Incoming'
        $x.Exchange.AuthAs | Should -Be 'Anonymous'
        $x.Exchange.AuthMechanism | Should -Be '04'
        $x.Exchange.AuthMechanismMeaning | Should -Match 'not publicly documented'
        $x.Exchange.CrossTenantFromEntity | Should -Be 'Internet'
        $x.Exchange.OriginatorOrg | Should -Be 'example.org'
    }

    It 'decodes the Defender verdicts' {
        $x.Spam.Scl | Should -Be '1'
        $x.Spam.SclMeaning | Should -Be 'not spam'
        $x.Spam.Bcl | Should -Be '0'
        $x.Spam.Category | Should -Be 'NONE'
        $x.Spam.SpamFilterVerdict | Should -Be 'NSPM'
        $x.Spam.Country | Should -Be 'CH'
    }

    It 'reads the ARC chain and list headers' {
        $x.ArcChain.Count | Should -Be 1
        $x.ArcChain[0].SealDomain | Should -Be 'microsoft.com'
        $x.ArcValid | Should -BeTrue
        $x.List.OneClick | Should -BeTrue
    }
}

Describe 'Get-MailHeaderAnalysis: trust in verification results' {
    It 'accepts results whose authserv-id appears in the delivery chain' {
        $r = Get-MailHeaderAnalysis -Path (Get-Fixture 'f04-authresults-echt.eml')
        $r.AuthTrust | Should -Be 'Matched'
        $r.Findings.Code | Should -Not -Contain 'AuthUnverified'
    }

    It 'flags results with a foreign authserv-id as unverified' {
        $r = Get-MailHeaderAnalysis -Path (Get-Fixture 'f04-authresults-gefaelscht.eml')
        $r.AuthTrust | Should -Be 'Unmatched'
        $r.Findings.Code | Should -Contain 'AuthUnverified'
    }

    It 'prefers the verified line when a forged one is prepended' {
        $r = Get-MailHeaderAnalysis -Path (Get-Fixture 'f04-authresults-gefaelscht-plus-echt.eml')
        $r.AuthTrust | Should -Be 'Matched'
        $r.Dmarc | Should -Be 'fail'
        $r.Findings.Code | Should -Contain 'AuthMixedOrigins'
        $r.Findings.Code | Should -Contain 'DmarcFail'
    }

    It 'marks an SPF result that comes only from Received-SPF' {
        $r = Get-MailHeaderAnalysis -Path (Get-Fixture 'f04-received-spf-ohne-auth.eml')
        $r.Spf | Should -Be 'pass'
        $r.Findings.Code | Should -Contain 'ReceivedSpfOnly'
        $r.Findings.Code | Should -Contain 'ReceivedSpfForeign'
    }
}

Describe 'Get-MailHeaderAnalysis: anomalies' {
    It 'reports duplicate singleton fields' {
        $r = Get-MailHeaderAnalysis -Path (Get-Fixture 'f05-doppelte-absenderzeilen.eml')
        @($r.Findings | Where-Object Code -eq 'DuplicateField').Count | Should -BeGreaterOrEqual 1
    }

    It 'reports Unicode direction controls' {
        $r = Get-MailHeaderAnalysis -Path (Get-Fixture 'f06-bidi-rlo.eml')
        $r.Findings.Code | Should -Contain 'BidiControls'
    }

    It 'keeps forged hops below the attested one' {
        $r = Get-MailHeaderAnalysis -Path (Get-Fixture 'f08-gefaelschte-hops.eml')
        $r.HopCount | Should -Be 3
        $r.Hops[0].Attested | Should -BeFalse
        $r.Hops[-1].Attested | Should -BeTrue
    }

    It 'recognizes an ARC witness for a broken DKIM signature, but only for the same domain' {
        (Get-MailHeaderAnalysis -Path (Get-Fixture 'w1a02-arc-witness-echt.eml')).Findings.Code | Should -Contain 'DkimBrokenAfterForward'
        (Get-MailHeaderAnalysis -Path (Get-Fixture 'w1a02-arc-witness-substring.eml')).Findings.Code | Should -Contain 'DkimNotPass'
    }

    It 'does not let a hostile DKIM d= value stall the parser' {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $null = Get-MailHeaderAnalysis -Path (Get-Fixture 'w1a01-dkim-d-redos.eml')
        $sw.Stop()
        $sw.Elapsed.TotalSeconds | Should -BeLessThan 5
    }

    It 'strips a byte order mark before the first field' {
        $r = Get-MailHeaderAnalysis -Path (Get-Fixture 'w1a10-bom.eml')
        $r.Fields[0].Name | Should -Match '^[A-Za-z]'
        $r.HopCount | Should -BeGreaterThan 0
    }
}

Describe 'Get-MailHeaderAnalysis: input forms' {
    It 'accepts a string' {
        $text = [System.IO.File]::ReadAllText((Get-Fixture 'baseline-m365.eml'))
        (Get-MailHeaderAnalysis -Header $text).HopCount | Should -Be 3
    }

    It 'joins lines piped from Get-Content into one header' {
        (Get-Content -Path (Get-Fixture 'baseline-m365.eml') | Get-MailHeaderAnalysis).HopCount | Should -Be 3
    }

    It 'takes files from Get-ChildItem and reports the source' {
        $results = @(Get-ChildItem -Path $script:Fixtures -Filter '*.eml' | Get-MailHeaderAnalysis)
        $results.Count | Should -Be (Get-ChildItem -Path $script:Fixtures -Filter '*.eml').Count
        $results[0].Source | Should -Match '\.eml$'
    }

    It 'throws on empty input' {
        { Get-MailHeaderAnalysis -Header '' } | Should -Throw
    }

    It 'writes an error for a missing file' {
        { Get-MailHeaderAnalysis -Path (Get-Fixture 'does-not-exist.eml') -ErrorAction Stop } | Should -Throw
    }
}

Describe 'ConvertTo-MailHeaderReport' {
    BeforeAll { $script:a = Get-MailHeaderAnalysis -Path (Get-Fixture 'sample-exchange-hybrid.eml') }

    It 'renders Markdown with the chain as a table' {
        $md = $a | ConvertTo-MailHeaderReport
        $md | Should -Match '^# Email header analysis'
        $md | Should -Match '## Authentication'
        $md | Should -Match '\| 1 \| client\.example\.net'
        $md | Should -Match 'compauth: pass \(reason=100'
        $md | Should -Match 'Exchange hybrid classification'
        $md | Should -Match 'Generated by MailHeaderAnalyzer'
    }

    It 'renders plain text without Markdown markup' {
        $txt = $a | ConvertTo-MailHeaderReport -Format Text
        $txt | Should -Not -Match '^#'
        $txt | Should -Not -Match '\|'
        $txt | Should -Match 'client\.example\.net \(198\.51\.100\.34\) -> mail\.example\.org'
    }

    It 'keeps direction controls visible in the report' {
        $r = Get-MailHeaderAnalysis -Path (Get-Fixture 'f06-bidi-rlo.eml')
        $r | ConvertTo-MailHeaderReport | Should -Match '<U\+202E>'
    }
}

Describe 'Parsing helpers' {
    It 'parses RFC 5322 dates including obsolete zones' {
        InModuleScope MailHeaderAnalyzer {
            (ConvertFrom-MailDate -Text 'Mon, 3 Aug 2026 09:15:12 +0000') | Should -Be (Get-Date -Date '2026-08-03T09:15:12Z').ToUniversalTime()
            (ConvertFrom-MailDate -Text 'Mon, 3 Aug 2026 09:15:12 +0200 (CEST)') | Should -Be (Get-Date -Date '2026-08-03T07:15:12Z').ToUniversalTime()
            (ConvertFrom-MailDate -Text 'Mon, 3 Aug 2026 09:15:12 EST') | Should -Be (Get-Date -Date '2026-08-03T14:15:12Z').ToUniversalTime()
            (ConvertFrom-MailDate -Text 'not a date') | Should -BeNullOrEmpty
        }
    }

    It 'decodes B and Q encoded-words' {
        InModuleScope MailHeaderAnalyzer {
            ConvertFrom-EncodedWord -Text '=?UTF-8?B?U2VydmljZS1SZXBvcnQ=?=' | Should -Be 'Service-Report'
            ConvertFrom-EncodedWord -Text '=?iso-8859-1?Q?M=E4rz?=' | Should -Be ('M{0}rz' -f [char]0xE4)
            ConvertFrom-EncodedWord -Text '=?UTF-8?Q?a?= =?UTF-8?Q?b?=' | Should -Be 'ab'
        }
    }

    It 'derives organizational domains and compares hosts at dot boundaries' {
        InModuleScope MailHeaderAnalyzer {
            Get-OrganizationalDomain -Domain 'mail.example.co.uk' | Should -Be 'example.co.uk'
            Get-OrganizationalDomain -Domain 'a.b.example.org' | Should -Be 'example.org'
            Test-HostMatch -A 'evil-bank.example' -B 'bank.example' | Should -BeFalse
            Test-HostMatch -A 'mx1.bank.example' -B 'bank.example' | Should -BeTrue
            Test-SameDomain -A 'Example.org.' -B 'example.org' | Should -BeTrue
            Get-DmarcAlignment -A 'example.org' -B 'bounce.example.org' | Should -Be 'Relaxed'
        }
    }

    It 'parses Received lines from Postfix and Exim' {
        InModuleScope MailHeaderAnalyzer {
            $raw = 'Received: from mail.example.net (mail.example.net [192.0.2.7]) by mx.example.org (Postfix) with ESMTPS id ABC (using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384) for <x@example.org>; Tue, 4 Aug 2026 10:00:00 +0200'
            $hop = ConvertFrom-ReceivedHeader -Value ($raw.Substring(10)) -Raw $raw
            $hop.IPAddress | Should -Be '192.0.2.7'
            $hop.ReverseDns | Should -Be 'mail.example.net'
            $hop.TlsVersion | Should -Be 'TLS 1.2'
            $hop.TlsCipher | Should -Be 'ECDHE-RSA-AES256-GCM-SHA384'
            $hop.ProtocolClass | Should -Be 'Tls'
            $hop.For | Should -Be 'x@example.org'
            $hop.Software | Should -Be 'Postfix'
        }
    }

    It 'classifies private IP addresses' {
        InModuleScope MailHeaderAnalyzer {
            Test-PrivateIPAddress -IPAddress '10.1.2.3' | Should -BeTrue
            Test-PrivateIPAddress -IPAddress '172.31.0.1' | Should -BeTrue
            Test-PrivateIPAddress -IPAddress '100.64.0.1' | Should -BeTrue
            Test-PrivateIPAddress -IPAddress '203.0.113.5' | Should -BeFalse
            Test-PrivateIPAddress -IPAddress 'fe80::1' | Should -BeTrue
        }
    }
}
