# MailHeaderAnalyzer

[![PowerShell Gallery](https://img.shields.io/powershellgallery/v/MailHeaderAnalyzer)](https://www.powershellgallery.com/packages/MailHeaderAnalyzer)
[![Downloads](https://img.shields.io/powershellgallery/dt/MailHeaderAnalyzer)](https://www.powershellgallery.com/packages/MailHeaderAnalyzer)
[![CI](https://github.com/pfstr/MailHeaderAnalyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/pfstr/MailHeaderAnalyzer/actions/workflows/ci.yml)

PowerShell module that analyzes email headers **offline**: delivery chain with delays and TLS, SPF/DKIM/DMARC/ARC results and whether they really come from the receiving server, DMARC alignment, Exchange Online hybrid classification, Microsoft Defender verdicts and anomalies such as duplicate `From` lines or Unicode direction controls.

No DNS lookups, no HTTP requests. The header never leaves the machine, which makes the module safe for messages that contain customer data. A test in the suite fails if any network cmdlet ever finds its way into the source.

Works on Windows PowerShell 5.1 (including the Exchange Management Shell) and PowerShell 7 on Windows, Linux and macOS.

## Install

```powershell
Install-Module -Name MailHeaderAnalyzer -Scope CurrentUser
```

## Quick start

Copy the header in Outlook (File > Properties > Internet headers), in Outlook on the web (View message details) or from any other client, then:

```powershell
Get-MailHeaderAnalysis -FromClipboard
```

```text
Subject     : Service-Report für März
From        : Beispiel Newsletter <news@example.org>
Date        : 2026-08-03 09:14:27Z
SPF         : pass
DKIM        : pass
DMARC       : pass
ARC         : -
CompAuth    : pass (reason 100)
AuthTrust   : Absent (no authserv-id, Microsoft 365 style)
Hops        : 3 (total 00:00:42)
DeliveredBy : zr0p278mb0570.chep278.prod.outlook.com
Findings    : none
```

From a file or a whole `.eml` message (the body is ignored):

```powershell
Get-MailHeaderAnalysis -Path .\message.eml
```

The delivery chain, chronological, with delay per hop:

```powershell
(Get-MailHeaderAnalysis -Path .\message.eml).Hops
```

```text
#   From                 IP              By                                     Protocol  TLS      Time (UTC)           Delay
-   ----                 --              --                                     --------  ---      ----------           -----
1   client.example.net   198.51.100.34   mail.example.org                       ESMTPSA   -        2026-08-03 09:14:28  -
2   mail.example.org     203.0.113.25    mx.eur02.prod.protection.outlook.com   Microsof… TLS 1.3  2026-08-03 09:15:09  41 s
3   AM0EUR02FT056.eop…   -               ZR0P278MB0570.CHEP278.PROD.OUTLOOK.COM Microsof… TLS 1.2  2026-08-03 09:15:10  1 s
```

Only the anomalies:

```powershell
(Get-MailHeaderAnalysis -Path .\message.eml).Findings
```

A batch over many messages, as a table:

```powershell
Get-ChildItem .\samples\*.eml |
    Get-MailHeaderAnalysis |
    Select-Object Source, Spf, Dkim, Dmarc, AuthTrust, HopCount |
    Format-Table
```

A Markdown report for a ticket, straight to the clipboard:

```powershell
Get-MailHeaderAnalysis -Path .\message.eml |
    ConvertTo-MailHeaderReport |
    Set-Clipboard
```

## What it reads

| Area | Details |
|---|---|
| Delivery chain | `Received` lines in chronological order, delay per hop, slowest hop, clock skew, TLS version and cipher (Microsoft, Postfix, Exim spellings), protocol class per RFC 3848 (`ESMTPS`, `ESMTPSA`, HTTP, MAPI), private IPs, provider detection, HELO and rDNS |
| Authentication | `Authentication-Results` (RFC 8601) including the Microsoft variant without authserv-id, `Received-SPF`, `DKIM-Signature` tags, the ARC chain (`cv=`), `compauth` reason codes |
| Trust | Whether the results come from the receiving server: the authserv-id has to match a station of the delivery chain (RFC 8601 section 5). A line a sender prepended themselves is reported as unverified instead of being shown as a pass |
| DMARC alignment | Strict or relaxed alignment of the envelope sender and the DKIM `d=` domain against the `From` domain |
| Exchange Online | `X-MS-Exchange-Organization-MessageDirectionality`, `AuthAs`, `AuthMechanism` (only code 10 is documented, the module says so instead of guessing), `X-OriginatorOrg`, `CrossTenant-*`, wrong-tenant attribution, stripped cross-premises headers |
| Spam filters | Defender/EOP `X-Forefront-Antispam-Report` (SCL, CAT, SFV, IPV, CIP, CTRY), `X-Microsoft-Antispam` (BCL), SpamAssassin tests and score, Rspamd symbols |
| Anomalies | Duplicate singleton fields (`From`, `Subject`, `Date` and others, RFC 5322 section 3.6), Unicode direction controls (shown as `<U+202E>`), weak DKIM hash (SHA-1), `l=` body length limit, expired signatures, `From` not signed, DKIM broken after forwarding but attested by ARC, Reply-To mismatch, SPF not aligned, too many hops |

## Output

`Get-MailHeaderAnalysis` returns one `MailHeaderAnalyzer.Analysis` object per message. The important properties:

| Property | Content |
|---|---|
| `Subject`, `From`, `ReplyTo`, `ReturnPath`, `Date`, `MessageId` | Message facts, RFC 2047 decoded; addresses as objects with `Name`, `Address`, `Domain` |
| `Spf`, `Dkim`, `Dmarc`, `Arc`, `CompAuth`, `CompAuthReason`, `CompAuthReasonMeaning` | Results as strings (`pass`, `fail`, ...), `$null` when absent |
| `AuthTrust`, `AuthServId` | `Matched`, `Unmatched`, `Absent` or `None` |
| `SpfAlignment`, `DkimAlignment` | `Strict`, `Relaxed`, `None` or `$null` |
| `Hops`, `HopCount`, `TotalDuration`, `SlowestHopIndex`, `HasClockSkew`, `DeliveredBy` | The chain, first hop first; `Delay` is a `TimeSpan` |
| `DkimSignatures`, `ArcChain`, `ArcValid` | Parsed signatures with receiver result, ARC instances |
| `Exchange`, `Spam`, `List` | Decoded Exchange hybrid headers, filter verdicts, list headers; `$null` when not present |
| `Findings` | Objects with `Severity` (`Info`, `Warning`, `Fail`), `Code` and `Message` |
| `Fields`, `HadBody`, `Source` | All raw fields, whether a body followed, file path or `Clipboard` |

Everything is a plain object, so `Select-Object`, `Where-Object`, `Export-Csv` and `ConvertTo-Json` work as usual.

## Finding codes

`DuplicateField`, `BidiControls`, `HopOverflow`, `AuthUnverified`, `AuthMixedOrigins`, `ReceivedSpfForeign`, `ReceivedSpfOnly`, `NoAuthResults`, `DmarcFail`, `SpfNotPass`, `DkimNotPass`, `DkimBrokenAfterForward`, `DkimWeakHash`, `DkimBodyLength`, `DkimExpired`, `DkimFromUnsigned`, `ClockSkew`, `ReplyToMismatch`, `SpfNotAligned`, `ExchangeWrongTenant`, `ExchangeHeadersFiltered`, `ExchangeExternallySecured`, `SpamCategory`, `SpamConfidence`.

## Limits

- The module reads what the header says. It does not verify DKIM signatures cryptographically and does not resolve DNS, so an SPF or DKIM `pass` is always the receiving server's verdict, not the module's.
- Organizational domains for relaxed alignment use a short list of multi-label suffixes (`co.uk`, `com.au`, ...), not the full public suffix list.
- Only `AuthMechanism` code 10 is decoded; Microsoft has not documented the other codes.

## Browser version

The same analysis runs in the browser, also without uploading anything: [rafaelpfister.ch/en/tools/header-analyzer](https://rafaelpfister.ch/en/tools/header-analyzer).

## Development

```powershell
Install-Module Pester, PSScriptAnalyzer -Scope CurrentUser
./build.ps1
```

`build.ps1` runs PSScriptAnalyzer, `Test-ModuleManifest` and the Pester suite. Test headers use RFC 2606 domains and RFC 5737 addresses only. Releases are published by tagging `vX.Y.Z` after bumping `ModuleVersion` in the manifest.

## License

MIT, see [LICENSE](LICENSE).
