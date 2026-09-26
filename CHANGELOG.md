# Changelog

## 0.2.0 (2026-09-26)

Tighter trust model for authentication results and honest ARC labels. Thanks to @saltyslugga for the review that prompted these changes.

- New parameter `-TrustedAuthServId`: only `Authentication-Results` and `Received-SPF` lines carrying one of these authserv-ids (exact match) count as `Trusted`. Documented requirement: the inbound gateway must strip incoming lines claiming that id.
- `AuthTrust = Matched` (authserv-id appears in the delivery chain) is now labelled as plausible, not proof, since the `Received` line can be forged together with the result line. New findings `AuthPlausibleOnly`, `AuthNotTrusted` and `AuthTrustedConflict` (contradicting lines with a trusted id, a sign the gateway does not strip them).
- **Breaking:** `ArcValid` is replaced by `ArcStructure` (`Consistent`/`Inconsistent`) and `ArcStructureIssues`. The check covers instance numbering, one header set per instance and the `cv=` sequence, now including missing `ARC-Message-Signature` headers and duplicates. It never verifies signatures; output, report and help say so. New finding `ArcStructureInconsistent`.
- `Arc` is shown as the receiver's verdict.
- `DkimBrokenAfterForward` only downgrades a DKIM failure when the receiver reports `arc=pass`; an unvalidated ARC claim no longer counts.
## 0.1.1 (2026-09-24)

- Project site is now the reference documentation on rafaelpfister.ch; the repository stays linked via license and release notes.
- Icon for the PowerShell Gallery listing.

## 0.1.0 (2026-09-24)

First release.

- `Get-MailHeaderAnalysis`: delivery chain, authentication results with origin check, DMARC alignment, DKIM and ARC details, Exchange Online hybrid classification, Defender/EOP, SpamAssassin and Rspamd verdicts, findings. Input from string, pipeline, file or clipboard.
- `ConvertTo-MailHeaderReport`: Markdown or plain-text report.
- Runs offline on Windows PowerShell 5.1 and PowerShell 7.
