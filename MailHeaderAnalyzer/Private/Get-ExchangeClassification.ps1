# Exchange Online / hybrid classification headers (X-MS-Exchange-Organization-*,
# X-MS-Exchange-CrossTenant-*). Facts per the Exchange Team Blog article
# "Demystifying hybrid mail flow". Only AuthMechanism 10 is documented publicly.

function Get-ExchangeClassification {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Fields)

    $value = { param($name) Get-HeaderValue -Fields $Fields -Name $name }

    $directionality = & $value 'X-MS-Exchange-Organization-MessageDirectionality'
    $authAs = & $value 'X-MS-Exchange-Organization-AuthAs'
    $authSource = & $value 'X-MS-Exchange-Organization-AuthSource'
    $authMechanism = & $value 'X-MS-Exchange-Organization-AuthMechanism'
    $originatorOrg = & $value 'X-OriginatorOrg'
    $ctAuthAs = & $value 'X-MS-Exchange-CrossTenant-AuthAs'
    $ctAuthSource = & $value 'X-MS-Exchange-CrossTenant-AuthSource'
    $ctId = & $value 'X-MS-Exchange-CrossTenant-Id'
    $ctFrom = & $value 'X-MS-Exchange-CrossTenant-FromEntityHeader'
    $wrongTenant = & $value 'X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp'
    $preserved = & $value 'X-OrganizationHeadersPreserved'
    $filtered = & $value 'X-CrossPremisesHeadersFilteredBySendConnector'

    $anyOrganization = @($Fields | Where-Object { $_.Name -like 'X-MS-Exchange-Organization-*' }).Count -gt 0
    if (-not $anyOrganization -and -not $originatorOrg -and -not $ctAuthAs -and -not $ctId -and -not $ctFrom) { return $null }

    $directionalityMeaning = $null
    switch -Regex ($directionality) {
        '^Originating$' { $directionalityMeaning = 'Exchange Online classifies the message as coming from the organization itself (inbound connector of type OnPremises matched, or the sender is an Exchange Online mailbox).' }
        '^Incoming$' { $directionalityMeaning = 'Exchange Online classifies the message as coming from outside: delivered to an accepted domain without matching an inbound connector of type OnPremises.' }
    }
    $authAsMeaning = $null
    switch -Regex ($authAs) {
        '^Internal$' { $authAsMeaning = 'Intra-organizational: EOP skips spam, spoof, phishing and impersonation checks for inbound mail.' }
        '^Anonymous$' { $authAsMeaning = 'External: spam filters apply, authentication-requiring distribution lists reject it, Office documents open in Protected View.' }
    }
    $authMechanismMeaning = $null
    if ($authMechanism) {
        if ($authMechanism -match '^0*10$') {
            $authMechanismMeaning = 'Receive connector with "externally secured" permissions: everything from that source is marked Internal and bypasses EOP filtering.'
        } else {
            $authMechanismMeaning = 'Mechanism code {0}; the remaining codes are not publicly documented by Microsoft.' -f $authMechanism
        }
    }
    $ctFromMeaning = $null
    switch -Regex ($ctFrom) {
        '^Internet$' { $ctFromMeaning = 'Submitted from outside Office 365.' }
        '^Hosted$' { $ctFromMeaning = 'From an Office 365 tenant (mailbox in Exchange Online).' }
        '^HybridOnPrem$' { $ctFromMeaning = "From the organization's own on-premises Exchange via the hybrid connector." }
    }

    [pscustomobject]@{
        PSTypeName                 = 'MailHeaderAnalyzer.ExchangeClassification'
        Directionality             = $directionality
        DirectionalityMeaning      = $directionalityMeaning
        AuthAs                     = $authAs
        AuthAsMeaning              = $authAsMeaning
        AuthSource                 = $authSource
        AuthMechanism              = $authMechanism
        AuthMechanismMeaning       = $authMechanismMeaning
        OriginatorOrg              = $originatorOrg
        CrossTenantAuthAs          = $ctAuthAs
        CrossTenantAuthSource      = $ctAuthSource
        CrossTenantId              = $ctId
        CrossTenantFromEntity      = $ctFrom
        CrossTenantFromMeaning     = $ctFromMeaning
        WrongTenantAttribution     = $wrongTenant
        OrganizationHeadersPreserved = $preserved
        CrossPremisesHeadersFiltered = $filtered
    }
}
