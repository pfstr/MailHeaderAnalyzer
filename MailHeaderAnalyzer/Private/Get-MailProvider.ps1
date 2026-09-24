# Provider/gateway detection from host names. Curated list, Swiss/DACH gateways first.
$script:MailProviders = @(
    @{ Pattern = '\bseppmail\.'; Name = 'SEPPmail' }
    @{ Pattern = '\bhin\.ch$'; Name = 'HIN Mailgateway' }
    @{ Pattern = '\b(totemo|kereon)\.'; Name = 'totemomail' }
    @{ Pattern = '\bhornetsecurity\.|antispameurope\.'; Name = 'Hornetsecurity' }
    @{ Pattern = '\bretarus\.'; Name = 'Retarus' }
    @{ Pattern = '\bnospamproxy\.'; Name = 'NoSpamProxy' }

    @{ Pattern = '\.protection\.outlook\.com$'; Name = 'Microsoft 365 (Exchange Online Protection)' }
    @{ Pattern = '\.prod\.outlook\.com$|\.mx\.microsoft$'; Name = 'Microsoft 365 (Exchange Online)' }
    @{ Pattern = '\b(aspmx|gmail-smtp-in)\.l\.google\.com$|\.googlemail\.com$|\.google\.com$'; Name = 'Google Workspace' }
    @{ Pattern = '\bmail\.protection\.sophos\.com$'; Name = 'Sophos Email' }
    @{ Pattern = '\b(pphosted|ppe-hosted|ppops)\.(com|net)$'; Name = 'Proofpoint' }
    @{ Pattern = '\bmimecast\.'; Name = 'Mimecast' }
    @{ Pattern = '\bmessagelabs\.com$'; Name = 'Broadcom (Symantec.cloud)' }
    @{ Pattern = '\bbarracuda(networks)?\.com$'; Name = 'Barracuda' }
    @{ Pattern = '\biphmx\.com$|\bcisco\.'; Name = 'Cisco Secure Email' }
    @{ Pattern = '\btrendmicro\.(com|eu)$'; Name = 'Trend Micro' }
    @{ Pattern = '\bavanan\.'; Name = 'Check Point (Avanan)' }

    @{ Pattern = '\binfomaniak\.(ch|com)$'; Name = 'Infomaniak' }
    @{ Pattern = '\bhostpoint\.ch$'; Name = 'Hostpoint' }
    @{ Pattern = '\bcyon\.ch$'; Name = 'cyon' }
    @{ Pattern = '\bmetanet\.ch$'; Name = 'Metanet' }
    @{ Pattern = '\bhosttech\.'; Name = 'hosttech' }
    @{ Pattern = '\bgreen\.ch$'; Name = 'green.ch' }
    @{ Pattern = '\b(bluewin|swisscom)\.ch$'; Name = 'Swisscom' }
    @{ Pattern = '\bprotonmail\.ch$|\bproton\.me$'; Name = 'Proton Mail' }

    @{ Pattern = '\bmailbox\.org$|\bheinlein'; Name = 'mailbox.org (Heinlein)' }
    @{ Pattern = '\bposteo\.de$'; Name = 'Posteo' }
    @{ Pattern = '\bionos\.|kundenserver\.de$|\b1and1\.|\b1und1\.'; Name = 'IONOS' }
    @{ Pattern = '\bstrato(server)?\.(de|net)$'; Name = 'Strato' }
    @{ Pattern = '\bkasserver\.com$|\ball-inkl\.'; Name = 'All-Inkl' }
    @{ Pattern = '\byour-server\.de$|\bhetzner\.'; Name = 'Hetzner' }
    @{ Pattern = '\bovh\.(net|com)$'; Name = 'OVHcloud' }
    @{ Pattern = '\bzoho(mail)?\.(eu|com)$'; Name = 'Zoho Mail' }
    @{ Pattern = '\bfastmail\.com$|\bmessagingengine\.com$'; Name = 'Fastmail' }
    @{ Pattern = '\bicloud\.com$|\bapple\.com$'; Name = 'Apple iCloud Mail' }
    @{ Pattern = '\byahoodns\.net$|\byahoo\.com$'; Name = 'Yahoo' }
    @{ Pattern = '\bmail\.gandi\.net$'; Name = 'Gandi' }
    @{ Pattern = '\bsecureserver\.net$'; Name = 'GoDaddy' }
    @{ Pattern = '\bemailsrvr\.com$'; Name = 'Rackspace Email' }
    @{ Pattern = '\bamazonaws\.com$|\bawsapps\.com$|\bamazonses\.com$'; Name = 'Amazon WorkMail/SES' }
    @{ Pattern = '\bmailgun\.'; Name = 'Mailgun' }
    @{ Pattern = '\bsendgrid\.net$'; Name = 'SendGrid' }
    @{ Pattern = '\bmailroute\.net$'; Name = 'MailRoute' }
    @{ Pattern = '\bspamtitan\.'; Name = 'SpamTitan' }
    @{ Pattern = '\bopen-xchange\.|\boxcs\.'; Name = 'Open-Xchange' }
)

function Get-MailProvider {
    <#
    .SYNOPSIS
        First provider match over the given host names (already lower-case, no trailing dot).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyCollection()][string[]]$Hosts)

    foreach ($h in $Hosts) {
        if (-not $h) { continue }
        foreach ($provider in $script:MailProviders) {
            if ([regex]::IsMatch($h, $provider.Pattern, 'IgnoreCase')) { return $provider.Name }
        }
    }
    return $null
}
