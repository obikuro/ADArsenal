function Add-ADUserSpn {
<#
.SYNOPSIS
    Adds a Service Principal Name (SPN) to an Active Directory user account using LDAP.

.DESCRIPTION
    Add-ADUserSpn binds directly to a Domain Controller via LDAP (System.DirectoryServices)
    and adds a specified SPN to a target user's servicePrincipalName attribute. It performs
    a uniqueness check before writing — if the SPN already exists on a different object in
    the directory, the operation is aborted and a failure result is returned.

     All operations use System.DirectoryServices.

.PARAMETER DcFqdn
    The fully qualified domain name (FQDN) of the Domain Controller to connect to.
    Example: dc01.corp.contoso.com

.PARAMETER TargetSam
    The sAMAccountName of the user account to which the SPN will be added.
    Aliases: Sam, UserSam

.PARAMETER Spn
    The Service Principal Name string to add to the user account.
    Example: HTTP/webserver.corp.contoso.com

.PARAMETER Credential
    Optional PSCredential to use when binding to the LDAP directory.
    If omitted, the current Windows identity is used.

.PARAMETER PassThruSpnList
    When specified, the returned result object includes a ServicePrincipalNames property
    containing all SPNs currently registered on the target user after the operation.

.OUTPUTS
    PSCustomObject with the following properties:
        Success          [bool]   - Whether the SPN is confirmed present after the operation.
        Step             [string] - The last step reached: Done, FindUser, CheckSpnUniqueness,
                                    VerifySpn, or Execution (on exception).
        DcFqdn           [string] - The DC that was targeted.
        UserSam          [string] - The sAMAccountName of the target user.
        TargetDn         [string] - The distinguishedName of the target user (when found).
        Spn              [string] - The SPN that was requested.
        AlreadyHadSpn    [bool]   - True if the user already had the SPN before this call.
        SpnCount         [int]    - Number of SPNs on the user after the operation.
        AddedOrConfirmed [bool]   - True if the SPN is present (added or pre-existing).
        ServicePrincipalNames [string[]] - Full SPN list (only present with -PassThruSpnList).

.EXAMPLE
    Add-ADUserSpn -DcFqdn dc01.corp.contoso.com -TargetSam jdoe -Spn HTTP/webapp.corp.contoso.com

    Adds the SPN 'HTTP/webapp.corp.contoso.com' to the user 'jdoe' using the current identity.

.EXAMPLE
    $cred = Get-Credential
    Add-ADUserSpn -DcFqdn dc01.corp.contoso.com -UserSam svcaccount -Spn MSSQLSvc/sql01.corp.contoso.com:1433 -Credential $cred -PassThruSpnList

    Adds an MSSQL SPN to 'svcaccount' using explicit credentials and returns the full SPN list.

.NOTES
    - Requires network access to the target DC on the LDAP port (default 389).
    - The calling account (or supplied credential) must have write permission on the
      servicePrincipalName attribute of the target user object.
    - SPN uniqueness is enforced: if the SPN is already registered on any other object in the
      domain, the function returns Success=$false with Step='CheckSpnUniqueness'.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DcFqdn,

        [Parameter(Mandatory)]
        [Alias('Sam','UserSam')]
        [string]$TargetSam,

        [Parameter(Mandatory)]
        [string]$Spn,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [switch]$PassThruSpnList
    )

    begin {
        $ErrorActionPreference = 'Stop'

        function New-LdapDirectoryEntry {
            param(
                [Parameter(Mandatory)]
                [string]$Path,

                [Parameter()]
                [System.Management.Automation.PSCredential]$Credential
            )

            if ($Credential) {
                $netCred = $Credential.GetNetworkCredential()

                if ([string]::IsNullOrWhiteSpace($netCred.Domain)) {
                    $bindUser = $netCred.UserName
                }
                else {
                    $bindUser = "{0}\{1}" -f $netCred.Domain, $netCred.UserName
                }

                return New-Object System.DirectoryServices.DirectoryEntry(
                    $Path,
                    $bindUser,
                    $netCred.Password
                )
            }

            return New-Object System.DirectoryServices.DirectoryEntry($Path)
        }

        function New-LdapSearcher {
            param(
                [Parameter(Mandatory)]
                [System.DirectoryServices.DirectoryEntry]$Root,

                [Parameter(Mandatory)]
                [string]$Filter,

                [Parameter()]
                [string[]]$PropertiesToLoad = @('distinguishedName')
            )

            $searcher = New-Object System.DirectoryServices.DirectorySearcher
            $searcher.SearchRoot = $Root
            $searcher.Filter = $Filter
            $searcher.PageSize = 1000

            foreach ($prop in $PropertiesToLoad) {
                [void]$searcher.PropertiesToLoad.Add($prop)
            }

            return $searcher
        }

        function Get-RootNamingContext {
            param(
                [Parameter(Mandatory)]
                [string]$DcFqdn,

                [Parameter()]
                [System.Management.Automation.PSCredential]$Credential
            )

            $rootDse = New-LdapDirectoryEntry -Path "LDAP://$DcFqdn/RootDSE" -Credential $Credential
            try {
                return [string]$rootDse.Properties['defaultNamingContext'][0]
            }
            finally {
                $rootDse.Dispose()
            }
        }

       function Escape-LdapFilterValue {
    param(
        [Parameter(Mandatory)]
        [string]$Value
    )

    $escaped = $Value.Replace('\', '\5c')
    $escaped = $escaped.Replace('*', '\2a')
    $escaped = $escaped.Replace('(', '\28')
    $escaped = $escaped.Replace(')', '\29')
    $escaped = $escaped.Replace([string][char]0, '\00')
    return $escaped
}





    }

    process {
        Write-Host "[*] Resolving default naming context from RootDSE"
        $defaultNC = Get-RootNamingContext -DcFqdn $DcFqdn -Credential $Credential

        if (-not $defaultNC) {
            Write-Error "Could not read defaultNamingContext from RootDSE on '$DcFqdn'."
            return
        }

        $rootPath = "LDAP://$DcFqdn/$defaultNC"
        $rootEntry = New-LdapDirectoryEntry -Path $rootPath -Credential $Credential

        try {
            $safeSam = Escape-LdapFilterValue -Value $TargetSam
            $safeSpn = Escape-LdapFilterValue -Value $Spn

            Write-Host "[*] Searching for target user '$TargetSam'"
            $userSearcher = New-LdapSearcher `
                -Root $rootEntry `
                -Filter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$safeSam))" `
                -PropertiesToLoad @('distinguishedName', 'servicePrincipalName', 'sAMAccountName')

            $userHit = $userSearcher.FindOne()

            if (-not $userHit) {
                [pscustomobject]@{
                    Success = $false
                    Step    = 'FindUser'
                    UserSam = $TargetSam
                    DcFqdn  = $DcFqdn
                    Message = "User '$TargetSam' not found in '$defaultNC'."
                }
                return
            }

            $userDn = [string]$userHit.Properties['distinguishedname'][0]

            Write-Host "[*] Checking SPN uniqueness for '$Spn'"
            $spnSearcher = New-LdapSearcher `
                -Root $rootEntry `
                -Filter "(servicePrincipalName=$safeSpn)" `
                -PropertiesToLoad @('distinguishedName', 'sAMAccountName', 'servicePrincipalName')

            $spnHit = $spnSearcher.FindOne()

            if ($spnHit) {
                $spnOwnerDn = [string]$spnHit.Properties['distinguishedname'][0]

                if ($spnOwnerDn -ne $userDn) {
                    [pscustomobject]@{
                        Success         = $false
                        Step            = 'CheckSpnUniqueness'
                        UserSam         = $TargetSam
                        TargetDn        = $userDn
                        ExistingOwnerDn = $spnOwnerDn
                        Spn             = $Spn
                        Message         = "SPN '$Spn' already exists on '$spnOwnerDn'."
                    }
                    return
                }
            }

            Write-Host "[*] Binding to target object"
            $userPath = "LDAP://$DcFqdn/$userDn"
            $userEntry = New-LdapDirectoryEntry -Path $userPath -Credential $Credential

            try {
                $spnProp = $userEntry.Properties['servicePrincipalName']
                $alreadyHadSpn = $false

                $currentSpns = @()
                foreach ($value in $spnProp) {
                    $currentSpns += [string]$value
                }

                if ($currentSpns -contains $Spn) {
                    $alreadyHadSpn = $true
                    Write-Host "[*] Target already has the SPN"
                }
                else {
                    Write-Host "[*] Adding SPN"
                    [void]$spnProp.Add($Spn)
                    $userEntry.CommitChanges()
                }
            }
            finally {
                $userEntry.Dispose()
            }

            Write-Host "[*] Verifying current SPNs on target"
            $verifyEntry = New-LdapDirectoryEntry -Path $userPath -Credential $Credential

            try {
                $verifiedSpns = @()
                foreach ($value in $verifyEntry.Properties['servicePrincipalName']) {
                    $verifiedSpns += [string]$value
                }
            }
            finally {
                $verifyEntry.Dispose()
            }

            $spnPresent = $verifiedSpns -contains $Spn

            $result = [pscustomobject]@{
                Success          = $spnPresent
                Step             = if ($spnPresent) { 'Done' } else { 'VerifySpn' }
                DcFqdn           = $DcFqdn
                UserSam          = $TargetSam
                TargetDn         = $userDn
                Spn              = $Spn
                AlreadyHadSpn    = $alreadyHadSpn
                SpnCount         = $verifiedSpns.Count
                AddedOrConfirmed = $spnPresent
            }

            if ($PassThruSpnList) {
                $result | Add-Member -NotePropertyName ServicePrincipalNames -NotePropertyValue $verifiedSpns
            }

            $result
        }
        catch {
            [pscustomobject]@{
                Success = $false
                Step    = 'Execution'
                DcFqdn  = $DcFqdn
                UserSam = $TargetSam
                Spn     = $Spn
                Error   = $_.Exception.Message
            }
        }
        finally {
            if ($rootEntry) {
                $rootEntry.Dispose()
            }
        }
    }
}
