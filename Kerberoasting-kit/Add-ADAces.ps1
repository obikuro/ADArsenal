<#
.SYNOPSIS
    Adds an Active Directory Access Control Entry (ACE) to a target AD user object.

.DESCRIPTION
    Add-ADAces grants a specified principal (user) one or more Active Directory rights
    on a target user object. It connects to a remote DC using supplied credentials,
    modifies the target's ACL, and returns a structured result showing all ACEs held
    by the principal on that target after the change.

    Import this script as a module and call the Add-ADAces cmdlet:
        Import-Module .\Add-ADAces.ps1
        Add-ADAces -DcFqdn dc01.corp.local -PrincipalSam jsmith -TargetSam aadams `
                   -Rights GenericAll -Username corp\admin -Password 'P@ssw0rd'

.PARAMETER DcFqdn
    Fully-qualified domain name of the target domain controller (e.g. dc01.corp.local).

.PARAMETER PrincipalSam
    SAM account name of the user who will receive the new permission.

.PARAMETER TargetSam
    SAM account name of the user object whose ACL will be modified.

.PARAMETER Rights
    One or more ActiveDirectoryRights values to grant. Accepts a comma-separated list
    or an array.

    Common values:
        GenericAll, GenericRead, GenericWrite, WriteDacl, WriteOwner,
        ReadControl, WriteProperty, ReadProperty, ExtendedRight,
        CreateChild, DeleteChild, Self, ListObject, Delete, DeleteTree,
        ListChildren, AccessSystemSecurity

    Defaults to GenericAll if not specified.

.PARAMETER Username
    Domain account used to authenticate against the DC (e.g. CORP\admin).

.PARAMETER Password
    Plaintext password for the authenticating account.

.OUTPUTS
    PSCustomObject with:
        Success        - [bool]   Whether the operation succeeded
        Principal      - [string] PrincipalSam value
        Target         - [string] TargetSam value
        TargetDn       - [string] Distinguished name of the target object
        AceCount       - [int]    Number of ACEs the principal now holds on the target
        Permissions    - [object[]] Detailed list of those ACEs

.EXAMPLE
    Import-Module .\Add-ADAces.ps1
    Add-ADAces -DcFqdn dc01.corp.local -PrincipalSam jsmith -TargetSam aadams `
               -Rights GenericAll -Username corp\admin -Password 'P@ssw0rd'

    Grants GenericAll to jsmith on aadams.

.EXAMPLE
    Add-ADAces -DcFqdn dc01.corp.local -PrincipalSam jsmith -TargetSam aadams `
               -Rights WriteDacl,WriteOwner -Username corp\admin -Password 'P@ssw0rd'

    Grants WriteDacl and WriteOwner in a single ACE.

.NOTES
    Requires the ActiveDirectory PowerShell module (RSAT).
    The authenticating account must have permission to modify the target object's ACL.
#>
function Add-ADAces {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DcFqdn,

        [Parameter(Mandatory)]
        [string]$PrincipalSam,

        [Parameter(Mandatory)]
        [string]$TargetSam,

        [Parameter(Mandatory)]
        [string]$Username,

        [Parameter(Mandatory)]
        [string]$Password,

        [Parameter()]
        [System.DirectoryServices.ActiveDirectoryRights[]]
        $Rights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
    )

    begin {
        Write-Host "[*] Building credential object"
        try {
            $secPw = ConvertTo-SecureString $Password -AsPlainText -Force
            $cred  = [pscredential]::new($Username, $secPw)
        }
        catch {
            Write-Error "Failed to create credential object: $($_.Exception.Message)"
            return
        }

        try {
            Import-Module ActiveDirectory -ErrorAction Stop
        }
        catch {
            Write-Error "ActiveDirectory module not available"
            return
        }
    }

    process {
        try {
            Write-Host "[*] Creating AD PSDrive"
            New-PSDrive -Name ADTemp `
                        -PSProvider ActiveDirectory `
                        -Server $DcFqdn `
                        -Root "//RootDSE/" `
                        -Credential $cred `
                        -Scope Script -ErrorAction Stop | Out-Null

            Write-Host "[*] Resolving principal: $PrincipalSam"
            $principal = Get-ADUser -Identity $PrincipalSam `
                                    -Properties SID `
                                    -Server $DcFqdn `
                                    -Credential $cred `
                                    -ErrorAction Stop

            Write-Host "[*] Resolving target: $TargetSam"
            $target = Get-ADUser -Identity $TargetSam `
                                 -Properties DistinguishedName `
                                 -Server $DcFqdn `
                                 -Credential $cred `
                                 -ErrorAction Stop

            $adPath = "ADTemp:\$($target.DistinguishedName)"
            Write-Host "[*] Target AD path: $adPath"

            $acl = Get-Acl -Path $adPath -ErrorAction Stop

            # Combine all requested rights into a single flags value
            $combinedRights = $Rights[0]
            for ($i = 1; $i -lt $Rights.Count; $i++) {
                $combinedRights = $combinedRights -bor $Rights[$i]
            }

            Write-Host "[*] Building ACE for rights: $combinedRights"
            $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
                ($principal.SID,
                 $combinedRights,
                 [System.Security.AccessControl.AccessControlType]::Allow,
                 [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

            $acl.AddAccessRule($rule)

            Write-Host "[*] Applying ACL"
            Set-Acl -Path $adPath -AclObject $acl -ErrorAction Stop

            Write-Host "[*] Enumerating all ACEs for principal on target"
            $aclAfter = Get-Acl -Path $adPath

            $principalAces = $aclAfter.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]) |
                             Where-Object { $_.IdentityReference -eq $principal.SID }

            $formattedAces = $principalAces | ForEach-Object {
                [pscustomobject]@{
                    IdentityReference = $_.IdentityReference.Value
                    Rights            = $_.ActiveDirectoryRights.ToString()
                    AccessType        = $_.AccessControlType
                    Inheritance       = $_.InheritanceType
                    IsInherited       = $_.IsInherited
                    ObjectType        = $_.ObjectType
                    InheritedObject   = $_.InheritedObjectType
                }
            }

            [pscustomobject]@{
                Success        = $true
                Principal      = $PrincipalSam
                Target         = $TargetSam
                TargetDn       = $target.DistinguishedName
                AceCount       = ($formattedAces | Measure-Object).Count
                Permissions    = $formattedAces
            }
        }
        catch {
            Write-Error "Execution failed: $($_.Exception.Message)"
        }
    }

    end {
        Write-Host "[*] Cleaning up PSDrive"
        Remove-PSDrive -Name ADTemp -ErrorAction SilentlyContinue
    }
}
