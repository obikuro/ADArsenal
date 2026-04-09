function Write-Banner {
    param(
        [string]$Tool     = "PSRemoteSurfaceScan",
        [string]$Operator = "Edrian"
    )

    # Palette from your image
    $Primary = @{ R = 206; G = 145; B = 120 }   # #CE9178
    $Accent  = @{ R = 166; G = 113; B =  91 }   # darker outline-style accent
    $Muted   = @{ R = 120; G = 120; B = 120 }   # neutral gray

    function Write-RGB {
        param(
            [string]$Text,
            [int]$R,
            [int]$G,
            [int]$B,
            [switch]$NoNewline
        )

        $esc = [char]27
        $ansiText = "$esc[38;2;${R};${G};${B}m$Text$esc[0m"

        if ($NoNewline) {
            Write-Host $ansiText -NoNewline
        }
        else {
            Write-Host $ansiText
        }
    }

    function Write-RGBLine {
        param(
            [string]$Left,
            [string]$Value,
            [hashtable]$LeftColor,
            [hashtable]$ValueColor,
            [int]$Width = 74
        )

        $plain = "$Left$Value"
        $pad = $Width - $plain.Length
        if ($pad -lt 0) { $pad = 0 }

        Write-RGB "   │ " $Accent.R $Accent.G $Accent.B -NoNewline
        Write-RGB $Left  $LeftColor.R  $LeftColor.G  $LeftColor.B -NoNewline
        Write-RGB $Value $ValueColor.R $ValueColor.G $ValueColor.B -NoNewline
        Write-RGB (" " * $pad) $ValueColor.R $ValueColor.G $ValueColor.B -NoNewline
        Write-RGB " │" $Accent.R $Accent.G $Accent.B
    }

    Write-Host ""

    Write-RGB "    █████╗ ██████╗  █████╗ ██████╗ ███████╗███████╗███╗   ██╗ █████╗ ██╗     " $Accent.R $Accent.G $Accent.B
    Write-RGB "   ██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝████╗  ██║██╔══██╗██║     " $Primary.R $Primary.G $Primary.B
    Write-RGB "   ███████║██║  ██║███████║██████╔╝███████╗█████╗  ██╔██╗ ██║███████║██║     " $Primary.R $Primary.G $Primary.B
    Write-RGB "   ██╔══██║██║  ██║██╔══██║██╔══██╗╚════██║██╔══╝  ██║╚██╗██║██╔══██║██║     " $Primary.R $Primary.G $Primary.B
    Write-RGB "   ██║  ██║██████╔╝██║  ██║██║  ██║███████║███████╗██║ ╚████║██║  ██║███████╗" $Accent.R $Accent.G $Accent.B
    Write-RGB "   ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝" $Primary.R $Primary.G $Primary.B

    Write-Host ""

    Write-RGB "   ┌──────────────────────────────────────────────────────────────────────────┐" $Accent.R $Accent.G $Accent.B
    Write-RGBLine " [ TOOL     ] " $Tool     $Muted   $Primary
    Write-RGBLine " [ OPERATOR ] " $Operator $Muted   $Primary
    Write-RGBLine " [ MODULE   ] " "Remote Attack Surface Recon" $Muted $Primary
    Write-RGB "   └──────────────────────────────────────────────────────────────────────────┘" $Accent.R $Accent.G $Accent.B

    Write-Host ""
}

function Get-PSRSErrorCategory {
    param([string]$Message)
    switch -Wildcard ($Message) {
        '*Access is denied*'                 { return [pscustomobject]@{ Category = 'AccessDenied';      Short = 'Access denied'          } }
        '*The WinRM client cannot complete*' { return [pscustomobject]@{ Category = 'WinRMError';        Short = 'WinRM client error'     } }
        '*No connection could be made*'      { return [pscustomobject]@{ Category = 'ConnectionRefused'; Short = 'Connection refused'     } }
        '*The network path was not found*'   { return [pscustomobject]@{ Category = 'HostNotFound';      Short = 'Network path not found' } }
        '*timed out*'                        { return [pscustomobject]@{ Category = 'Timeout';           Short = 'Connection timed out'   } }
        '*WinRM service is not running*'     { return [pscustomobject]@{ Category = 'WinRMNotRunning';   Short = 'WinRM not running'      } }
        '*No such host is known*'            { return [pscustomobject]@{ Category = 'DNSFailure';        Short = 'DNS resolution failed'  } }
        default                              { return [pscustomobject]@{ Category = 'Unknown';           Short = $Message                 } }
    }
}

function Invoke-PSRemoteSurfaceScan {
<#
.SYNOPSIS
Search for remote access on machines in a domain or list using PowerShell Remoting.

.DESCRIPTION
Attempts to execute a simple PowerShell Remoting command on each target computer
to determine if PSRemoting access is available. Connections are made in parallel
up to ThrottleLimit using Invoke-Command's built-in multi-computer parallelism
(PS5.1+ compatible — no ForEach-Object -Parallel required).

.PARAMETER ComputerName
One or more computer names (supports pipeline input).

.PARAMETER ComputerFile
Path to a file containing one computer name per line.

.PARAMETER Domain
LDAP domain name (e.g. "example.com"). If no ComputerName/ComputerFile is
provided, computers are enumerated from this domain. Disabled computer accounts
are excluded automatically. If not specified, the current domain is used.

.PARAMETER Credential
PSCredential to use for the remoting connection. If omitted, the current
user's security context is used.

.PARAMETER StopOnSuccess
Stop scanning when the first machine with access is found.

.PARAMETER ThrottleLimit
Maximum number of simultaneous remoting connections (default: 32).

.PARAMETER TimeoutSeconds
Timeout in seconds for each remoting connection attempt (default: 30).

.PARAMETER Quiet
Suppress all progress status messages (Write-Host / Write-Progress).
Only warnings and errors are shown. Output objects are unaffected.

.OUTPUTS
[pscustomobject] with:
    ComputerName  - Target computer
    HasAccess     - True/False
    ErrorCategory - Category of the failure (AccessDenied, Timeout, DNSFailure, etc.)
    Error         - Full error message (if any)

.EXAMPLE
$cred = Get-Credential
Invoke-PSRemoteSurfaceScan -ComputerName "pc1","pc2" -Credential $cred

.EXAMPLE
Invoke-PSRemoteSurfaceScan -ComputerFile .\servers.txt -StopOnSuccess

.EXAMPLE
Invoke-PSRemoteSurfaceScan -Domain "example.com" -Credential (Get-Credential) -ThrottleLimit 50 -TimeoutSeconds 15
# Enumerates enabled computers from AD and tests each in parallel.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false,
                   Position = 0,
                   ValueFromPipeline = $true,
                   ValueFromPipelineByPropertyName = $true)]
        [Alias('Name','DNSHostName')]
        [string[]]
        $ComputerName,

        [Parameter(Mandatory = $false, Position = 1)]
        [string]
        $ComputerFile,

        [Parameter(Mandatory = $false, Position = 2)]
        [string]
        $Domain,

        [Parameter(Mandatory = $false, Position = 3)]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter(Mandatory = $false, Position = 4)]
        [switch]
        $StopOnSuccess,

        [Parameter(Mandatory = $false, Position = 5)]
        [int]
        $ThrottleLimit = 32,

        [Parameter(Mandatory = $false, Position = 6)]
        [int]
        $TimeoutSeconds = 30,

        [Parameter(Mandatory = $false)]
        [switch]
        $Quiet
    )

    begin {
        Write-Banner -Tool "PSRemoteSurfaceScan" -Operator "Edrian"
        $resolvedComputers = New-Object System.Collections.Generic.List[string]
    }

    process {
        if ($ComputerName) {
            foreach ($c in $ComputerName) { $resolvedComputers.Add($c) }
        }
    }

    end {
        # From file, if provided
        if ($ComputerFile) {
            if (Test-Path $ComputerFile) {
                Get-Content -Path $ComputerFile |
                    ForEach-Object { $_.Trim() } |
                    Where-Object   { $_ } |
                    ForEach-Object { $resolvedComputers.Add($_) }
            }
            else {
                Write-Warning "ComputerFile '$ComputerFile' not found."
            }
        }

        # If nothing yet, enumerate from AD domain
        if ($resolvedComputers.Count -eq 0) {
            if (-not $Quiet) { Write-Host "  [*] No target list supplied — enumerating computers from AD." -ForegroundColor DarkCyan }

            $searcher = New-Object System.DirectoryServices.DirectorySearcher

            if ($Domain) {
                if (-not $Quiet) { Write-Host "  [*] AD search root: LDAP://$Domain" -ForegroundColor DarkCyan }
                if ($Credential) {
                    $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry(
                        "LDAP://$Domain",
                        $Credential.UserName,
                        $Credential.GetNetworkCredential().Password
                    )
                }
                else {
                    $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain")
                }
            }
            else {
                if (-not $Quiet) { Write-Host "  [*] AD search root: current domain (auto-discover)" -ForegroundColor DarkCyan }
                if ($Credential) {
                    # Auto-discover the domain root via RootDSE using the supplied credentials
                    try {
                        $rootDSE   = New-Object System.DirectoryServices.DirectoryEntry(
                            'LDAP://RootDSE',
                            $Credential.UserName,
                            $Credential.GetNetworkCredential().Password
                        )
                        $defaultNC = $rootDSE.defaultNamingContext
                        $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry(
                            "LDAP://$defaultNC",
                            $Credential.UserName,
                            $Credential.GetNetworkCredential().Password
                        )
                    }
                    catch {
                        Write-Warning "Could not auto-discover domain root with supplied credentials: $_"
                        Write-Warning "Specify -Domain explicitly (e.g. -Domain example.com)."
                        return
                    }
                }
                else {
                    $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry
                }
            }

            # sAMAccountType=805306369 = computer objects; exclude disabled accounts (UAC bit 2)
            $searcher.Filter = "(&(sAMAccountType=805306369)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
            $searcher.PageSize = 1000

            $searcher.FindAll() |
                ForEach-Object { $_.Properties.dnshostname | Select-Object -First 1 } |
                Where-Object   { $_ } |
                ForEach-Object { $resolvedComputers.Add($_) }
        }

        # Normalize and dedupe
        $unique = @($resolvedComputers | Where-Object { $_ } | Sort-Object -Unique)
        $resolvedComputers = New-Object System.Collections.Generic.List[string]
        foreach ($c in $unique) { $resolvedComputers.Add($c) }

        if ($resolvedComputers.Count -eq 0) {
            Write-Warning "No computers to test."
            return
        }

        $total = $resolvedComputers.Count
        if (-not $Quiet) { Write-Host "  [*] Scanning $total computer(s) for PSRemoting access  [ThrottleLimit: $ThrottleLimit | Timeout: ${TimeoutSeconds}s]" -ForegroundColor Cyan }

        # Session options enforce per-connection timeout
        $sessionOption = New-PSSessionOption `
            -OpenTimeout      ($TimeoutSeconds * 1000) `
            -OperationTimeout ($TimeoutSeconds * 1000) `
            -CancelTimeout    ($TimeoutSeconds * 1000)

        $invokeParams = @{
            ComputerName  = $resolvedComputers.ToArray()
            ScriptBlock   = { $env:COMPUTERNAME }
            ThrottleLimit = $ThrottleLimit
            SessionOption = $sessionOption
            ErrorAction   = 'SilentlyContinue'
            ErrorVariable = 'remoteErrors'
        }
        if ($Credential) { $invokeParams.Credential = $Credential }

        $remoteErrors   = @()
        $successObjects = @(Invoke-Command @invokeParams)

        # Build success lookup
        $successMap = @{}
        foreach ($s in $successObjects) {
            $successMap[$s.PSComputerName.ToLower()] = $true
        }

        # Build error lookup — resolve computer name from the error record
        $errorMap = @{}
        foreach ($e in $remoteErrors) {
            $cn = $null
            if ($e.TargetObject -is [string] -and $e.TargetObject) {
                $cn = $e.TargetObject
            }
            elseif ($e.TargetObject -and $e.TargetObject.PSObject.Properties['ConnectionInfo']) {
                $cn = $e.TargetObject.ConnectionInfo.ComputerName
            }
            elseif ($e.CategoryInfo.TargetName) {
                $cn = $e.CategoryInfo.TargetName
            }

            if ($cn) {
                $cat = Get-PSRSErrorCategory -Message $e.Exception.Message
                $errorMap[$cn.ToLower()] = @{
                    Message  = $e.Exception.Message
                    Category = $cat.Category
                    Short    = $cat.Short
                }
            }
        }

        $results = New-Object System.Collections.Generic.List[object]
        $i = 0

        foreach ($computer in $resolvedComputers) {
            $i++
            $key = $computer.ToLower()

            if (-not $Quiet) {
                Write-Progress -Activity 'PSRemote Surface Scan' `
                               -Status   "[$i/$total] $computer" `
                               -PercentComplete ([int](($i / $total) * 100))
            }

            if ($successMap.ContainsKey($key)) {
                if (-not $Quiet) { Write-Host "  [+] $computer" -ForegroundColor Green }
                $obj = [pscustomobject]@{
                    ComputerName  = $computer
                    HasAccess     = $true
                    ErrorCategory = $null
                    Error         = $null
                }
                $results.Add($obj)

                if ($StopOnSuccess) {
                    if (-not $Quiet) { Write-Progress -Activity 'PSRemote Surface Scan' -Completed }
                    $obj
                    return
                }
            }
            elseif ($errorMap.ContainsKey($key)) {
                $info = $errorMap[$key]
                if (-not $Quiet) { Write-Host "  [-] $computer  [$($info.Category)] $($info.Short)" -ForegroundColor Red }
                $results.Add([pscustomobject]@{
                    ComputerName  = $computer
                    HasAccess     = $false
                    ErrorCategory = $info.Category
                    Error         = $info.Message
                })
            }
            else {
                if (-not $Quiet) { Write-Host "  [?] $computer  [NoResult]" -ForegroundColor Yellow }
                $results.Add([pscustomobject]@{
                    ComputerName  = $computer
                    HasAccess     = $false
                    ErrorCategory = 'NoResult'
                    Error         = 'No result returned from Invoke-Command.'
                })
            }
        }

        if (-not $Quiet) { Write-Progress -Activity 'PSRemote Surface Scan' -Completed }

        $successCount = ($results | Where-Object { $_.HasAccess }).Count
        if (-not $Quiet) {
            Write-Host ""
            Write-Host "  [*] Scan complete — $successCount/$total host(s) with PSRemoting access." -ForegroundColor Cyan
        }

        $results
    }
}
