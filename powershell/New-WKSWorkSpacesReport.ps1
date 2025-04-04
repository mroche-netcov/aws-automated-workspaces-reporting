[CmdletBinding()]
param (
    [Parameter()]
    [System.String]
    $Path = "C:\Temp",
    
    [Parameter()]
    [ValidatePattern("^\d{1,3}$")]
    [System.Int32]
    $InactiveDays = 60,
    
    [Parameter(Mandatory = $true)]
    [System.String]
    $LdapServer,

    [Parameter()]
    [System.Int32]
    $LdapPort = 389,

    [Parameter(Mandatory = $true)]
    [System.String]
    $LdapSearchBase,

    [Parameter()]
    [System.Management.Automation.PSCredential]
    $Credential = (Get-Credential -Message "Enter LDAP credentials"),
    
    [Parameter(Mandatory = $true)]
    $ProfileName
)

# Helper function to parse userAccountControl flags
function Parse-UserAccountControl {
    param ([int]$UAC)

    $flags = [ordered]@{
        "SCRIPT"                      = 0x0001
        "ACCOUNTDISABLE"             = 0x0002
        "HOMEDIR_REQUIRED"           = 0x0008
        "LOCKOUT"                    = 0x0010
        "PASSWD_NOTREQD"             = 0x0020
        "PASSWD_CANT_CHANGE"         = 0x0040
        "ENCRYPTED_TEXT_PWD_ALLOWED" = 0x0080
        "TEMP_DUPLICATE_ACCOUNT"     = 0x0100
        "NORMAL_ACCOUNT"             = 0x0200
        "INTERDOMAIN_TRUST_ACCOUNT"  = 0x0800
        "WORKSTATION_TRUST_ACCOUNT"  = 0x1000
        "SERVER_TRUST_ACCOUNT"       = 0x2000
        "DONT_EXPIRE_PASSWORD"       = 0x10000
        "MNS_LOGON_ACCOUNT"          = 0x20000
        "SMARTCARD_REQUIRED"         = 0x40000
        "TRUSTED_FOR_DELEGATION"     = 0x80000
        "NOT_DELEGATED"              = 0x100000
        "USE_DES_KEY_ONLY"           = 0x200000
        "DONT_REQUIRE_PREAUTH"       = 0x400000
        "PASSWORD_EXPIRED"           = 0x800000
        "TRUSTED_TO_AUTH_FOR_DELEGATION" = 0x1000000
        "PARTIAL_SECRETS_ACCOUNT"    = 0x04000000
    }

    $decodedFlags = $flags.GetEnumerator() | Where-Object { ($UAC -band $_.Value) } | ForEach-Object { $_.Key }

    [PSCustomObject]@{
        Enabled = -not ($UAC -band 0x0002)
        Raw     = $UAC
        Flags   = $decodedFlags -join ", "
    }
}

function Resolve-ManagerDisplayName {
    param (
        [string]$managerDN,
        [string]$searchBase = "DC=yourdomain,DC=com"  # Update as needed
    )

    if (-not $managerDN) { return $null }

    $request = New-Object System.DirectoryServices.Protocols.SearchRequest(
        $managerDN,
        "(objectClass=*)",
        [System.DirectoryServices.Protocols.SearchScope]::Base,
        "displayName"
    )

    try {
        $response = $Connection.SendRequest($request)
        if ($response.Entries.Count -gt 0) {
            return $response.Entries[0].Attributes["displayName"][0]
        } else {
            return $null
        }
    } catch {
        return $null
    }
}

function Search-Ldap {
    param (
        [string]$filter,
        [string[]]$attributes,
        [string]$searchBase,
        [int]$pageSize = 500
    )

    $allResults = @()
    $pageCookie = $null

    do {
        $pageControl = New-Object System.DirectoryServices.Protocols.PageResultRequestControl($pageSize)
        $pageControl.Cookie = $pageCookie

        $searchRequest = New-Object System.DirectoryServices.Protocols.SearchRequest(
            $searchBase,
            $filter,
            [System.DirectoryServices.Protocols.SearchScope]::Subtree,
            $attributes
        )
        $searchRequest.Controls.Add($pageControl)

        $searchResponse = $Connection.SendRequest($searchRequest)

        foreach ($entry in $searchResponse.Entries) {
            $result = @{}
            foreach ($attr in $entry.Attributes.AttributeNames) {
                $result[$attr] = $entry.Attributes[$attr][0]
            }

            # Decode UAC if applicable
            if ($result.ContainsKey("userAccountControl")) {
                $parsedUAC = Parse-UserAccountControl -UAC $result["userAccountControl"]
                $result["Enabled"] = $parsedUAC.Enabled
                $result["UACFlags"] = $parsedUAC.Flags
            }

            # Resolve manager DN to display name
            if ($result.ContainsKey("manager")) {
                $result["ManagerDisplayName"] = Resolve-ManagerDisplayName -managerDN $result["manager"]
            }

            # Convert lastLogonTimestamp if present
            if ($result.ContainsKey("lastLogonTimestamp")) {
                try {
                    $fileTime = [Int64]::Parse($result["lastLogonTimestamp"])
                    $result["LastLogonDate"] = [DateTime]::FromFileTimeUtc($fileTime)
                } catch {
                    $result["LastLogonDate"] = $null
                }
            }

            $allResults += [PSCustomObject]$result
        }

        $pageResponse = $searchResponse.Controls |
            Where-Object { $_ -is [System.DirectoryServices.Protocols.PageResultResponseControl] }

        $pageCookie = $pageResponse.Cookie

    } while ($pageCookie.Length -gt 0)

    return $allResults
}

Import-Module AWS.Tools.Common, AWS.Tools.WorkSpaces, AWS.Tools.CloudWatch, AWS.Tools.DirectoryService, AWS.Tools.EC2

if (-not(Test-Path $Path)) {New-Item -ItemType Directory -Path $Path | Out-Null}

<# if ($InactiveDays -ge 455) {Write-Host ('CloudWatch aggregates log data so you may need to modify the period queried per this link{0}https://aws.amazon.com/about-aws/whats-new/2016/11/cloudwatch-extends-metrics-retention-and-new-user-interface/' -f $([Environment]::NewLine))}

# CloudWatch metrics are aggregate from the WorkSpce client. If the proper ports are not open, the client will not be able to send metrics to CloudWatch. The following ports must be open for the WorkSpaces client to send metrics to CloudWatch:
# 1. TCP 443 (HTTPS) - For the WorkSpaces client to communicate with the WorkSpaces service
$StartDate = (Get-Date).AddDays(-$InactiveDays)
$EndDate = Get-Date

$Dimension = New-Object Amazon.CloudWatch.Model.Dimension
$Dimension.set_Name("WorkspaceId")
# Setting this to 1 day (60 seconds * 60 minutes * 24 hours in a day) to allow querying larger data points - see above link relating to CloudWatch metrics aggregation
$Period = 86400 #>


# Create the LDAP directory identifier
$Identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($LdapServer, $LdapPort)

# Create the LDAP connection
$Connection = New-Object System.DirectoryServices.Protocols.LdapConnection($Identifier, $Credential)

# Set the LDAP protocal version
$Connection.SessionOptions.ProtocolVersion = 3 

# Bind the connection
$Connection.Bind()

$WorkSpaces = Get-WKSWorkspace -ProfileName $ProfileName | Select-Object UserName, ComputerName, WorkspaceId, IpAddress, DirectoryId, BundleId, SubnetId, State, RootVolumeEncryptionEnabled, UserVolumeEncryptionEnabled, WorkspaceProperties
$WorkSpacesCount = $WorkSpaces.Count
Write-Host ('Capturing info for {0} WorkSpaces' -f  $WorkSpacesCount)

$Report = @()
foreach ($WorkSpace in $WorkSpaces){
    Write-Host ("Enumerating workspace {0} assigned to user {1}" -f $WorkSpace.WorkspaceId, $WorkSpace.UserName)
    $UserName = $WorkSpace.UserName
    $ComputerName = $WorkSpace.ComputerName

    
    # Search for user information
    $UserFilter = "(sAMAccountName=$userName)"
    $UserAttributes = @("cn", "sAMAccountName", "displayName", "mail", "department", "mobile", "manager", "userAccountControl")
    $ADUserInfo = Search-Ldap -filter $UserFilter -attributes $UserAttributes -searchBase $LdapSearchBase

    $ComputerFilter = "(cn=$computerName)"
    $ComputerAttributes = @("cn", "name", "whenCreated", "operatingSystem", "dNSHostName", "userAccountControl", "lastLogonTimestamp")
    $ADComputerInfo = Search-Ldap -filter $ComputerFilter -attributes $ComputerAttributes -searchBase $LdapSearchBase

    # The code block below does not work as expected and/or does not provide value. It is commented out for now.
    <# $WorkSpaceConnectionInfo = Get-WKSWorkspacesConnectionStatus -WorkspaceId $WorkSpace.WorkspaceId -ProfileName $ProfileName
    $WorkSpaceSubnetInfo = Get-EC2Subnet -SubnetId $WorkSpace.SubnetId -ProfileName $ProfileName
    
    $Dimension.set_Value($WorkSpace.WorkspaceId)
    $Data = Get-CWMetricStatistics -Namespace "AWS/WorkSpaces" -MetricName "ConnectionSuccess" -UtcStartTime $StartDate -UtcEndTime $EndDate -Period $period -Statistics @("Maximum") -Dimensions @($dimension) -ProfileName $ProfileName
    if (($Data.Datapoints.Maximum | Sort-Object -Unique | Select-Object -Last 1) -ge 1) {
        # logins found
        $WorkSpaceUnused = $false
    }
    else {
        # no logins found
        $WorkSpaceUnused = $true
    } #>

    # Build the report object with all required properties
    $obj = New-Object -TypeName PSObject -Property @{
        "FullName" = $ADUserInfo.displayName
        "UserName" = $WorkSpace.UserName
        "EmailAddress" = $ADUserInfo.mail
        "UserEnabled" = $ADUserInfo.Enabled
        "ComputerName" = $WorkSpace.ComputerName
        "ComputerFullName" = $ADComputerInfo.dNSHostName
        "ComputerEnabed" = $ADComputerInfo.Enabled
        "ComputerCreated" = $ADComputerInfo.whenCreated
        "ComputerLastLogonDate" = $ADComputerInfo.LastLogonDate
        "WorkSpaceId" = $WorkSpace.WorkspaceId
        "WorkSpaceComputeType" = $WorkSpace.WorkspaceProperties.ComputeTypeName
        "WorkSpaceRunningMode" = $WorkSpace.WorkspaceProperties.RunningMode
        "WorkSpaceIpAddress" = $WorkSpace.IpAddress
        "WorkSpaceDirectory" = (Get-DSDirectory -ProfileName $ProfileName -DirectoryID $WorkSpace.DirectoryId).Alias
        "WorkSpaceBundleName" = (Get-WKSWorkspaceBundle -ProfileName $ProfileName -BundleId $WorkSpace.BundleId).Name
        "WorkSpaceSubnetId" = $WorkSpace.SubnetId
    }
    
    # Append each WorkSpace to the report object so all objects can be written to disk at the same time
    $Report += $obj | Select-Object -Property FullName, UserName, EmailAddress, UserEnabled, ComputerName, ComputerFullName, ComputerEnabed, ComputerCreated, ComputerLastLogonDate, WorkSpaceId, WorkSpaceComputeType, WorkSpaceRunningMode, WorkSpaceIpAddress, WorkSpaceDirectory, WorkSpaceBundleName, WorkSpaceSubnetId
    
    # Decrement the count of WorkSpaces so the user sees a progress indicator
    $WorkSpacesCount--
    Write-Host "$($WorkSpacesCount) WorkSpaces remain"
    
    # Delay to prevent AWS API Throttling
    Start-Sleep -Milliseconds 750
}

$Report | Sort-Object UserName, Directory | Export-Csv -Path (Join-Path -Path -ChildPath ('workspacesreport-{0}.csv' -f (Get-Date -Format "yyyy-MMMM"))) -NoTypeInformation -Append

# Dispose of the connection when done
$Connection.Dispose()