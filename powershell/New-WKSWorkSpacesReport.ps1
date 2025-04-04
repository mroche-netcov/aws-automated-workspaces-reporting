[CmdletBinding()]
param (
    [Parameter()]
    [System.String]
    $Path = "C:\Temp\",

    [Parameter(Mandatory = $true)]
    [ValidateSet("us-east-1", "us-west-2", "ap-northeast-2", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ca-central-1", "eu-central-1", "eu-west-1", "eu-west-2", "sa-east-1")]
    [System.String]
    $Region,
    
    [Parameter()]
    [ValidatePattern("^\d{1,3}$")]
    [System.Int32]
    $InactiveDays = 60
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
        $response = $connection.SendRequest($request)
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

        $searchResponse = $connection.SendRequest($searchRequest)

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

Import-Module AWS.Tools.Common, AWS.Tools.WorkSpaces, AWS.Tools.CloudWatch

$Path = "C:\Temp\"

if (-not(Test-Path $Path)) {New-Item -ItemType Directory -Path $Path | Out-Null}
if ($InactiveDays -ge 455) {Write-Host ('CloudWatch aggregates log data so you may need to modify the period queried per this link{0}https://aws.amazon.com/about-aws/whats-new/2016/11/cloudwatch-extends-metrics-retention-and-new-user-interface/' -f $([Environment]::NewLine))}

$StartDate = (Get-Date).AddDays(-$InactiveDays)
$EndDate = Get-Date

$Dimension = New-Object Amazon.CloudWatch.Model.Dimension
$Dimension.set_Name("WorkspaceId")
# Setting this to 1 day (60 seconds * 60 minutes * 24 hours in a day) to allow querying larger data points - see above link relating to CloudWatch metrics aggregation
$Period = 86400

$WorkSpaces = Get-WKSWorkspace -ProfileName sila-prod | Select-Object UserName, ComputerName, WorkspaceId, IpAddress, DirectoryId, BundleId, SubnetId, State, RootVolumeEncryptionEnabled, UserVolumeEncryptionEnabled, WorkspaceProperties
$WorkSpacesCount = $WorkSpaces.Count
Write-Host ('Capturing info for {0} WorkSpaces' -f  $WorkSpacesCount)

$Report = @()

# Define the LDAP server and port
$server = '54.224.216.23'
$port = 389

# Define the credentials
$domain = 'sila'
$username = 'ncitech'
$password = 'WiaD&0Miz65M#%'
$credential = New-Object -TypeName pscredential -ArgumentList ('{0}\{1}' -f $domain, $username), (ConvertTo-SecureString -String $password -AsPlainText -Force)

# Create the LDAP directory identifier
$identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($server, $port)

# Create the LDAP connection
$connection = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier, $credential)

# Set the LDAP protocal version
$connection.SessionOptions.ProtocolVersion = 3 

# Bind the connection
$connection.Bind()

$searchBase = "DC=sila,DC=local"


foreach ($WorkSpace in $WorkSpaces){
    Write-Host ("Enumerating workspace {0} assigned to user {1}" -f $WorkSpace.WorkspaceId, $WorkSpace.UserName)
    $UserName = $WorkSpace.UserName
    $ComputerName = $WorkSpace.ComputerName

    
    # Search for user information
    $filter = "(sAMAccountName=$userName)"
    $attributes = @("cn", "sAMAccountName", "displayName", "mail", "department", "mobile", "manager", "userAccountControl")
    

    $ADUserInfo = Search-Ldap -filter $filter -attributes $attributes -searchBase $searchBase

    $computerFilter = "(cn=$computerName)"
    $computerAttributes = @("whenCreated", "operatingSystem")
    $computerattributes = @("cn", "name", "whenCreated", "operatingSystem", "dNSHostName", "userAccountControl", "lastLogonTimestamp")

    $ADcomputerInfo = Search-Ldap -filter $computerFilter -attributes $computerAttributes -searchBase $searchBase




    #$ADUserInfo = Get-ADUser -Filter {SamAccountName -eq $UserName} -Properties Name, Enabled, Department, EmailAddress, Manager, MobilePhone | Select-Object *, @{Label = "ADUserManager"; Expression = {(Get-ADUser $_.Manager -Properties DisplayName).DisplayName}}
    #$ADComputerInfo = Get-ADComputer -Filter {Name -eq $ComputerName} -Properties Created, OperatingSystem
    $WorkSpaceConnectionInfo = Get-WKSWorkspacesConnectionStatus -WorkspaceId $WorkSpace.WorkspaceId -ProfileName sila-prod
    $WorkSpaceSubnetInfo = Get-EC2Subnet -SubnetId $WorkSpace.SubnetId -ProfileName sila-prod
    
    $Dimension.set_Value($WorkSpace.WorkspaceId)
    $Data = Get-CWMetricStatistics -Namespace "AWS/WorkSpaces" -MetricName "ConnectionSuccess" -UtcStartTime $StartDate -UtcEndTime $EndDate -Period $period -Statistics @("Maximum") -Dimensions @($dimension) -ProfileName sila-prod
    if (($Data.Datapoints.Maximum | Sort-Object -Unique | Select-Object -Last 1) -ge 1) {
        # logins found
        $WorkSpaceUnused = $false
    }
    else {
        # no logins found
        $WorkSpaceUnused = $true
    }
         


    # Build the report object with all required properties
    $obj = New-Object -TypeName PSObject -Property @{
        "UserName" = $WorkSpace.UserName
        "ADUserFullName" = $ADUserInfo.cn
        "ADUserDepartment" = $ADUserInfo.Department
        "ADUserEnabled" = $ADUserInfo.Enabled
        "ADUserEmailAddress" = $ADUserInfo.mail
        "ADUserManager" = $ADUserInfo.ManagerDisplayName
        "ADUserMobilePhone" = $ADUserInfo.MobilePhone
        "ComputerName" = $WorkSpace.ComputerName
        "ADComputerCreated" = $ADComputerInfo.whenCreated
        "ADComputerOperatingSystem" = $ADComputerInfo.OperatingSystem
        "ADComputerLastLogonDate" = $ADcomputerInfo.LastLogonDate
        "ADComputerEnabed" = $ADcomputerInfo.Enabled
        "ADComputerFullyQualifiedDomainName" = $ADcomputerInfo.dNSHostName
        "WorkSpaceId" = $WorkSpace.WorkspaceId
        "ConnectionState" = $WorkSpaceConnectionInfo.ConnectionState
        "ConnectionStateCheckTimestamp" = $WorkSpaceConnectionInfo.ConnectionStateCheckTimestamp
        "LastKnownUserConnectionTimestamp" = $WorkSpaceConnectionInfo.LastKnownUserConnectionTimestamp
        "WorkSpaceUnusedForDefinedPeriod" = $WorkSpaceUnused
        "WorkSpaceState" = $WorkSpace.State
        "ComputeType" = $WorkSpace.WorkspaceProperties.ComputeTypeName
        "IpAddress" = $WorkSpace.IpAddress
        "Directory" = (get-dsdirectory -ProfileName sila-prod -DirectoryID $WorkSpace.DirectoryId).alias
        "DirectoryId" = $WorkSpace.DirectoryId
        "Bundle" = (Get-WKSWorkspaceBundle -ProfileName sila-prod -BundleId $WorkSpace.BundleId).Name
        "BundleId" = $WorkSpace.BundleId
        "SubnetLabel" =  $WorkSpaceSubnetInfo.Tag.Where({$_.Key -eq "Name"}).value
        "SubnetId" = $WorkSpace.SubnetId
        "SubnetAZ" = $WorkSpaceSubnetInfo.AvailabilityZone
        "SubnetAZId" = $WorkSpaceSubnetInfo.AvailabilityZoneId
        "SubnetAvailableIpAddressCount" = $WorkSpaceSubnetInfo.AvailableIpAddressCount
        "RootEncryption" = $WorkSpace.RootVolumeEncryptionEnabled
        "RootVolumeSizeGib" = $WorkSpace.WorkspaceProperties.RootVolumeSizeGib
        "UserEncryption" = $WorkSpace.UserVolumeEncryptionEnabled
        "UserVolumeSizeGib" = $WorkSpace.WorkspaceProperties.UserVolumeSizeGib
        "RunningMode" = $WorkSpace.WorkspaceProperties.RunningMode
        "TimeoutMinutes" = $WorkSpace.WorkspaceProperties.RunningModeAutoStopTimeoutInMinutes
    }
    
    # Append each WorkSpace to the report object so all objects can be written to disk at the same time
    $report += $obj | Select-Object UserName, `
    ADUserFullName, ` `
    ADUserEnabled, `
    ComputerName, `
    ADComputerEnabed, `
    ADComputerCreated, `
    ADComputerOperatingSystem, `
    ADComputerLastLogonDate, 
    ADComputerFullyQualifiedDomainName, `
    WorkSpaceId, `
    ConnectionState, `
    ConnectionStateCheckTimestamp, `
    LastKnownUserConnectionTimestamp, `
    WorkSpaceUnusedForDefinedPeriod, `
    WorkSpaceState, `
    ComputeType, `
    ipaddress, `
    Directory, `
    directoryid, `
    Bundle, `
    bundleid, `
    SubnetLabel, `
    SubnetId, `
    SubnetAZ, `
    SubnetAZId, `
    SubnetAvailableIpAddressCount, `
    RootEncryption, `
    RootVolumeSizeGib, `
    UserEncryption, `
    UserVolumeSizeGib, `
    RunningMode, `
    TimeoutMinutes, `
    ADUserDepartment,
    ADUserEmailAddress, `
    ADUserManager, `
    ADUserMobilePhone
    # Decrement the count of WorkSpaces so the user sees a progress indicator
    $WorkSpacesCount--
    Write-Host "$($WorkSpacesCount) WorkSpaces remain"
    # Delay to prevent AWS API Throttling
    Start-Sleep -Milliseconds 750
}

$report | Sort-Object UserName, Directory | Export-Csv  ($Path + "workspacesreport.csv") -notypeinformation -Append
# Dispose of the connection when done
$connection.Dispose()
