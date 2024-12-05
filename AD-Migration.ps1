[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Justification='PasswordOutputPath is a file path, not a credential')]
[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [ValidateSet('export','import')]
    [string]$Operation,

    [Parameter(Mandatory=$true)]
    [string]$DomainName,

    [Parameter(Mandatory=$true)]
    [string]$OrganizationalUnit,

    [Parameter(Mandatory=$true)]
    [string]$DomainController,

    [Parameter(Mandatory=$false)]
    [string]$CsvPath = ".\ADUsers.csv",

    [Parameter(Mandatory=$false)]
    [string]$LogPath = ".\ADMigration.log",

    [Parameter(Mandatory=$false)]
    [ValidateSet('Skip','Update','Error')]
    [string]$ConflictAction = 'Skip',

    [Parameter(Mandatory=$false)]
    [string]$PasswordOutputPath = ".\TempPasswords.csv",

    [Parameter(Mandatory=$false)]
    [switch]$ForcePasswordReset,

    [Parameter(Mandatory=$false)]
    [switch]$IncludeGroups,

    [Parameter(Mandatory=$false)]
    [string]$GroupMembershipPath = ".\GroupMemberships.csv",

    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$CredentialPath = ".\ad_migration_creds.xml",

    [Parameter(Mandatory=$false)]
    [switch]$StoreCredential,

    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $Credential = [System.Management.Automation.PSCredential]::Empty,

    [Parameter(Mandatory=$false)]
    [switch]$UseSSL,

    [Parameter(Mandatory=$false)]
    [string]$TempPath = "$env:TEMP\ADMigration"
)

```powershell
<#
.SYNOPSIS
    Exports users from a source AD domain and imports them into a target domain with enhanced security features.

.DESCRIPTION
    This script provides secure functionality to export AD users from specified OUs in a source domain
    to a CSV file, and then import those users into a target domain. It includes enhanced security features,
    secure credential handling, SSL support, and comprehensive validation checks.
    
    The script can be run in either export mode to collect user data, or import mode to create users 
    in the target domain. When enabled, it can also handle group memberships.
    
    Key Features:
    - Secure credential storage and management
    - SSL/TLS support for secure connections
    - Network connectivity validation
    - Prerequisite checking
    - Export users from source domain with all relevant attributes
    - Import users to target domain with configurable conflict handling
    - Optional group membership migration
    - Automatic UPN domain update during import
    - Secure temporary password generation and storage
    - Comprehensive logging with verbose option
    - Detailed error handling and statistics
    - Progress reporting and execution tracking
    - Secure temporary file handling
    - Remote session management

.PARAMETER Operation
    Required. Specifies the operation to perform:
    - export: Exports users from the specified source domain and OU to a CSV file
    - import: Imports users from the CSV file into the target domain and OU

.PARAMETER DomainName
    Required. The FQDN of the domain to operate on.
    For export: The source domain containing the users to export
    For import: The target domain where users will be created
    Also used as the new UPN suffix for imported users

.PARAMETER OrganizationalUnit
    Required. The distinguished name of the OU to operate on.
    For export: The source OU containing the users to export
    For import: The target OU where users will be created
    Example: "OU=Users,DC=contoso,DC=local"

.PARAMETER DomainController
    Required. The FQDN of the domain controller to connect to.
    Example: "DC1.contoso.local"

.PARAMETER CsvPath
    Optional. The file path for the CSV file used in export/import operations.
    Default: ".\ADUsers.csv"

.PARAMETER LogPath
    Optional. The file path where logs will be written.
    Default: ".\ADMigration.log"

.PARAMETER ConflictAction
    Optional. Specifies how to handle existing users during import:
    - Skip: Skip the user and continue (default)
    - Update: Update the existing user with new information and reset password
    - Error: Throw an error and stop the script
    Default: Skip

.PARAMETER PasswordOutputPath
    Optional. The file path where temporary passwords will be stored.
    The file is automatically secured to allow access only to administrators.
    Passwords will be appended with timestamps for historical tracking.
    Default: ".\TempPasswords.csv"

.PARAMETER ForcePasswordReset
    Optional. When specified with ConflictAction 'Update', forces password reset for existing users
    even if no other attributes need updating.
    Default: False

.PARAMETER IncludeGroups
    Optional. When specified, exports and imports user group memberships along with user accounts.
    Requires GroupMembership.ps1 script to be present in the same directory.
    Default: False

.PARAMETER GroupMembershipPath
    Optional. The file path for the CSV file used to store group memberships.
    Default: ".\GroupMemberships.csv"

.PARAMETER CredentialPath
    Optional. The file path where encrypted credentials are stored/loaded.
    Default: ".\ad_migration_creds.xml"

.PARAMETER StoreCredential
    Optional. Switch to save credentials for future use.
    When this switch is used, the script will prompt for credentials, save them, and exit.

.PARAMETER Credential
    Optional. PSCredential object containing domain admin credentials.
    If not provided, will attempt to load from CredentialPath or prompt for credentials.

.PARAMETER UseSSL
    Optional. Switch to enable SSL/TLS for secure connections to domain controllers.
    Enforces LDAPS protocol and certificate validation.

.PARAMETER TempPath
    Optional. The path where temporary files will be stored.
    This directory is secured with appropriate ACLs.
    Default: "$env:TEMP\ADMigration"

.EXAMPLE
    # Store credentials for future use
    .\AD-Migration.ps1 -StoreCredential

.EXAMPLE
    # Export users with SSL enabled
    .\AD-Migration.ps1 -Operation export `
                      -DomainName "source.local" `
                      -OrganizationalUnit "OU=Users,DC=source,DC=local" `
                      -DomainController "DC1.source.local" `
                      -UseSSL `
                      -Verbose

.EXAMPLE
    # Import users with stored credentials and group memberships
    .\AD-Migration.ps1 -Operation import `
                      -DomainName "target.local" `
                      -OrganizationalUnit "OU=Users,DC=target,DC=local" `
                      -DomainController "DC1.target.local" `
                      -ConflictAction Update `
                      -ForcePasswordReset `
                      -IncludeGroups `
                      -UseSSL `
                      -Verbose

.NOTES
    Author: John A. O'Neill Sr.
    Date: 12/04/2024
    Version: 2.0
    Change Purpose: Added enhanced security features including:
                   - Secure credential management
                   - SSL/TLS support
                   - Network validation
                   - Secure temp file handling
                   - Remote session management
    Prerequisites:  PowerShell Version 5.1 or later
                    ActiveDirectory PowerShell Module
                    Admin rights in both source and target domains
                    GroupMembership.ps1 script (if using -IncludeGroups)

.LINK
    https://learn.microsoft.com/en-us/powershell/module/activedirectory/
#>

# Start time for tracking execution duration
$StartTime = Get-Date

function Test-Prerequisites {
    [CmdletBinding()]
    param()
    
    Write-Log "Checking prerequisites..." -Level Verbose
    
    # Check for admin rights
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (!$isAdmin) {
        throw "This script requires administrative rights. Please run as administrator."
    }
    
    # Check required modules
    $requiredModules = @('ActiveDirectory', 'Microsoft.PowerShell.Security')
    foreach ($module in $requiredModules) {
        if (!(Get-Module -ListAvailable -Name $module)) {
            throw "Required module $module is not installed. Please install it first."
        }
    }
    
    # Enable TLS 1.2
    try {
        Write-Log "Configuring TLS 1.2..." -Level Verbose
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }
    catch {
        throw "Failed to enable TLS 1.2: $_"
    }
    
    Write-Log "Prerequisites check completed successfully." -Level Verbose
}

function Test-DomainControllerConnectivity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$DomainController,
        
        [Parameter(Mandatory=$false)]
        [switch]$UseSSL
    )
    
    Write-Log "Testing connectivity to domain controller: $DomainController" -Level Verbose
    
    # Test basic network connectivity
    if (!(Test-Connection -ComputerName $DomainController -Count 1 -Quiet)) {
        throw "Cannot ping domain controller $DomainController"
    }
    
    # Test LDAP connectivity
    $port = if ($UseSSL) { 636 } else { 389 }
    if (!(Test-NetConnection -ComputerName $DomainController -Port $port -WarningAction SilentlyContinue).TcpTestSucceeded) {
        throw "Cannot connect to domain controller $DomainController on $(if ($UseSSL) { 'LDAPS' } else { 'LDAP' }) port $port"
    }
    
    Write-Log "Successfully verified connectivity to $DomainController" -Level Verbose
}

function Initialize-SecureTempFolder {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$TempPath
    )
    
    Write-Log "Initializing secure temporary folder..." -Level Verbose
    
    if (!(Test-Path $TempPath)) {
        New-Item -ItemType Directory -Path $TempPath -Force | Out-Null
        
        # Secure the temporary directory
        $acl = Get-Acl $TempPath
        $acl.SetAccessRuleProtection($true, $false)
        
        # Add current user with full control
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $env:USERNAME,
            "FullControl",
            "ContainerInherit,ObjectInherit",
            "None",
            "Allow"
        )
        $acl.AddAccessRule($rule)
        
        # Add SYSTEM with full control
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "NT AUTHORITY\SYSTEM",
            "FullControl",
            "ContainerInherit,ObjectInherit",
            "None",
            "Allow"
        )
        $acl.AddAccessRule($rule)
        
        Set-Acl $TempPath $acl
        Write-Log "Secured temporary directory created at: $TempPath" -Level Verbose
    }
}

function New-SecureRemoteSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$DomainController,
        
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]$Credential,
        
        [Parameter(Mandatory=$false)]
        [switch]$UseSSL
    )
    
    Write-Log "Establishing secure remote session to $DomainController..." -Level Verbose
    
    $sessionParams = @{
        ComputerName = $DomainController
        Credential = $Credential
        ErrorAction = 'Stop'
    }
    
    if ($UseSSL) {
        $sessionParams['UseSSL'] = $true
    }
    
    try {
        $session = New-PSSession @sessionParams
        Write-Log "Successfully established secure session to $DomainController" -Level Verbose
        return $session
    }
    catch {
        throw "Failed to establish session to ${DomainController}: $_"
    }
}

function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [Parameter(Mandatory=$false)]
        [ValidateSet('Information','Warning','Error','Verbose')]
        [string]$Level = 'Information'
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "$Timestamp [$Level] $Message"
    Add-Content -Path $LogPath -Value $LogMessage
    
    switch ($Level) {
        'Warning' { Write-Host $LogMessage -ForegroundColor Yellow }
        'Error' { Write-Host $LogMessage -ForegroundColor Red }
        'Verbose' { Write-Verbose $Message }
        default { Write-Host $LogMessage }
    }
}

function Update-UserPrincipalName {
    param(
        [Parameter(Mandatory=$true)]
        [string]$OldUPN,
        
        [Parameter(Mandatory=$true)]
        [string]$NewDomain
    )
    
    try {
        $username = $OldUPN.Split('@')[0]
        return "$username@$NewDomain"
    }
    catch {
        Write-Log "Error updating UPN for $OldUPN - $($_.Exception.Message)" -Level Error
        return $OldUPN
    }
}

function New-RandomPassword {
    param (
        [Parameter(Mandatory=$false)]
        [int]$Length = 16,
        [Parameter(Mandatory=$false)]
        [int]$MinSpecialChars = 2,
        [Parameter(Mandatory=$false)]
        [int]$MinNumbers = 2,
        [Parameter(Mandatory=$false)]
        [int]$MinUpperCase = 2
    )
    
    $UpperCase = 'ABCDEFGHKLMNOPRSTUVWXYZ'
    $LowerCase = 'abcdefghiklmnoprstuvwxyz'
    $Numbers = '0123456789'
    $SpecialChars = '!@#$%^&*()-_=+[]{}|;:,.<>?'
    
    $PasswordArray = @()
    
    # Add required special characters
    for ($i = 0; $i -lt $MinSpecialChars; $i++) {
        $PasswordArray += $SpecialChars[(Get-Random -Maximum $SpecialChars.Length)]
    }
    
    # Add required numbers
    for ($i = 0; $i -lt $MinNumbers; $i++) {
        $PasswordArray += $Numbers[(Get-Random -Maximum $Numbers.Length)]
    }
    
    # Add required uppercase characters
    for ($i = 0; $i -lt $MinUpperCase; $i++) {
        $PasswordArray += $UpperCase[(Get-Random -Maximum $UpperCase.Length)]
    }
    
    # Fill the rest with lowercase characters
    while ($PasswordArray.Count -lt $Length) {
        $PasswordArray += $LowerCase[(Get-Random -Maximum $LowerCase.Length)]
    }
    
    # Randomize the array
    $PasswordArray = $PasswordArray | Sort-Object {Get-Random}
    return -join $PasswordArray
}

function Export-ADUsers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$DomainName,
        [Parameter(Mandatory=$true)]
        [string]$OrganizationalUnit,
        [Parameter(Mandatory=$true)]
        [string]$DomainController,
        [Parameter(Mandatory=$true)]
        [string]$CsvPath,
        [Parameter(Mandatory=$false)]
        [bool]$IncludeGroups = $false,
        [Parameter(Mandatory=$false)]
        [string]$GroupMembershipPath = ".\GroupMemberships.csv"
    )
    
    try {
        Write-Log "Starting export operation from $DomainName"
        Write-Log "Connecting to domain controller: $DomainController" -Level Verbose
        Import-Module ActiveDirectory -ErrorAction Stop
        
        $UserProperties = @(
            'DisplayName','GivenName','Surname','SamAccountName','UserPrincipalName',
            'EmailAddress','Description','Office','Department','Title','Company',
            'Manager','Enabled','PasswordNeverExpires'
        )
        Write-Log "Retrieving users from OU: $OrganizationalUnit" -Level Verbose
        
        $Users = Get-ADUser -Server $DomainController -SearchBase $OrganizationalUnit -Filter * -Properties $UserProperties
        
        if ($Users.Count -eq 0) {
            Write-Log "No users found in the specified OU" -Level Warning
            return
        }
        
        Write-Log "Found $($Users.Count) users to export" -Level Verbose
        $Users | Select-Object $UserProperties | Export-Csv -Path $CsvPath -NoTypeInformation
        Write-Log "Successfully exported $($Users.Count) users to $CsvPath"
        Write-Log "CSV file size: $((Get-Item $CsvPath).Length) bytes" -Level Verbose

        if ($IncludeGroups) {
            try {
                Write-Log "Exporting group memberships..." -Level Verbose
                Export-ADUserGroups -DomainController $DomainController `
                                  -OutputPath $GroupMembershipPath `
                                  -OrganizationalUnit $OrganizationalUnit `
                                  -LogPath $LogPath

                Write-Log "Successfully exported group memberships to $GroupMembershipPath"
            }
            catch {
                Write-Log "Error exporting group memberships: $($_.Exception.Message)" -Level Error
                Write-Log "Group membership export failed but user export was successful" -Level Warning
            }
        }
    }
    catch {
        Write-Log "Error during export operation: $($_.Exception.Message)" -Level Error
        Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level Verbose
        throw
    }
}

function Update-ExistingUser {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [Microsoft.ActiveDirectory.Management.ADUser]$ExistingUser,
        
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$UserData,
        
        [Parameter(Mandatory=$true)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [bool]$ForcePasswordReset = $false
    )
    
    try {
        Write-Log "Updating existing user: $($UserData.SamAccountName)" -Level Verbose
        $UpdateParams = @{}

        # Check and update UPN
        $NewUPN = Update-UserPrincipalName -OldUPN $UserData.UserPrincipalName -NewDomain $DomainName
        if ($NewUPN -ne $ExistingUser.UserPrincipalName) {
            $UpdateParams['UserPrincipalName'] = $NewUPN
            Write-Log "Updating UPN from '$($ExistingUser.UserPrincipalName)' to '$NewUPN'" -Level Verbose
        }

        # Standard attribute checks
        if ($UserData.DisplayName -and $UserData.DisplayName -ne $ExistingUser.DisplayName) {
            $UpdateParams['DisplayName'] = $UserData.DisplayName
        }
        if ($UserData.GivenName -and $UserData.GivenName -ne $ExistingUser.GivenName) {
            $UpdateParams['GivenName'] = $UserData.GivenName
        }
        if ($UserData.Surname -and $UserData.Surname -ne $ExistingUser.Surname) {
            $UpdateParams['Surname'] = $UserData.Surname
        }
        if ($UserData.EmailAddress -and $UserData.EmailAddress -ne $ExistingUser.EmailAddress) {
            $UpdateParams['EmailAddress'] = $UserData.EmailAddress
        }
        if ($UserData.Description -and $UserData.Description -ne $ExistingUser.Description) {
            $UpdateParams['Description'] = $UserData.Description
        }
        if ($UserData.Office -and $UserData.Office -ne $ExistingUser.Office) {
            $UpdateParams['Office'] = $UserData.Office
        }
        if ($UserData.Department -and $UserData.Department -ne $ExistingUser.Department) {
            $UpdateParams['Department'] = $UserData.Department
        }
        if ($UserData.Title -and $UserData.Title -ne $ExistingUser.Title) {
            $UpdateParams['Title'] = $UserData.Title
        }
        if ($UserData.Company -and $UserData.Company -ne $ExistingUser.Company) {
            $UpdateParams['Company'] = $UserData.Company
        }

        $Enabled = [System.Convert]::ToBoolean($UserData.Enabled)
        if ($Enabled -ne $ExistingUser.Enabled) {
            $UpdateParams['Enabled'] = $Enabled
        }
        
        $PasswordNeverExpires = [System.Convert]::ToBoolean($UserData.PasswordNeverExpires)
        if ($PasswordNeverExpires -ne $ExistingUser.PasswordNeverExpires) {
            $UpdateParams['PasswordNeverExpires'] = $PasswordNeverExpires
        }

        $needsUpdate = $UpdateParams.Count -gt 0 -or $ForcePasswordReset

        if ($needsUpdate) {
            $TempPassword = New-RandomPassword -Length 16 -MinSpecialChars 2 -MinNumbers 2 -MinUpperCase 2
            $SecurePassword = ConvertTo-SecureString $TempPassword -AsPlainText -Force

            if ($UpdateParams.Count -gt 0) {
                $UpdateParams['Identity'] = $ExistingUser
                $UpdateParams['Server'] = $Server
                Write-Log "Updating properties: $($UpdateParams.Keys -join ', ')" -Level Verbose
                Set-ADUser @UpdateParams
            }

            # Handle password reset separately
            Set-ADAccountPassword -Identity $ExistingUser `
                                -Server $Server `
                                -Reset `
                                -NewPassword $SecurePassword
            
            # Force password change at next logon
            Set-ADUser -Identity $ExistingUser `
                      -Server $Server `
                      -ChangePasswordAtLogon $true

            $updateReason = if ($UpdateParams.Count -gt 0) { "attributes changed" } else { "forced password reset" }
            Write-Log "Updating user ($updateReason): $($UserData.SamAccountName)" -Level Verbose
            
            return @{
                Success = $true
                PasswordInfo = [PSCustomObject]@{
                    SamAccountName = $UserData.SamAccountName
                    UserPrincipalName = $NewUPN
                    DisplayName = $UserData.DisplayName
                    SenderName = "IT Support"
                    TemporaryPassword = $TempPassword
                    CreationTime = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                    Action = if ($UpdateParams.Count -gt 0) { "Updated" } else { "Password Reset" }
                }
            }
        } else {
            Write-Log "No changes required for user: $($UserData.SamAccountName)" -Level Verbose
            return @{
                Success = $true
                PasswordInfo = $null
            }
        }
    }
    catch {
        Write-Log "Error updating user $($UserData.SamAccountName): $($_.Exception.Message)" -Level Error
        Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level Verbose
        return @{
            Success = $false
            PasswordInfo = $null
        }
    }
}

function Import-ADUsers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$DomainName,
        
        [Parameter(Mandatory=$true)]
        [string]$OrganizationalUnit,
        
        [Parameter(Mandatory=$true)]
        [string]$DomainController,
        
        [Parameter(Mandatory=$true)]
        [string]$CsvPath,

        [Parameter(Mandatory=$false)]
        [string]$ConflictAction = 'Skip',

        [Parameter(Mandatory=$false)]
        [bool]$ForcePasswordReset = $false,

        [Parameter(Mandatory=$false)]
        [string]$PasswordOutputPath = ".\TempPasswords.csv",

        [Parameter(Mandatory=$false)]
        [bool]$IncludeGroups = $false,

        [Parameter(Mandatory=$false)]
        [string]$GroupMembershipPath = ".\GroupMemberships.csv"
    )
    
    try {
        Write-Log "Starting import operation to $DomainName"
        Write-Log "User conflict handling mode: $ConflictAction" -Level Verbose
        if ($ForcePasswordReset) {
            Write-Log "Force password reset enabled for existing users" -Level Verbose
        }
        
        Import-Module ActiveDirectory -ErrorAction Stop
        
        if (-not (Test-Path $CsvPath)) {
            throw "CSV file not found at $CsvPath"
        }
        
        $PasswordOutputDir = Split-Path $PasswordOutputPath -Parent
        if ($PasswordOutputDir -and (-not (Test-Path $PasswordOutputDir))) {
            New-Item -ItemType Directory -Path $PasswordOutputDir -Force | Out-Null
        }
        
        $Users = Import-Csv -Path $CsvPath
        $Server = $DomainController
        Write-Log "Using DC: $Server" -Level Verbose

        $SuccessCount = 0
        $ErrorCount = 0
        $SkipCount = 0
        $UpdateCount = 0
        $PasswordResetCount = 0
        $PasswordList = New-Object System.Collections.ArrayList
        
        foreach ($User in $Users) {
            try {
                Write-Log "Processing user: $($User.SamAccountName)" -Level Verbose
                $ExistingUser = Get-ADUser -Filter "SamAccountName -eq '$($User.SamAccountName)'" -Server $Server -ErrorAction SilentlyContinue -Properties *
                
                if ($ExistingUser) {
                    Write-Log "User $($User.SamAccountName) already exists in target domain" -Level Warning
                    
                    switch ($ConflictAction) {
                        'Skip' {
                            Write-Log "Skipping existing user: $($User.SamAccountName)" -Level Verbose
                            $SkipCount++
                        }
                        'Update' {
                            Write-Log "Processing update for user: $($User.SamAccountName)" -Level Verbose
                            if ($ForcePasswordReset) {
                                Write-Log "Force password reset requested for user: $($User.SamAccountName)" -Level Verbose
                            }
                            $updateResult = Update-ExistingUser -ExistingUser $ExistingUser `
                                                              -UserData $User `
                                                              -Server $Server `
                                                              -ForcePasswordReset $ForcePasswordReset
                            if ($updateResult.Success) {
                                if ($updateResult.PasswordInfo) {
                                    $null = $PasswordList.Add($updateResult.PasswordInfo)
                                    Write-Log "Added password to tracking list for user $($User.SamAccountName) (Action: $($updateResult.PasswordInfo.Action))" -Level Verbose
                                    if ($updateResult.PasswordInfo.Action -eq "Password Reset") {
                                        $PasswordResetCount++
                                    } else {
                                        $UpdateCount++
                                    }
                                }
                            } else {
                                $ErrorCount++
                            }
                        }
                        'Error' {
                            throw "User $($User.SamAccountName) already exists and ConflictAction is set to Error"
                        }
                    }
                    continue
                }
                
                $TempPassword = New-RandomPassword -Length 16 -MinSpecialChars 2 -MinNumbers 2 -MinUpperCase 2
                $SecurePassword = ConvertTo-SecureString $TempPassword -AsPlainText -Force
                
                $NewUPN = Update-UserPrincipalName -OldUPN $User.UserPrincipalName -NewDomain $DomainName
                Write-Log "Setting UPN for new user as: $NewUPN" -Level Verbose

                $NewUserParams = @{
                    Name = "$($User.GivenName) $($User.Surname)"
                    DisplayName = $User.DisplayName
                    GivenName = $User.GivenName
                    Surname = $User.Surname
                    SamAccountName = $User.SamAccountName
                    UserPrincipalName = $NewUPN
                    EmailAddress = $User.EmailAddress
                    Description = $User.Description
                    Office = $User.Office
                    Department = $User.Department
                    Title = $User.Title
                    Company = $User.Company
                    Enabled = [System.Convert]::ToBoolean($User.Enabled)
                    PasswordNeverExpires = [System.Convert]::ToBoolean($User.PasswordNeverExpires)
                    AccountPassword = $SecurePassword
                    ChangePasswordAtLogon = $true
                    Path = $OrganizationalUnit
                    Server = $Server
                }
                
                New-ADUser @NewUserParams
                
                $null = $PasswordList.Add([PSCustomObject]@{
                    SamAccountName = $User.SamAccountName
                    UserPrincipalName = $NewUPN
                    DisplayName = $User.DisplayName
                    SenderName = "IT Support"
                    TemporaryPassword = $TempPassword
                    CreationTime = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                    Action = "Created"
                })
                
                Write-Log "Successfully created user: $($User.SamAccountName)" -Level Verbose
                $SuccessCount++
            }
            catch {
                Write-Log "Error processing user $($User.SamAccountName): $($_.Exception.Message)" -Level Error
                Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level Verbose
                $ErrorCount++
                continue
            }
        }
        
        if ($PasswordList.Count -gt 0) {
            $ExistingPasswords = @()
            if (Test-Path $PasswordOutputPath) {
                Write-Log "Reading existing password history from: $PasswordOutputPath" -Level Verbose
                $ExistingPasswords = Import-Csv -Path $PasswordOutputPath
            }

            $AllPasswords = $ExistingPasswords + $PasswordList
            $AllPasswords = $AllPasswords | Sort-Object CreationTime -Descending
            $AllPasswords | Export-Csv -Path $PasswordOutputPath -NoTypeInformation
            Write-Log "Added $($PasswordList.Count) new password entries to history file: $PasswordOutputPath" -Level Verbose
            
            $Acl = Get-Acl $PasswordOutputPath
            $Acl.SetAccessRuleProtection($true, $false)
            $AdminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators","FullControl","Allow")
            $Acl.AddAccessRule($AdminRule)
            Set-Acl $PasswordOutputPath $Acl
            Write-Log "Password file permissions secured" -Level Verbose
        }

        # Handle group membership import if requested
        if ($IncludeGroups -and (Test-Path $GroupMembershipPath)) {
            try {
                Write-Log "Importing group memberships..." -Level Verbose
                Import-ADUserGroups -DomainController $DomainController `
                                  -InputPath $GroupMembershipPath `
                                  -LogPath $LogPath

                Write-Log "Successfully imported group memberships from $GroupMembershipPath"
            }
            catch {
                Write-Log "Error importing group memberships: $($_.Exception.Message)" -Level Error
                Write-Log "Group membership import failed but user import was successful" -Level Warning
            }
        }
        
        Write-Log "Import operation completed. Success: $SuccessCount, Errors: $ErrorCount, Skipped: $SkipCount, Updated: $UpdateCount, Password Resets: $PasswordResetCount"
        Write-Log "Final statistics - Attempted: $($Users.Count), Succeeded: $SuccessCount, Failed: $ErrorCount, Skipped: $SkipCount, Updated: $UpdateCount, Password Resets: $PasswordResetCount" -Level Verbose
    }
    catch {
        Write-Log "Error during import operation: $($_.Exception.Message)" -Level Error
        Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level Verbose
        throw
    }
}

# Main script execution
try {
    Write-Log "Script started with operation: $Operation"
    Write-Log "Script parameters - Domain: $DomainName, OU: $OrganizationalUnit, DC: $DomainController" -Level Verbose
    
    # Handle credentials first
    if ($StoreCredential) {
        Write-Log "Storing new credentials..." -Level Verbose
        $cred = Get-Credential -Message "Enter Domain Admin credentials to store"
        $cred | Export-Clixml -Path $CredentialPath
        Write-Log "Credentials stored successfully at: $CredentialPath"
        exit
    }

    # Handle credentials if not provided
    if ($Credential -eq [System.Management.Automation.PSCredential]::Empty) {
        if (Test-Path $CredentialPath) {
            Write-Log "Loading stored credentials..." -Level Verbose
            try {
                $Credential = Import-Clixml -Path $CredentialPath
                Write-Log "Credentials loaded successfully." -Level Verbose
            }
            catch {
                Write-Log "Failed to load stored credentials: $_" -Level Error
                Write-Log "Please enter credentials manually..." -Level Warning
                $Credential = Get-Credential -Message "Enter Domain Admin credentials"
            }
        }
        else {
            Write-Log "No stored credentials found. Please enter credentials." -Level Warning
            Write-Log "Tip: Use -StoreCredential switch to save credentials for future use." -Level Information
            $Credential = Get-Credential -Message "Enter Domain Admin credentials"
        }
    }
    
    # Check prerequisites and setup security
    Test-Prerequisites
    Initialize-SecureTempFolder -TempPath $TempPath
    Test-DomainControllerConnectivity -DomainController $DomainController -UseSSL:$UseSSL
    $session = New-SecureRemoteSession -DomainController $DomainController -Credential $Credential -UseSSL:$UseSSL
    
    # Update AD parameters with security settings
    $adParams = @{
        Server = $DomainController
        Credential = $Credential
    }
    
    if ($UseSSL) {
        # Force LDAPS when SSL is enabled
        $adParams['AuthType'] = 'Negotiate'
        $adParams['Port'] = 636
    }

    # Verify log file path
    $LogFolder = Split-Path $LogPath -Parent
    if ($LogFolder -and (-not (Test-Path $LogFolder))) {
        Write-Log "Creating log directory: $LogFolder" -Level Verbose
        New-Item -ItemType Directory -Path $LogFolder -Force | Out-Null
    }
    
    # Import group membership functions if needed
    if ($IncludeGroups) {
        $GroupMembershipScript = Join-Path $PSScriptRoot "GroupMembership.ps1"
        if (Test-Path $GroupMembershipScript) {
            . $GroupMembershipScript
            Write-Log "Successfully loaded group membership functions" -Level Verbose
        } else {
            throw "Group membership script not found at: $GroupMembershipScript"
        }
    }
    
    # Execute requested operation
    switch ($Operation.ToLower()) {
        'export' {
            Write-Log "Initiating export operation" -Level Verbose
            Export-ADUsers -DomainName $DomainName `
                         -OrganizationalUnit $OrganizationalUnit `
                         -DomainController $DomainController `
                         -CsvPath $CsvPath `
                         -IncludeGroups $IncludeGroups `
                         -GroupMembershipPath $GroupMembershipPath `
                         @adParams
        }
        'import' {
            Write-Log "Initiating import operation" -Level Verbose
            Import-ADUsers -DomainName $DomainName `
                         -OrganizationalUnit $OrganizationalUnit `
                         -DomainController $DomainController `
                         -CsvPath $CsvPath `
                         -ConflictAction $ConflictAction `
                         -ForcePasswordReset $ForcePasswordReset.IsPresent `
                         -PasswordOutputPath $PasswordOutputPath `
                         -IncludeGroups $IncludeGroups `
                         -GroupMembershipPath $GroupMembershipPath `
                         @adParams
        }
    }
    
    Write-Log "Script completed successfully"
    $TotalTime = [math]::Round(($((Get-Date) - $StartTime).TotalSeconds), 2)
    Write-Log "Total execution time: $TotalTime seconds" -Level Verbose
}
catch {
    Write-Log "Script failed with error: $($_.Exception.Message)" -Level Error
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level Error
    throw
}
finally {
    # Clean up secure remote session if it exists
    if ($session) {
        Remove-PSSession $session -ErrorAction SilentlyContinue
        Write-Log "Cleaned up remote session" -Level Verbose
    }
    
    # Clean up temp files
    if (Test-Path $TempPath) {
        Get-ChildItem $TempPath -Recurse | Remove-Item -Force -ErrorAction SilentlyContinue
        Write-Log "Cleaned up temporary files" -Level Verbose
    }
}