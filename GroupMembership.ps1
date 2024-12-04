<# 
.SYNOPSIS
    Exports and imports Active Directory user group memberships.

.DESCRIPTION
    This script provides functions to export and import Active Directory group memberships.
    It can export memberships for specific users or all users in an OU, and import those
    memberships to the same or different domain. The script handles missing users/groups
    gracefully and includes detailed logging.

.NOTES
    Author: John A. O'Neill Sr.
    Date: 11/24/2024
    Version: 1.0
    Change Date:
    Change Purpose:
    Prerequisite:   PowerShell Version 5.1 or later
                    ActiveDirectory PowerShell Module
                    Domain Admin rights in both source and target domains

.LINK
    https://learn.microsoft.com/en-us/powershell/module/activedirectory/
#>

function Export-ADUserGroups {
    <#
    .SYNOPSIS
        Exports Active Directory group memberships for specified users or OU.

    .DESCRIPTION
        Exports group memberships for either specific users (by SamAccountName) or all users
        in a specified Organizational Unit. The export includes group names and distinguished
        names for reliable importing later. Excludes the "Domain Users" group as it's automatically
        assigned.

    .PARAMETER DomainController
        The domain controller to connect to for the export operation.

    .PARAMETER OutputPath
        The path where the CSV file containing group memberships will be saved.

    .PARAMETER SamAccountNames
        Optional. An array of SamAccountNames to export group memberships for.
        Either this or OrganizationalUnit must be specified.

    .PARAMETER OrganizationalUnit
        Optional. The distinguished name of the OU containing users to export group memberships for.
        Either this or SamAccountNames must be specified.

    .PARAMETER LogPath
        Optional. The path where log files will be written.
        Default: ".\GroupMembership.log"

    .EXAMPLE
        Export-ADUserGroups -DomainController "dc1.domain.com" -OutputPath ".\UserGroups.csv" -SamAccountNames "user1","user2"
        Exports group memberships for specific users.

    .EXAMPLE
        Export-ADUserGroups -DomainController "dc1.domain.com" -OutputPath ".\UserGroups.csv" -OrganizationalUnit "OU=Users,DC=domain,DC=com"
        Exports group memberships for all users in the specified OU.

    .NOTES
        The export creates a CSV file with columns: SamAccountName, GroupName, GroupDN
        This format is compatible with the Import-ADUserGroups function.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$DomainController,

        [Parameter(Mandatory=$true)]
        [string]$OutputPath,

        [Parameter(Mandatory=$false)]
        [string[]]$SamAccountNames,

        [Parameter(Mandatory=$false)]
        [string]$OrganizationalUnit,

        [Parameter(Mandatory=$false)]
        [string]$LogPath = ".\GroupMembership.log"
    )

    try {
        # Function to write logs
        function Write-GroupLog {
            param($Message, $Level = 'Information')
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

        Write-GroupLog "Starting group membership export"
        Import-Module ActiveDirectory -ErrorAction Stop

        # Get users based on input parameters
        if ($SamAccountNames) {
            Write-GroupLog "Getting users from provided SamAccountNames" -Level Verbose
            $Users = foreach ($sam in $SamAccountNames) {
                Get-ADUser -Identity $sam -Server $DomainController -ErrorAction SilentlyContinue
            }
        }
        elseif ($OrganizationalUnit) {
            Write-GroupLog "Getting users from OU: $OrganizationalUnit" -Level Verbose
            $Users = Get-ADUser -SearchBase $OrganizationalUnit -Filter * -Server $DomainController
        }
        else {
            throw "Either SamAccountNames or OrganizationalUnit must be provided"
        }

        $Results = @()
        $ProcessedCount = 0
        $TotalUsers = ($Users | Measure-Object).Count
        Write-GroupLog "Found $TotalUsers users to process"

        foreach ($User in $Users) {
            $ProcessedCount++
            Write-GroupLog "Processing user $($User.SamAccountName) ($ProcessedCount of $TotalUsers)" -Level Verbose
            
            $Groups = Get-ADPrincipalGroupMembership -Identity $User.SamAccountName -Server $DomainController |
                     Where-Object { $_.Name -ne "Domain Users" } |
                     Select-Object Name, DistinguishedName

            foreach ($Group in $Groups) {
                $Results += [PSCustomObject]@{
                    SamAccountName = $User.SamAccountName
                    GroupName = $Group.Name
                    GroupDN = $Group.DistinguishedName
                }
            }
        }

        # Export results
        $Results | Export-Csv -Path $OutputPath -NoTypeInformation
        Write-GroupLog "Successfully exported group memberships to $OutputPath"
        Write-GroupLog "Processed $ProcessedCount users and found $($Results.Count) group memberships"
    }
    catch {
        Write-GroupLog "Error during group export: $($_.Exception.Message)" -Level Error
        Write-GroupLog $_.ScriptStackTrace -Level Verbose
        throw
    }
}

function Import-ADUserGroups {
    <#
    .SYNOPSIS
        Imports Active Directory group memberships from a CSV file and optionally creates missing groups.

    .DESCRIPTION
        This function imports group memberships from a CSV file created by Export-ADUserGroups.
        It can optionally create missing groups in a specified OU and add users to them.
        The function handles existing memberships, missing users, and provides detailed logging
        of all operations.

    .PARAMETER DomainController
        Required. The FQDN of the domain controller to connect to for the import operation.
        Example: "dc1.domain.com"

    .PARAMETER InputPath
        Required. The path to the CSV file containing group memberships to import.
        Must be in the format created by Export-ADUserGroups with columns:
        SamAccountName, GroupName, GroupDN

    .PARAMETER TargetOU
        Optional. The distinguished name of the OU where new groups should be created
        if they don't exist and CreateMissingGroups is specified.
        Example: "OU=Groups,DC=domain,DC=com"

    .PARAMETER LogPath
        Optional. The path where log files will be written.
        Default: ".\GroupMembership.log"

    .PARAMETER WhatIf
        Optional. Shows what changes would be made without actually making them.
        Useful for testing before making actual changes.

    .PARAMETER CreateMissingGroups
        Optional. When specified, creates groups that don't exist in the target domain.
        Groups will be created in the OU specified by TargetOU parameter.
        New groups are created as Global Security groups.

    .EXAMPLE
        # Basic import of group memberships
        Import-ADUserGroups -DomainController "dc1.domain.com" -InputPath ".\Groups.csv"

    .EXAMPLE
        # Import with creation of missing groups
        Import-ADUserGroups -DomainController "dc1.domain.com" `
                           -InputPath ".\Groups.csv" `
                           -TargetOU "OU=Groups,DC=domain,DC=com" `
                           -CreateMissingGroups

    .EXAMPLE
        # Test import without making changes
        Import-ADUserGroups -DomainController "dc1.domain.com" `
                           -InputPath ".\Groups.csv" `
                           -TargetOU "OU=Groups,DC=domain,DC=com" `
                           -CreateMissingGroups `
                           -WhatIf

    .NOTES
        The import process:
        1. Verifies user exists in target domain
        2. Checks if group exists
        3. Creates group if missing (when CreateMissingGroups is specified)
        4. Skips if user is already a member
        5. Adds user to group if all checks pass

        New groups are created with the following default settings:
        - Group Scope: Global
        - Group Category: Security

    .OUTPUTS
        None. This function writes output to the log file and console.
        Statistics are provided upon completion:
        - Number of successful additions
        - Number of errors
        - Number of skipped operations
        - Number of groups created
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$DomainController,

        [Parameter(Mandatory=$true)]
        [string]$InputPath,

        [Parameter(Mandatory=$false)]
        [string]$TargetOU,

        [Parameter(Mandatory=$false)]
        [string]$LogPath = ".\GroupMembership.log",

        [Parameter(Mandatory=$false)]
        [switch]$WhatIf,

        [Parameter(Mandatory=$false)]
        [switch]$CreateMissingGroups
    )

    try {
        function Write-GroupLog {
            param($Message, $Level = 'Information')
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

        Write-GroupLog "Starting group membership import"
        Import-Module ActiveDirectory -ErrorAction Stop

        if (-not (Test-Path $InputPath)) {
            throw "Input file not found: $InputPath"
        }

        $Memberships = Import-Csv -Path $InputPath
        $SuccessCount = 0
        $ErrorCount = 0
        $SkipCount = 0
        $GroupsCreated = 0
        $Total = ($Memberships | Measure-Object).Count

        Write-GroupLog "Found $Total group memberships to process"

        foreach ($Membership in $Memberships) {
            try {
                Write-GroupLog "Processing membership: $($Membership.SamAccountName) -> $($Membership.GroupName)" -Level Verbose

                # Verify user exists
                $User = Get-ADUser -Identity $Membership.SamAccountName -Server $DomainController -ErrorAction SilentlyContinue
                if (-not $User) {
                    Write-GroupLog "User $($Membership.SamAccountName) not found - skipping" -Level Warning
                    $SkipCount++
                    continue
                }

                # Try to find group by name first
                $Group = Get-ADGroup -Filter "Name -eq '$($Membership.GroupName)'" -Server $DomainController -ErrorAction SilentlyContinue

                # If group doesn't exist and CreateMissingGroups is specified
                if (-not $Group -and $CreateMissingGroups) {
                    if ($WhatIf) {
                        Write-GroupLog "WhatIf: Would create group $($Membership.GroupName) in $TargetOU" -Level Warning
                    }
                    else {
                        try {
                            $NewGroupParams = @{
                                Name = $Membership.GroupName
                                GroupScope = 'Global'  # Default to Global scope
                                GroupCategory = 'Security'  # Default to Security group
                                Path = $TargetOU
                                Server = $DomainController
                            }
                            $Group = New-ADGroup @NewGroupParams -PassThru
                            Write-GroupLog "Created new group: $($Membership.GroupName)" -Level Warning
                            $GroupsCreated++
                        }
                        catch {
                            Write-GroupLog "Failed to create group $($Membership.GroupName): $($_.Exception.Message)" -Level Error
                            continue
                        }
                    }
                }
                elseif (-not $Group) {
                    Write-GroupLog "Group $($Membership.GroupName) not found - skipping" -Level Warning
                    $SkipCount++
                    continue
                }

                # Check if user is already a member
                $IsMember = Get-ADGroupMember -Identity $Group -Server $DomainController | 
                           Where-Object { $_.SamAccountName -eq $User.SamAccountName }
                
                if ($IsMember) {
                    Write-GroupLog "$($User.SamAccountName) is already a member of $($Group.Name) - skipping" -Level Verbose
                    $SkipCount++
                    continue
                }

                if ($WhatIf) {
                    Write-GroupLog "WhatIf: Would add $($User.SamAccountName) to $($Group.Name)" -Level Warning
                    $SuccessCount++
                }
                else {
                    Add-ADGroupMember -Identity $Group -Members $User -Server $DomainController
                    Write-GroupLog "Added $($User.SamAccountName) to $($Group.Name)"
                    $SuccessCount++
                }
            }
            catch {
                Write-GroupLog "Error processing membership for $($Membership.SamAccountName): $($_.Exception.Message)" -Level Error
                Write-GroupLog $_.ScriptStackTrace -Level Verbose
                $ErrorCount++
            }
        }

        Write-GroupLog "Import completed. Success: $SuccessCount, Errors: $ErrorCount, Skipped: $SkipCount, Groups Created: $GroupsCreated"
    }
    catch {
        Write-GroupLog "Error during group import: $($_.Exception.Message)" -Level Error
        Write-GroupLog $_.ScriptStackTrace -Level Verbose
        throw
    }
}
