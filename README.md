# AD Migration Script

A PowerShell script for migrating Active Directory users between domains with support for group membership transfer, conflict handling, and comprehensive logging.

## Features

- Export users from source domain with all relevant attributes
- Import users to target domain with configurable conflict handling
- Optional group membership migration
- Automatic UPN domain update during import
- Secure temporary password generation and storage
- Appends to password history file with timestamps
- Password reset for updated users
- Force password reset option for existing users
- Comprehensive logging with verbose option
- Detailed error handling and statistics
- Progress reporting and execution tracking

## Prerequisites

- PowerShell Version 5.1 or later
- ActiveDirectory PowerShell Module
- Domain Admin rights in both source and target domains
- GroupMembership.ps1 script (if using -IncludeGroups)

## Parameters

### Required Parameters

- **Operation** (Required)
  - Values: 'export' or 'import'
  - Specifies whether to export users from source domain or import to target domain

- **DomainName** (Required)
  - The FQDN of the domain to operate on
  - For export: Source domain containing users to export
  - For import: Target domain where users will be created
  - Also used as the new UPN suffix for imported users

- **OrganizationalUnit** (Required)
  - The distinguished name of the OU to operate on
  - For export: Source OU containing users to export
  - For import: Target OU where users will be created
  - Example: "OU=Users,DC=contoso,DC=local"

- **DomainController** (Required)
  - The FQDN of the domain controller to connect to
  - Example: "DC1.contoso.local"

### Optional Parameters

- **CsvPath**
  - File path for the CSV file used in export/import operations
  - Default: ".\ADUsers.csv"

- **LogPath**
  - File path where logs will be written
  - Default: ".\ADMigration.log"

- **ConflictAction**
  - Specifies how to handle existing users during import
  - Values: 'Skip', 'Update', 'Error'
  - Skip: Skip the user and continue (default)
  - Update: Update existing user with new information and reset password
  - Error: Throw an error and stop the script
  - Default: Skip

- **PasswordOutputPath**
  - File path where temporary passwords will be stored
  - File is automatically secured to allow access only to administrators
  - Passwords are appended with timestamps for historical tracking
  - Default: ".\TempPasswords.csv"

- **ForcePasswordReset**
  - When specified with ConflictAction 'Update', forces password reset for existing users
  - Default: False

- **IncludeGroups**
  - When specified, exports and imports user group memberships
  - Requires GroupMembership.ps1 script in same directory
  - Default: False

- **GroupMembershipPath**
  - File path for the CSV file used to store group memberships
  - Default: ".\GroupMemberships.csv"

## Examples

### Export Users from Source Domain
```powershell
.\AD-Migration.ps1 -Operation export `
                   -DomainName "source.local" `
                   -OrganizationalUnit "OU=Users,DC=source,DC=local" `
                   -DomainController "DC1.source.local" `
                   -Verbose
```

### Export Users and Their Group Memberships
```powershell
.\AD-Migration.ps1 -Operation export `
                   -DomainName "source.local" `
                   -OrganizationalUnit "OU=Users,DC=source,DC=local" `
                   -DomainController "DC1.source.local" `
                   -IncludeGroups `
                   -Verbose
```

### Import Users with Group Memberships and Force Password Resets
```powershell
.\AD-Migration.ps1 -Operation import `
                   -DomainName "target.local" `
                   -OrganizationalUnit "OU=Users,DC=target,DC=local" `
                   -DomainController "DC1.target.local" `
                   -ConflictAction Update `
                   -ForcePasswordReset `
                   -IncludeGroups `
                   -Verbose
```

## Validation Checks

The script performs the following checks and validations:
- Verifies the existence of specified domain controllers
- Validates the existence of specified OUs
- Checks for existing users during import
- Verifies file paths and creates directories as needed

## Additional Resources

For more information about the ActiveDirectory PowerShell Module:
[Microsoft Documentation](https://learn.microsoft.com/en-us/powershell/module/activedirectory/)

## Author
John A. O'Neill Sr.

## Version History
- Version: 1.2
- Last Updated: 12/03/2024
- Change Purpose: Add fields to temporary password CSV file
