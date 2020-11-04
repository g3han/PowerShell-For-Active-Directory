<#
.Synopsis
   Script for retrieving base Domain and Forest information for auditing purposes.
.DESCRIPTION
   The script runs under the privilages of the current user against the Microsft Active Directory
   the host where the script is currently being run is joined to. The sript performs the following actions:
   * Enumerated the current domain functional level.
   * Enumerates the current domain trusts relationships.
   * Enumerates the current domain password policy.
   * Enumerates all sites for the forest the domain is part off.
   * Enumerates general domain information for the current domain. 
   * Enumerates the current domain domain controllers and their information.
   * Checks if each domain controller in the current domain is a Virtual Machine and what type of Hypervisor (Xen, VMware and Hyper-V).
   * Enumerates all groups for the current domain.
   * Enumerates all user accounts for the current domain.
   * Enumerates all never logged on user accounts for the current domain.
   * Enumerates all disabled user accounts for the current domain.
   * Enumerates all user accounts that have not logged on in the last 180 days for the current domain.
   * Enumerates all user accounts whos password does not expires for the current domain.
   * Enumerates all user accounts who have a missing SN or email field for the current domain.
   * Enumerates all user accounts that can not change their password in the current domain.
   * Enumerates all accounts and groups whose name starts with a given prefix.

    
   Each query is perform individually so in the case of a problem with the script, data or network the data for the set of enumerations
   that have run are still available. 
.EXAMPLE
   script01.ps1 -Limit 10000 -Path .

   Retrieve a maximun of 10,000 users account instead of the default 1,000 and save the results to the cureent path.
.EXAMPLE
   script01.ps1 -Prefix ADX -Path .

   Retrieve the default 1,000 maximun of user accounts and save the results to the cureent path with each file having ADX appended to the beguining of each.
.NOTES
   Script has been tested against Windows PowerShell 2.0, 4.0 and 5.0. The script can be ran either form a 
   domain controller or a host that is domain joined using a domain administrator account since it does not
   have any dependency on any of the ActiveDirectory PowerShell modules and uses ADSI (Active Directory Scripting
   Interface) to retrieve all information from active directory.

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false,
        HelpMessage='Maximum number of Objects to retrieve from AD, default is 1,000 .')]
    [int]$Limit = 1000,

    [Parameter(Mandatory=$true,
        HelpMessage='Relative or full path where to saved the output.')]
    [string]$Path,

    [Parameter(Mandatory=$false,
        HelpMessage='Text to prefix to the beguinig of the name of the files created')]
    [string]$Prefix = 'AD',

    [Parameter(Mandatory=$false,
        HelpMessage='Wildcard expression to search either on the start of end of the name of users and groups to enumerate. ')]
    [string]$StringSearch
)


<#
.Synopsis
   Enumerates all user in the current domain the host is a member of. 
.DESCRIPTION
   Enumerates all user in the current domain the host is a member of. 
.EXAMPLE
   Get-ADSUser -Limit 2000

   Gets up to 2000 users from the current domain.
#>
function Get-ADDSUser
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$false,
            HelpMessage='Maximum number of Objects to retrieve from AD, default is 1,000 .')]
        [int]$Limit = 1000,

        [Parameter(Mandatory=$false,
            HelpMessage = 'Name of SAMAccount to search for.')]
        [string]$SamAccount
    )

    Begin{}
    Process
    {
        if ($SamAccount.Length -gt 0)
        {
            $Filter = "(&(sAMAccountType=805306368)(sAMAccountName=$($SamAccount)))"   
        }
        else
        {
            $Filter = '(sAMAccountType=805306368)'
        }
        $objDomain = [ADSI]'' 
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $objSearcher.Filter = $Filter
        $ObjSearcher.PageSize = 500
        $objSearcher.SizeLimit = $Limit

        $objSearcher.FindAll() | ForEach-Object {
            $UserProps = @{}
            $UserProps.Add('SAMAccount', "$($_.properties.samaccountname)")
            $UserProps.Add('Description', ("$($_.properties.description)").replace('`n','').replace(',',';'))
            $UserProps.Add('UserPrincipal', "$($_.properties.userprincipalname)")
            $UserProps.Add('DN', "$($_.properties.distinguishedname)")
            try
            {
                $userProps.Add('Created', [dateTime]"$($groupMember.whencreated)")
            }
            catch
            {
                $userProps.Add('Created','')
            }

            try
            {
                $userProps.Add('LastModified', [dateTime]"$($groupMember.whenchanged)")
            }
            catch
            {
                $userProps.Add('LastModified','')
                    
            }

            try
            {
                $userProps.Add('PasswordLastSet', [dateTime]::FromFileTime("$($group.ConvertLargeIntegerToInt64($groupMember.pwdlastset[0]))"))
            }
            catch
            {
                $userProps.Add('PasswordLastSet','')
            }
            $UserProps.Add('AccountExpires',( &{
            
                Try
                {
                    $exval = "$($_.properties.accountexpires)"
                    If (($exval -eq 0) -or ($exval -gt [DateTime]::MaxValue.Ticks))
                    {
                        $AcctExpires = '<Never>'
                    }
                    Else
                    {
                        $Date = [DateTime]$exval
                        $AcctExpires = $Date.AddYears(1600).ToLocalTime()
                    }
                    $AcctExpires
                }
                catch
                {
                    '<never>'
                }
            
            }))
            $UserProps.Add('LastLogon', [dateTime]::FromFileTime("$($_.properties.lastlogon)"))
            $UserProps.Add('GroupMembership', "$($_.properties.memberof)")
            $UserProps.Add('SID', "$(&{$sidobj = [byte[]]"$($_.Properties.objectsid)".split(' ');$sid = new-object System.Security.Principal.SecurityIdentifier $sidobj, 0; $sid.Value})")
            New-Object -TypeName psobject -Property $UserProps
        }
    }
    End{}
}

<#
.Synopsis
   Enumerates all user account that have never logged on in the current domain. 
.DESCRIPTION
   Enumerates all user account that have never logged on.
.EXAMPLE
   Get-ADDSUserNeverLoggedOn -limit 500
#>
function Get-ADDSUserNeverLoggedOn
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$false,
            HelpMessage='Maximum number of Objects to retrieve from AD, default is 1,000 .')]
        [int]$Limit = 1000
    )

    Begin{}
    Process
    {
        $UserFilter = '(&(sAMAccountType=805306368)(lastLogon=0))'
        $objDomain = [ADSI]'' 
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = 500
        $objSearcher.SizeLimit = $Limit
        $objSearcher.Filter = $UserFilter
        
        $objSearcher.FindAll() | ForEach-Object {

                $UserProps = @{}
                $UserProps.Add('SAMAccount', "$($_.properties.samaccountname)")
                $UserProps.Add('Description', ("$($_.properties.description)").replace('`n','').replace(',',';'))
                $UserProps.Add('UserPrincipal', "$($_.properties.userprincipalname)")
                $UserProps.Add('DN', "$($_.properties.distinguishedname)")
                try
                {
                    $userProps.Add('Created', [dateTime]"$($groupMember.whencreated)")
                }
                catch
                {
                    $userProps.Add('Created','')
                }

                try
                {
                    $userProps.Add('LastModified', [dateTime]"$($groupMember.whenchanged)")
                }
                catch
                {
                    $userProps.Add('LastModified','')
                    
                }

                try
                {
                    $userProps.Add('PasswordLastSet', [dateTime]::FromFileTime("$($group.ConvertLargeIntegerToInt64($groupMember.pwdlastset[0]))"))
                }
                catch
                {
                    $userProps.Add('PasswordLastSet','')
                }
                $UserProps.Add('AccountExpires',( &{
                    Try
                    {
                        $exval = "$($_.properties.accountexpires)"
                        If (($exval -eq 0) -or ($exval -gt [DateTime]::MaxValue.Ticks))
                        {
                            $AcctExpires = '<Never>'
                        }
                        Else
                        {
                            $Date = [DateTime]$exval
                            $AcctExpires = $Date.AddYears(1600).ToLocalTime()
                        }
                        $AcctExpires
                    }
                    catch
                    {
                        '<never>'
                    }
            
                }))
                $UserProps.Add('LastLogon', [dateTime]::FromFileTime("$($_.properties.lastlogon)"))
                $UserProps.Add('GroupMembership', "$($_.properties.memberof)")
                $UserProps.Add('SID', "$(&{$sidobj = [byte[]]"$($_.Properties.objectsid)".split(' ');$sid = new-object System.Security.Principal.SecurityIdentifier $sidobj, 0; $sid.Value})")
                New-Object -TypeName psobject -Property $UserProps
  
        }
    }
    End{}
}

<#
.Synopsis
   Enumerates all user account that are disabled on in the current domain. 
.DESCRIPTION
   Enumerates all user account that are disabled in the current domain. 
.EXAMPLE
   Get-ADDSUserDisabled -Limit 1000
#>
function Get-ADDSUserDisabled
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$false,
            HelpMessage='Maximum number of Objects to pull from AD, default is 1,000 .')]
        [int]$Limit = 1000
    )

    Begin{}
    Process
    {
        $Filter = '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))'
        $objDomain = [ADSI]'' 
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $objSearcher.Filter = $Filter
        $ObjSearcher.PageSize = 500
        $objSearcher.SizeLimit = $Limit


        $objSearcher.FindAll() | ForEach-Object {
            $UserProps = @{}
            $UserProps.Add('SAMAccount', "$($_.properties.samaccountname)")
            $UserProps.Add('Description', ("$($_.properties.description)").replace('`n','').replace(',',';'))
            $UserProps.Add('UserPrincipal', "$($_.properties.userprincipalname)")
            $UserProps.Add('DN', "$($_.properties.distinguishedname)")
            try
            {
                $userProps.Add('Created', [dateTime]"$($groupMember.whencreated)")
            }
            catch
            {
                $userProps.Add('Created','')
            }

            try
            {
                $userProps.Add('LastModified', [dateTime]"$($groupMember.whenchanged)")
            }
            catch
            {
                $userProps.Add('LastModified','')
                    
            }

            try
            {
                $userProps.Add('PasswordLastSet', [dateTime]::FromFileTime("$($group.ConvertLargeIntegerToInt64($groupMember.pwdlastset[0]))"))
            }
            catch
            {
                $userProps.Add('PasswordLastSet','')
            }
            $UserProps.Add('AccountExpires',( &{
            
                Try
                {
                    $exval = "$($_.properties.accountexpires)"
                    If (($exval -eq 0) -or ($exval -gt [DateTime]::MaxValue.Ticks))
                    {
                        $AcctExpires = '<Never>'
                    }
                    Else
                    {
                        $Date = [DateTime]$exval
                        $AcctExpires = $Date.AddYears(1600).ToLocalTime()
                    }
                    $AcctExpires
                }
                catch
                {
                    '<never>'
                }
            
            }))
            $UserProps.Add('LastLogon', [dateTime]::FromFileTime("$($_.properties.lastlogon)"))
            $UserProps.Add('GroupMembership', "$($_.properties.memberof)")
            $UserProps.Add('SID', "$(&{$sidobj = [byte[]]"$($_.Properties.objectsid)".split(' ');$sid = new-object System.Security.Principal.SecurityIdentifier $sidobj, 0; $sid.Value})")
            New-Object -TypeName psobject -Property $UserProps
        }
    }
    End{}
}

<#
.Synopsis
   Enumerates all user account thathave not logged in in the last 180 days in the current domain. 
.DESCRIPTION
   Enumerates all user account thathave not logged in in the last 180 days in the current domain. 
.EXAMPLE
   Get-ADDSUserAbandoned -Limit 1000
#>
function Get-ADDSUserAbandoned
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$false,
            HelpMessage='Maximum number of Objects to pull from AD, default is 1,000 .')]
        [int]$Limit = 1000
    )

    Begin{}
    Process
    {
       
        $180DaysAgo = (Get-Date).AddDays(-180).ToFileTimeUtc()
        $Filter = "(&(objectCategory=person)(objectClass=user)(lastLogonTimeStamp<=$($180DaysAgo)))"
        $objDomain = [ADSI]'' 
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $objSearcher.Filter = $Filter
        $ObjSearcher.PageSize = 500
        $objSearcher.SizeLimit = $Limit


        $objSearcher.FindAll() | ForEach-Object {
            $UserProps = @{}
            $UserProps.Add('SAMAccount', "$($_.properties.samaccountname)")
            $UserProps.Add('Description', ("$($_.properties.description)").replace('`n','').replace(',',';'))
            $UserProps.Add('UserPrincipal', "$($_.properties.userprincipalname)")
            $UserProps.Add('DN', "$($_.properties.distinguishedname)")
            try
            {
                $userProps.Add('Created', [dateTime]"$($groupMember.whencreated)")
            }
            catch
            {
                $userProps.Add('Created','')
            }

            try
            {
                $userProps.Add('LastModified', [dateTime]"$($groupMember.whenchanged)")
            }
            catch
            {
                $userProps.Add('LastModified','')
                    
            }

            try
            {
                $userProps.Add('PasswordLastSet', [dateTime]::FromFileTime("$($group.ConvertLargeIntegerToInt64($groupMember.pwdlastset[0]))"))
            }
            catch
            {
                $userProps.Add('PasswordLastSet','')
            }
            $UserProps.Add('AccountExpires',( &{
            
                Try
                {
                    $exval = "$($_.properties.accountexpires)"
                    If (($exval -eq 0) -or ($exval -gt [DateTime]::MaxValue.Ticks))
                    {
                        $AcctExpires = '<Never>'
                    }
                    Else
                    {
                        $Date = [DateTime]$exval
                        $AcctExpires = $Date.AddYears(1600).ToLocalTime()
                    }
                    $AcctExpires
                }
                catch
                {
                    '<never>'
                }
            
            }))
            $UserProps.Add('LastLogon', [dateTime]::FromFileTime("$($_.properties.lastlogon)"))
            $UserProps.Add('GroupMembership', "$($_.properties.memberof)")
            $UserProps.Add('SID', "$(&{$sidobj = [byte[]]"$($_.Properties.objectsid)".split(' ');$sid = new-object System.Security.Principal.SecurityIdentifier $sidobj, 0; $sid.Value})")
            New-Object -TypeName psobject -Property $UserProps
        }
    }
    End{}
}

<#
.Synopsis
   Enumerates all user accounts that the password never expires in the current domain. 
.DESCRIPTION
   Enumerates all user accounts that the password never expires in the current domain. 
.EXAMPLE
   Get-ADDSUserPasswordNeverExpire -Limit 1000
#>
function Get-ADDSUserPasswordNeverExpire
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$false,
            HelpMessage='Maximum number of Objects to pull from AD, default is 1,000 .')]
        [int]$Limit = 1000
    )

    Begin{}
    Process
    {
       
        $Filter = '(&(sAMAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=65536))'
        $objDomain = [ADSI]'' 
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $objSearcher.Filter = $Filter
        $ObjSearcher.PageSize = 500
        $objSearcher.SizeLimit = $Limit


        $objSearcher.FindAll() | ForEach-Object {
            $UserProps = @{}
            $UserProps.Add('SAMAccount', "$($_.properties.samaccountname)")
            $UserProps.Add('Description', ("`"$($_.properties.description)`"").replace('`n','').replace(',',';'))
            $UserProps.Add('UserPrincipal', "$($_.properties.userprincipalname)")
            $UserProps.Add('DN', "$($_.properties.distinguishedname)")
            try
            {
                $userProps.Add('Created', [dateTime]"$($groupMember.whencreated)")
            }
            catch
            {
                $userProps.Add('Created','')
            }

            try
            {
                $userProps.Add('LastModified', [dateTime]"$($groupMember.whenchanged)")
            }
            catch
            {
                $userProps.Add('LastModified','')
                    
            }

            try
            {
                $userProps.Add('PasswordLastSet', [dateTime]::FromFileTime("$($group.ConvertLargeIntegerToInt64($groupMember.pwdlastset[0]))"))
            }
            catch
            {
                $userProps.Add('PasswordLastSet','')
            }
            $UserProps.Add('AccountExpires',( &{
            
                Try
                {
                    $exval = "$($_.properties.accountexpires)"
                    If (($exval -eq 0) -or ($exval -gt [DateTime]::MaxValue.Ticks))
                    {
                        $AcctExpires = '<Never>'
                    }
                    Else
                    {
                        $Date = [DateTime]$exval
                        $AcctExpires = $Date.AddYears(1600).ToLocalTime()
                    }
                    $AcctExpires
                }
                catch
                {
                    '<never>'
                }
            
            }))
            $UserProps.Add('LastLogon', [dateTime]::FromFileTime("$($_.properties.lastlogon)"))
            $UserProps.Add('GroupMembership', "`"$($_.properties.memberof)`"")
            $UserProps.Add('SID', "$(&{$sidobj = [byte[]]"$($_.Properties.objectsid)".split(' ');$sid = new-object System.Security.Principal.SecurityIdentifier $sidobj, 0; $sid.Value})")
            New-Object -TypeName psobject -Property $UserProps
        }
    }
    End{}
}

<#
.Synopsis
   Enumerate the functional level of the current domain.
.DESCRIPTION
   Enumerate the functional level of the current domain.
.EXAMPLE
   Get-ADDSFunctionalLevel
#>
function Get-ADDSFunctionalLevel
{
    [CmdletBinding()]
    Param()

    Begin
    {
        $FunctionalLevel = @{
            '0' = '2000'
            '1' = '2003 Interim'
            '2' = '2003'
            '3' = '2008'
            '4' = '2008 R2'
            '5' = '2012'
            '6' = '2012 R2'
            '7' = '2016'
        }
    }
    Process
    {
        $rootDSE = [ADSI]'LDAP://RootDSE'
        $objParams = @{
            'DCFunctionalLevel' = ($FunctionalLevel."$($rootDSE.domainControllerFunctionality)")
            'DomainFunctionalLevel' = ($FunctionalLevel."$($rootDSE.domainFunctionality)")
            'ForestFunctionalLevel' = ($FunctionalLevel."$($rootDSE.forestFunctionality)")
        }
        New-Object PSObject -Property $objParams
    }
    End{}
}

<#
.Synopsis
   Enumerate the trust relationships and their details for the current domain.
.DESCRIPTION
   Enumerate the trust relationships and their details for the current domain.
.EXAMPLE
   Get-ADDSDomainTrust
#>
function Get-ADDSDomainTrust
{
    [CmdletBinding()]
    Param()
    Begin{}
    Process
    {
        $Filter = '(objectClass=trustedDomain)'
        $objDomain = [ADSI]'' 
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $objSearcher.Filter = $Filter
        $objSearcher.FindAll() | ForEach-Object {
            $trustProperties = $_.Properties

            $SID = "$(&{$sidobj = [byte[]]"$($_.Properties.securityidentifier)".split(' ');
                        $sid = new-object System.Security.Principal.SecurityIdentifier $sidobj, 0; 
                        $sid.Value})"
            
            switch ($trustProperties.trustdirection[0])
            {
                '0' {$TrustDirection = 'Disabled'}
                '1' {$TrustDirection = 'Inbound Trust'}
                '2' {$TrustDirection = 'Outbound Trust'}
                '3' {$TrustDirection = 'Two-Way Trust'}
            }

            switch ($trustProperties.trusttype[0])
            {
                '0' {$TrustType = 'Down Level'}
                '1' {$TrustType = 'Up Level'}
                '2' {$TrustType = 'MIT'}
                '3' {$TrustType = 'DCE'}
            }

            $trustObj = New-Object -TypeName psobject
            Add-Member -InputObject $trustObj -MemberType NoteProperty -Name 'Name' -Value $trustProperties.name[0]
            Add-Member -InputObject $trustObj -MemberType NoteProperty -Name 'SID' -Value $SID
            Add-Member -InputObject $trustObj -MemberType NoteProperty -Name 'CreatedOn' -Value $trustProperties.whencreated[0]
            Add-Member -InputObject $trustObj -MemberType NoteProperty -Name 'TrustDirection' -Value $TrustDirection
            Add-Member -InputObject $trustObj -MemberType NoteProperty -Name 'Type' -Value $TrustType
            
            $trustObj
        }
    }
    End{}
}

<#
.Synopsis
   Enumerates the password policy for the current domain.
.DESCRIPTION
   Enumerates the password policy for the current domain.
.EXAMPLE
   Get-ADDSDomainPasswordPolicy
#>
function Get-ADDSDomainPasswordPolicy
{
    [CmdletBinding()]
    Param()

    Begin{}
    Process
    {
         $objDomain = [ADSI]'' 
         $MinPwAgeVal = $objDomain.ConvertLargeIntegerToInt64($objDomain.minPwdAge[0])/-864000000000
         $MaxPwAgeVal = $objDomain.ConvertLargeIntegerToInt64(($objDomain.maxPwdAge)[0])/-864000000000
         if ($MaxPwAgeVal -eq 10675199.1167301) {$MaxPwAgeVal = 0}
         $LockoutMin = $objDomain.ConvertLargeIntegerToInt64($objDomain.lockoutDuration[0])/ -600000000
         $LockoutObservationMin= $objDomain.ConvertLargeIntegerToInt64($objDomain.lockOutObservationWindow[0])/ -600000000
         $Complexity = ''
         switch ($objDomain.pwdProperties)
         {
            0 {$Complexity = 'Passwords can be simple and the administrator account cannot be locked out'}

            1 {$Complexity = 'Passwords must be complex and the administrator account cannot be locked out'}

            8 {$Complexity = 'Passwords can be simple, and the administrator account can be locked out'}

            9 {$Complexity = 'Passwords must be complex, and the administrator account can be locked out'}
         }

         $PolObjProps = @{
            MinPasswordLength = $objDomain.minPwdLength.Value
            PasswordHistoryLeght = $objDomain.pwdHistoryLength.Value
            LockoutThreshhold = $objDomain.lockoutThreshold.Value
            LockoutDuration =  $LockoutMin
            LockoutObservationPeriod = $LockoutObservationMin
            Complexity = $Complexity
            MinimunPasswordAge = $MinPwAgeVal
            MaximumPasswordAge = $MaxPwAgeVal
         }
         New-Object -TypeName psobject -Property $PolObjProps
    }
    End{}
}

<# PwC - Script02 - 02.2017 Add
.Synopsis
   Identify the Bitlocker policy currently applied with the groups for the current domain.
.DESCRIPTION
   Enumerates the enforcement policy and groups for the current domain.
.EXAMPLE
   Get-ADDSDomainBitlockerPolicyGroups
#>
function Get-ADDSDomainBitlockerPolicyGroups
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$false,
            HelpMessage='Optional path parameter')]
        [String]$path = (Get-Item -Path ".\" -Verbose).FullName
    )

    Begin{}
    Process
    {
        # Retrieve Policy setting bitlocker
        $count = 0
        $bitLockerPolicies = @()
        $bitlockerSearch = @(Get-GPO -All | where{$_.DisplayName -like '*Bitlocker*'})
        ForEach ($bitlocker in $bitlockerSearch)
        {
            [xml]$BitlockerGPOReport  = Get-GPOReport -GUID $bitlocker.id -ReportType XML

            $BitLockerPolicies += New-Object -TypeName psobject
            Add-Member -InputObject $BitLockerPolicies[$count] -MemberType NoteProperty -Name 'Bitlocker_id' -Value $bitlocker.id
            Add-Member -InputObject $BitLockerPolicies[$count] -MemberType NoteProperty -Name 'Bitlocker_Name' -Value $bitlocker.displayName
            Add-Member -InputObject $BitLockerPolicies[$count] -MemberType NoteProperty -Name 'Bitlocker_GPOStatus' -Value $bitlocker.GpoStatus
            Add-Member -InputObject $BitLockerPolicies[$count] -MemberType NoteProperty -Name 'Bitlocker_filter' -Value $bitlocker.wmiFilter.name

            # Retrieve policy status using "Require additional auth" and "configure TPM statup PIN".
            $regexStatus = [regex]"<q3:Name>Require additional authentication at startup</q3:Name><q3:State>(\w*)</q3:State>"
            $preAuthStatus = $regexStatus.Match($BitlockerGPOReport.InnerXml)
            $regexType = [regex]"<q3:Name>Configure TPM startup PIN:</q3:Name><q3:State>(\w*)</q3:State>"
            $preAuthType = $regexType.Match($BitlockerGPOReport.InnerXml)
   
            # Save status
            If (($preAuthType.Captures[0].groups[1] -eq "False") -or ($preAuthStatus.Captures[0].groups[1] -eq "False")){
                Add-Member -InputObject $BitLockerPolicies[$count] -MemberType NoteProperty -Name 'Pre-Auth_Status' -Value "Disabled"
            } Else {
                Add-Member -InputObject $BitLockerPolicies[$count] -MemberType NoteProperty -Name 'Pre-Auth_Status' -Value "Enabled"
            }

            # Retrieve information about the filter
            if ($bitlocker.wmiFilter.name){
                $wmiFilterAttr = "msWMI-Name", "msWMI-Parm1", "msWMI-Parm2", "msWMI-Author", "msWMI-ID"
		        $search = New-Object System.DirectoryServices.DirectorySearcher([ADSI]'')
		        $wminame = $bitlocker.wmiFilter.name
		        $search.Filter = "(&(objectClass=msWMI-Som)(msWMI-Name=$wminame))"
		        $search.PropertiesToLoad.AddRange($wmiFilterAttr)
		        $result = $search.FindOne()

		        $WMI = New-Object -TypeName PSCustomObject -Property @{
				    Name 	= [string]$result.Properties["mswmi-name"];
				    Parm1	= [string]$result.Properties["mswmi-parm1"];
				    Parm2	= [string]$result.Properties["mswmi-parm2"];
				    Author  = [string]$result.Properties["mswmi-author"];
				    ID	    = [string]$result.Properties["mswmi-ID"]
	            }
            }
 
            # Add information about the WMI filter
		    Add-Member -InputObject $BitLockerPolicies[$count] -MemberType NoteProperty -Name 'Bitlocker_filter_details' -Value $WMI
        }

        $TimeStamp = Get-Date -Format MMddyyyy_HHmmss
        $filenameblkconf = "$($Path)\AD-$($TimeStamp)-BitlockerConfigurationInfo.csv"
        $BitLockerPolicies | select Bitlocker_id,Bitlocker_Name,Bitlocker_GPOStatus,Pre-Auth_Status,Bitlocker_filter,Bitlocker_filter_details | Export-CSV $filenameblkconf -NoTypeInformation -Encoding UTF8

        # Retrieve OU´s applying the Bitlocker policy
        ForEach ($policy in $BitLockerPolicies){
            $idFilter = $policy.Bitlocker_id
            [Array]$OrganizationalUnits += Get-ADOrganizationalUnit -LDAPFilter "(GPLink=*$idFilter*)"  -Properties *
        }

        $filenameblkgroups = "$($Path)\AD-$($TimeStamp)-BitlockerAssetsGroups.csv"
        $OrganizationalUnits | Export-CSV $filenameblkgroups -NoTypeInformation -Encoding UTF8
         
        # Retrieve the filter configuration to apply in filters
        if ($bitLockerPolicies.Length -gt 1){
            $total = $bitLockerPolicies.count
            $count = 1
            $filterString = "("
            ForEach ($policy in $BitLockerPolicies){
                if ($policy.Bitlocker_filter) {
                    $WMIFilter = ((($policy.Bitlocker_filter_details -split "_"))[1] -split " ")[0]
                    $WMIQuery = (($policy.Bitlocker_filter_details -split "'")[1] -split " ")[1,2] -join ' ' -replace "%"
                    $computerFilter = "*$WMIQuery*"
                    $filterString += "$WMIFilter -like ""$computerFilter"")"
                    
                    if ($count -ne $total){
                        $filterString += " -or ("
                    } else{
                        $filterString += ""
                    }
                }
                else {
                    if (($count -eq $total) -and ($filterString -eq ("("))){
                        $filterString = "*"
                    }
                }
                $count += 1
            }
        } else {
            if ($policy.Bitlocker_filter) {
                $WMIFilter = ((($policy.Bitlocker_filter_details -split "_"))[1] -split " ")[0]
                $WMIQuery = (($policy.Bitlocker_filter_details -split "'")[1] -split " ")[1,2] -join ' ' -replace "%"
                $computerFilter = "*$WMIQuery*"
                $filterString = "$WMIFilter -like ""$computerFilter"""
            }
            else {
                $filterString = "*"
            }
        }

        # Retrieve all computers that belongs to the OUs appliying Bitlocker GPO using the filters
        $OrganizationalUnits | ForEach {
            $computers = Get-ADComputer -Filter $filterString -Property * -SearchBase $_.DistinguishedName | Select-Object Name,OperatingSystem,OperatingSystemVersion,OperatingSystemServicePack,DistinguishedName          
        }

        # Test to retrieve Assets wit no bitlocker in asset groups that use bitlocker
        $count = 0
        $Results = ForEach ($Computer in $computers)
        {
            Write-Progress -Id 0 -Activity "Searching Computers for BitLocker" -Status "$Count of $($Computers.Count)" -PercentComplete (($Count / $Computers.Count) * 100)
            $BitLockerPasswordSet = Get-ADObject -Filter "objectClass -eq 'msFVE-RecoveryInformation'" -SearchBase $Computer.DistinguishedName -Properties msFVE-RecoveryPassword,whenCreated | Sort whenCreated -Descending | Select -First 1 | Select -ExpandProperty whenCreated
            Add-Member -InputObject $computers[$count] -MemberType NoteProperty -Name 'BitLockerPasswordSet' -Value $BitLockerPasswordSet -Force
            $Count ++
        }
        Write-Progress -Id 0 -Activity " " -Status " " -Complet

        $filenameblkmachines = "$($Path)\AD-$($TimeStamp)-BitlockerMachines.csv"
        $Computers | Export-CSV $filenameblkmachines -NoTypeInformation -Encoding UTF8
    }
    End{}
}

<# PwC - Script02 - 02.2017 Add
.Synopsis
   Identify and enumerate all the policies applied for the current domain.
.DESCRIPTION
   Identify and enumerate all the policies applied for the current domain.
.EXAMPLE
   Get-ADDSAllDomainPasswordPolicy
#>
function Get-ADDSAllDomainPasswordPolicy
{
    [CmdletBinding()]
    Param()

    Begin{}
    Process
    {
         # Get-ADFineGrainedPasswordPolicy -Filter * -properties
         # In order to obtain all the Fine Grained password policies defined. 
         Get-ADFineGrainedPasswordPolicy -Filter * -Properties * | 
         forEach-Object {
            $CompProps = @{}
            $CompProps.Add('AppliedTo', "$($_.appliesTo)")
            $CompProps.Add('CN', "$($_.cn)")
            $CompProps.Add('LockOut Duration', "$($_.lockoutduration)")
            $CompProps.Add('Max. Password age', "$($_.maxpasswordage)")
            $CompProps.Add('Min. Password age', "$($_.minpasswordage)")
            $CompProps.Add('Min. Password length', "$($_.minpasswordlength)")
            $CompProps.Add('Password complexity status', "$($_."msDS-passwordComplexityEnabled")")
            $CompProps.Add('Password history length', "$($_."msDS-passwordHistoryLength")")
            $CompProps.Add('Reversible encryption status', "$($_."msDS-passwordReversibleEncryptionEnabled")")
            $CompProps.Add('Password settings precedence', "$($_."msDS-passwordSettingsPrecedence")")
            $CompProps.Add('Password history count', "$($_.passwordhistorycount)")
            New-Object PSObject -Property $CompProps 
         }
    }  
    End{}
}

<# PwC - Script02 - 02.2017 Add
.Synopsis
   Check the users for what this DLL must me enabled
.DESCRIPTION
   Check the users for what this DLL must me enabled
.EXAMPLE
   Get-ADDSGroupPasswordDLLCheck -ADGRoupName "PassfiltGroup"
#>
function Get-ADDSGroupPasswordDLLCheck
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$false,
            HelpMessage='Group Name used by the DLL to set the configuration')]
        [String]$ADGroupName = "Passfilt"
    )

    Begin{}
    Process
    {
         $Filter = "(&(objectClass=group)(name=*$ADGroupName*))"
         $objDomain = [ADSI]'' 
         $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
         $objSearcher.Filter = $Filter
         $PassFiltGroup = $objSearcher.FindAll()
       
         $PassFiltGroup | forEach-Object {
            $DN = $_.properties.distinguishedname
            $_.Properties.member | forEach-Object {
                $CompProps = @{}
                $CompProps.Add('user', "$($_)")
                $CompProps.Add('DistinguisedName', "$($DN)")
                New-Object PSObject -Property $CompProps
            }
         }      
    }
    End{}
}

<# PwC - Script02 - 02.2017 Add
.Synopsis
   Retrieve the audit log policy implemented for the group 
.DESCRIPTION
   Retrieve the audit log policy implemented for the group
.EXAMPLE
   Get-ADDSDomainAuditPolicy -GPO "8525d36d-6fc5-40d3-91b5-bdf5c6b38fe3"
#>
function Get-ADDSGroupAuditPolicy
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$false,
            HelpMessage='GPO to retrieve the Audit policy configured')]
        [String]$GPO = "Default"
    )

    Begin{}
    Process
    {     
         $GPOs = Get-GPO -All | where{$_.DisplayName -like "*$GPO*"}
         
         $GPOs | foreach-Object{

             [xml]$GPOReport  = Get-GPOReport -GUID $_.id -ReportType XML 

             # Retrieve policy audit records from XML
             $regexStatus = [regex]"<q1:Audit><q1:Name>AuditAccountLogon</q1:Name><q1:SuccessAttempts>(\w*)</q1:SuccessAttempts><q1:FailureAttempts>(\w*)</q1:FailureAttempts></q1:Audit>"
             $auditAccountLogon = $regexStatus.Match($GPOReport.InnerXml)
             $regexStatus = [regex]"<q1:Audit><q1:Name>AuditAccountManage</q1:Name><q1:SuccessAttempts>(\w*)</q1:SuccessAttempts><q1:FailureAttempts>(\w*)</q1:FailureAttempts></q1:Audit>"
             $AuditAccountManage = $regexStatus.Match($GPOReport.InnerXml)
             $regexStatus = [regex]"<q1:Audit><q1:Name>AuditDSAccess</q1:Name><q1:SuccessAttempts>(\w*)</q1:SuccessAttempts><q1:FailureAttempts>(\w*)</q1:FailureAttempts></q1:Audit>"
             $AuditDSAccess = $regexStatus.Match($GPOReport.InnerXml)
             $regexStatus = [regex]"<q1:Audit><q1:Name>AuditLogonEvents</q1:Name><q1:SuccessAttempts>(\w*)</q1:SuccessAttempts><q1:FailureAttempts>(\w*)</q1:FailureAttempts></q1:Audit>"
             $AuditLogonEvents = $regexStatus.Match($GPOReport.InnerXml)
             $regexStatus = [regex]"<q1:Audit><q1:Name>AuditObjectAccess</q1:Name><q1:SuccessAttempts>(\w*)</q1:SuccessAttempts><q1:FailureAttempts>(\w*)</q1:FailureAttempts></q1:Audit>"
             $AuditObjectAccess = $regexStatus.Match($GPOReport.InnerXml)
             $regexStatus = [regex]"<q1:Audit><q1:Name>AuditPolicyChange</q1:Name><q1:SuccessAttempts>(\w*)</q1:SuccessAttempts><q1:FailureAttempts>(\w*)</q1:FailureAttempts></q1:Audit>"
             $AuditPolicyChange = $regexStatus.Match($GPOReport.InnerXml)
             $regexStatus = [regex]"<q1:Audit><q1:Name>AuditPrivilegeUse</q1:Name><q1:SuccessAttempts>(\w*)</q1:SuccessAttempts><q1:FailureAttempts>(\w*)</q1:FailureAttempts></q1:Audit>"
             $AuditPrivilegeUse = $regexStatus.Match($GPOReport.InnerXml)
             $regexStatus = [regex]"<q1:Audit><q1:Name>AuditProcessTracking</q1:Name><q1:SuccessAttempts>(\w*)</q1:SuccessAttempts><q1:FailureAttempts>(\w*)</q1:FailureAttempts></q1:Audit>"
             $AuditProcessTracking = $regexStatus.Match($GPOReport.InnerXml)
             $regexStatus = [regex]"<q1:Audit><q1:Name>AuditSystemEvents</q1:Name><q1:SuccessAttempts>(\w*)</q1:SuccessAttempts><q1:FailureAttempts>(\w*)</q1:FailureAttempts></q1:Audit>"
             $AuditSystemEvents = $regexStatus.Match($GPOReport.InnerXml)

             if ($auditAccountLogon.groups[1].value -ne ""){
                 New-Object PSObject -Property @{
				    Name 	              = [string]$_.DisplayName;
				    auditAccountLogon	  = @($auditAccountLogon.groups[1].value,$auditAccountLogon.groups[2].value) -join ":";
				    AuditAccountManage	  = @($AuditAccountManage.groups[1].value,$AuditAccountManage.groups[2].value) -join ":";
				    AuditDSAccess         = @($AuditDSAccess.groups[1].value,$AuditDSAccess.groups[2].value) -join ":";
				    AuditLogonEvents	  = @($AuditLogonEvents.groups[1].value,$AuditLogonEvents.groups[2].value) -join ":";
                    AuditObjectAccess	  = @($AuditObjectAccess.groups[1].value,$AuditObjectAccess.groups[2].value) -join ":";
                    AuditPolicyChange	  = @($AuditPolicyChange.groups[1].value,$AuditPolicyChange.groups[2].value) -join ":";
                    AuditPrivilegeUse	  = @($AuditPrivilegeUse.groups[1].value,$AuditPrivilegeUse.groups[2].value) -join ":";
                    AuditProcessTracking  = @($AuditProcessTracking.groups[1].value,$AuditProcessTracking.groups[2].value) -join ":";
                    AuditSystemEvents	  = @($AuditSystemEvents.groups[1].value,$AuditSystemEvents.groups[2].value) -join ":";
	             }
             }
        }
    }         
    End{}
}

<# PwC - Script02 - 02.2017 Add
.Synopsis
   Retrieve the list of computers in the domain and several information 
.DESCRIPTION
   Retrieve the list of computers in the domain and several information
.EXAMPLE
   Get-ADDSDomainComputersActivity -Limit "3000"
#>
function Get-ADDSDomainComputersActivity
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$false,
            HelpMessage='GPO to retrieve computers in the domain')]
        [String]$Limit = 1000
    )

    Begin{}
    Process
    {
        Get-ADComputer -Filter * -Property * -ResultSetSize $limit | Select-Object Name,OperatingSystem,OperatingSystemServicePack,OperatingSystemVersion,LastLogonDate,PasswordLastSet,Modified | sort -property LastLogonDate | forEach-Object {
            $CompProps = @{}

            $CompProps.Add('Name', "$($_.Name)")
            $CompProps.Add('OperatingSystem', "$($_.OperatingSystem)")
            $CompProps.Add('OperatingSystem ServicePack', "$($_.OperatingSystemServicePack)")
            $CompProps.Add('OperatingSystem Version', "$($_.OperatingSystemVersion)")
            $CompProps.Add('LastLogonDate', "$($_.LastLogonDate)")
            $CompProps.Add('PasswordLastSet', "$($_.PasswordLastSet)")
            $CompProps.Add('Modified', "$($_.Modified)")
            New-Object PSObject -Property $CompProps 
         }
    }
    End{}
}

<#
.Synopsis
   Enumerate all sites in the current forest. 
.DESCRIPTION
   Enumerate all sites in the current forest including their details.
.EXAMPLE
   Get-ADDSForestSites
#>
function Get-ADDSForestSites
{
    [CmdletBinding()]
    Param()
    Begin{}
    Process
    {
        $Sites = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Sites
        foreach($Site in $Sites)
        {
            $Domains = ($Site.Domains | select -ExpandProperty name) -join ';'
            $Subnets = ($Site.Subnets | select -ExpandProperty name) -join ';'
            $Servers = ($Site.Servers | select -ExpandProperty name) -join ';'
            $siteObj = New-Object -TypeName psobject -Property @{}
            Add-Member -InputObject $siteObj -MemberType NoteProperty -Name 'Name' -Value $Site.name
            Add-Member -InputObject $siteObj -MemberType NoteProperty -Name 'Localtion' -Value $Site.Location
            Add-Member -InputObject $siteObj -MemberType NoteProperty -Name 'Domains' -Value $domains
            Add-Member -InputObject $siteObj -MemberType NoteProperty -Name 'Subnets' -Value $subnets
            Add-Member -InputObject $siteObj -MemberType NoteProperty -Name 'Servers' -Value $Servers
            $siteObj
        }
    }
    End{}
}

<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
function Get-ADDSForestDomainInfo
{
    [CmdletBinding()]
    Param()

    Begin{}
    Process
    {
        $Domains = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Domains
        foreach($domain in $Domains)
        {
            $dcs = $domain.DomainControllers | select -ExpandProperty name
            $domainObj = New-Object -TypeName psobject -Property @{}
            Add-Member -InputObject $domainObj -MemberType NoteProperty -Name 'Name' -Value $domain.name
            Add-Member -InputObject $domainObj -MemberType NoteProperty -Name 'DomainMode' -Value $domain.DomainMode
            Add-Member -InputObject $domainObj -MemberType NoteProperty -Name 'PDCRole' -Value $domain.PdcRoleOwner
            Add-Member -InputObject $domainObj -MemberType NoteProperty -Name 'RIDRole' -Value $domain.RidRoleOwner
            Add-Member -InputObject $domainObj -MemberType NoteProperty -Name 'InfrastructureRole' -Value $domain.InfrastructureRoleOwner
            Add-Member -InputObject $domainObj -MemberType NoteProperty -Name 'DomainControllers' -Value ($dcs -join ';')
            $domainObj
        }
    }
    End{}
}

<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
function Get-ADDSDomainController
{
    [CmdletBinding()]
    [OutputType([int])]
    Param()

    Begin{}
    Process
    {
        $Filter = '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))'
        $objDomain = [ADSI]'' 
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $objSearcher.Filter = $Filter
        $objSearcher.FindAll() | ForEach-Object {
            $CompProps = @{}
            $CompProps.Add('HostName', "$($_.properties.dnshostname)")
            $CompProps.Add('OperatingSystem', "$($_.properties.operatingsystem)")
            $CompProps.Add('ServicePack', "$($_.properties.operatingsystemservicepack)")
            $CompProps.Add('Version', "$($_.properties.operatingsystemversion)")
            $CompProps.Add('IPAddress',([System.Net.Dns]::GetHostAddresses("$($_.properties.dnshostname)") | ForEach-Object {$_.ToString()}) -join ';')

            New-Object PSObject -Property $CompProps
        }
    }
    End{}
}

<#
.Synopsis
   Enumerates all groups in the current domain.
.DESCRIPTION
   Enumerates all groups in the current domain.
.EXAMPLE
   Get-ADDSGroups
#>
function Get-ADDSGroups
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
            HelpMessage='Maximum number of Objects to pull from AD, default is 1,000 .')]
        [int]$Limit = 1000,

        [Parameter(Mandatory=$false,
            HelpMessage='Name of group to search for. Accepts * wildacard.')]
        [string]$Name
    )

    Begin{}
    Process
    {
        if ($name.Length -gt 0)
        {
            $Filter = "(&(groupType:1.2.840.113556.1.4.803:=2147483648)(cn=$($Name)))"
        }
        else
        {
            $Filter = '(groupType:1.2.840.113556.1.4.803:=2147483648)'
        }

        $objDomain = [ADSI]'' 
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $objSearcher.Filter = $Filter
        $objSearcher.FindAll() | ForEach-Object {
            $GroupProps = @{}
            $GroupProps.Add('Name', "$($_.properties.name)")
            $GroupProps.Add('DistinguishedName', "$($_.properties.distinguishedname)")
            $GroupProps.Add('Description', "`"$(($_.properties.description))`"".replace('`n','').replace(',',';'))
            $GroupProps.Add('Created', "$($_.properties.whencreated)")
            $GroupProps.Add('Modified',$_.properties.whenchanged)
            switch($_.properties.grouptype){            
            2  {            
                    $GroupProps.Add('GroupCategory', 'Distribution')          
                    $GroupProps.Add('GroupScope', 'Global')  
                }            
            4  {            
                    $GroupProps.Add('GroupCategory', 'Distribution')           
                    $GroupProps.Add('GroupScope', 'DomainLocal')            
                }             
            8  {            
                    $GroupProps.Add('GroupScope','Distribution' )           
                    $GroupProps.Add('GroupScope', 'Universal')            
                }             
            -2147483646  {            
                    $GroupProps.Add('GroupCategory', 'Security' )           
                    $GroupProps.Add('GroupScope', 'Global')          
                }            
            -2147483644  {            
                    $GroupProps.Add('GroupCategory','Security')           
                    $GroupProps.Add('GroupScope', 'DomainLocal')         
                }            
            -2147483643   {            
                    $GroupProps.Add('GroupCategory','Security')           
                    $GroupProps.Add('GroupScope', 'BuiltinLocal')          
                }            
            -2147483640  {            
                    $GroupProps.Add('GroupCategory','Security')          
                    $GroupProps.Add('GroupScope', 'Universal')          
                }             
            default {Throw 'Error - Unrecognised group type'}            
             
            } 
            New-Object PSObject -Property $GroupProps
        }
    }
    End{}
}

<#
.Synopsis
   Tests if all the domain controllers in the current domain are virtualized.
.DESCRIPTION
   Tests if all the domain controllers in the current domain are virtualized.
   Tests for VMware and Hyper-V using WMI RCP. 
.EXAMPLE
   Test-ADDSDCVirtual
#>
function Test-ADDSDCVirtual
{
    [CmdletBinding()]
    Param
    ()

    Begin{}
    Process
    {
        $Filter = '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))'
        $objDomain = [ADSI]'' 
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $objSearcher.Filter = $Filter
        $objSearcher.FindAll() | ForEach-Object {
            $hostobj = $_
            $CompProps = @{}
            Write-verbose -Message "Trying to connect to $($_.properties.name)"
            $TcpSocket = new-object System.Net.Sockets.TcpClient
            try
            {
                $TcpSocket.Connect($_.properties.dnshostname[0], 135)
                $portopen = $true
                # Close Connection
                $tcpsocket.Close()
            }catch
            {
                $portopen = $false
            }
            if ($portopen)
            {
                try {
               
                    $bios = Get-WmiObject -Class Win32_BIOS -ComputerName $_.properties.dnshostname[0] -ErrorAction Stop 
                    $compsys = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $_.properties.dnshostname[0] 
                    $CompProps.Add('DomainController', $_.properties.dnshostname[0])
                    if($bios.Version -match 'VRTUAL') 
                    {
                        $CompProps.Add('Type', 'Virtual')
                        $CompProps.Add('Hypervisor', 'Hyper-V')
                    }
                    elseif($bios.Version -like '*Xen*') 
                    {
                        $CompProps.Add('Type', 'Virtual')
                        $CompProps.Add('Hypervisor', 'Xen')
                    }
                    elseif($bios.SerialNumber -like '*VMware*') 
                    {
                        $CompProps.Add('Type', 'Virtual')
                        $CompProps.Add('Hypervisor', 'VMware')
                    }
                    elseif($compsys.manufacturer -like '*Microsoft*') 
                    {
                        $CompProps.Add('Type', 'Virtual')
                        $CompProps.Add('Hypervisor', 'Hyper-V')
                    }
                    elseif($compsys.manufacturer -like '*VMWare*') 
                    {
                        $CompProps.Add('Type', 'Virtual')
                        $CompProps.Add('Hypervisor', 'VMware')
                    }
                    elseif($compsys.model -like '*Virtual*') 
                    {
                        $CompProps.Add('Type', 'Virtual')
                        $CompProps.Add('Hypervisor', 'Hyper-V')
                    }
                    else 
                    {
                        $CompProps.Add('Type', 'Physical')
                        $CompProps.Add('Hypervisor', '<none>')
                    }
                    New-Object -TypeName psobject -Property $CompProps
                }
                Catch
                {
                    $Message = @"
Could not connect to $($hostobj.properties.name)
Check that the current user has permission to logon locally and that WMI is configured to receive connections.
https://msdn.microsoft.com/en-us/library/windows/desktop/aa393266(v=vs.85).aspx
"@
                    Write-Warning -Message $Message
                }
            }
            else
            {
                Write-Warning -Message "Port TCP 135 is close on $($_.properties.name), WMI on this port is used for this check"
            }
        }
    }
    End{}
}


<#
.Synopsis
   Find user accounts with blank SN and Email.
.DESCRIPTION
   Find user accounts with blank SN and Email.
.EXAMPLE
   Find-ADDSUserMissingAttribute
#>
function Find-ADDSUserMissingAttribute
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$false,
            HelpMessage='Maximum number of Objects to retrieve from AD, default is 1,000 .')]
        [int]$Limit = 1000
    )

    Begin{}
    Process
    {
        $Filter = '(&(sAMAccountType=805306368)(|(!(sn=*))(!(mail=*))))'
        $objDomain = [ADSI]'' 
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $objSearcher.Filter = $Filter
        $ObjSearcher.PageSize = 500
        $objSearcher.SizeLimit = $Limit

        $objSearcher.FindAll() | ForEach-Object {
            $UserProps = @{}
            $UserProps.Add('SAMAccount', "$($_.properties.samaccountname)")
            $UserProps.Add('SN', "$($_.properties.sn)")
            $UserProps.Add('Email', "$($_.properties.mail)")
            $UserProps.Add('Description', "`"$(($_.properties.description))`"".replace('`n','').replace(',',';'))
            $UserProps.Add('UserPrincipal', "$($_.properties.userprincipalname)")
            $UserProps.Add('DN', "$($_.properties.distinguishedname)")
            $UserProps.Add('Created', [dateTime]"$($_.properties.whencreated)")
            $UserProps.Add('LastModified', [dateTime]"$($_.properties.whenchanged)")
            $UserProps.Add('PasswordLastSet', [dateTime]::FromFileTime("$($_.properties.pwdlastset)"))
            $UserProps.Add('AccountExpires',( &{
            
                Try
                {
                    $exval = "$($_.properties.accountexpires)"
                    If (($exval -eq 0) -or ($exval -gt [DateTime]::MaxValue.Ticks))
                    {
                        $AcctExpires = '<Never>'
                    }
                    Else
                    {
                        $Date = [DateTime]$exval
                        $AcctExpires = $Date.AddYears(1600).ToLocalTime()
                    }
                    $AcctExpires
                }
                catch
                {
                    '<never>'
                }
            
            }))
            $UserProps.Add('LastLogon', [dateTime]::FromFileTime("$($_.properties.lastlogon)"))
            $UserProps.Add('GroupMembership', "`"$($_.properties.memberof)`"")
            $UserProps.Add('SID', "$(&{$sidobj = [byte[]]"$($_.Properties.objectsid)".split(' ');$sid = new-object System.Security.Principal.SecurityIdentifier $sidobj, 0; $sid.Value})")
            New-Object -TypeName psobject -Property $UserProps
        }
    }
    End{}
}


<#
.Synopsis
   Enumerate the members of a group in the current domain.
.DESCRIPTION
   Enumerate the members of a group in the current domain given a distinguished name.
.EXAMPLE
   Get-ADDSGroupMember -DistinguishedName "CN=Domain Admins,CN=Users,DC=corp,DC=tacticalperspective,DC=com"
#>
function Get-ADDSGroupMember
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage='DN of group to get members from.',
                   Position=0)]
        [string]$DistinguishedName
    )

    Begin{}
    Process
    {
        $group = [ADSI]"LDAP://$($DistinguishedName)"
        Write-Verbose -Message "Enumerating users in group $($group.Name)"
        $group.member | ForEach-Object {
            $groupMember = [ADSI]"LDAP://$($_)"
            if ($groupMember.objectClass -contains 'User' -and $groupMember.samaccountname.length -gt 0)
            {
                $userProps = @{}
                $userProps.Add('ObjectClass', 'Person')
                $userProps.Add('SAMAccount', "$($groupMember.samaccountname)")
                $userProps.Add('GroupName', "$($group.Name)")
                $userProps.Add('Description', ("`"$($groupMember.description)`"").replace('`n','').replace(',',';'))
                $userProps.Add('UserPrincipal', "$($groupMember.userprincipalname)")
                $userProps.Add('DN', "$($groupMember.distinguishedname)")
                try
                {
                    $userProps.Add('Created', [dateTime]"$($groupMember.whencreated)")
                }
                catch
                {
                    $userProps.Add('Created','')
                }

                try
                {
                    $userProps.Add('LastModified', [dateTime]"$($groupMember.whenchanged)")
                }
                catch
                {
                    $userProps.Add('LastModified','')
                    
                }

                try
                {
                    $userProps.Add('PasswordLastSet', [dateTime]::FromFileTime("$($group.ConvertLargeIntegerToInt64($groupMember.pwdlastset[0]))"))
                }
                catch
                {
                    $userProps.Add('PasswordLastSet','')
                }
                $UserProps.Add('AccountExpires',( &{
            
                    Try
                    {
                        $exval = "$($_.properties.accountexpires)"
                        If (($exval -eq 0) -or ($exval -gt [DateTime]::MaxValue.Ticks))
                        {
                            $AcctExpires = '<Never>'
                        }
                        Else
                        {
                            $Date = [DateTime]$exval
                            $AcctExpires = $Date.AddYears(1600).ToLocalTime()
                        }
                        $AcctExpires
                    }
                    catch
                    {
                        '<never>'
                    }
            
                }))
                $userProps.Add('LastLogon', (&{try{[dateTime]::FromFileTime("$($groupMember.ConvertLargeIntegerToInt64($groupMember.lastlogon[0]))")}catch{'<never>'}}))
                $userProps.Add('GroupMembership', "`"$($_.properties.memberof)`"")
                $userProps.Add('SID', "$(&{$sidobj = [byte[]]"$($groupMember.objectsid)".split(' ');$sid = new-object System.Security.Principal.SecurityIdentifier $sidobj, 0; $sid.Value})")
                New-Object -TypeName psobject -Property $userProps
            }
        }
    }
    End{}
}

<#
.Synopsis
   Enumerates accounts that can not change their own password.
.DESCRIPTION
   Enumerates accounts that can not change their own password by checking their ACL.
.EXAMPLE
   Get-ADDSAccountCantChangePassword -Limit 1000
#>
function Get-ADDSAccountCantChangePassword
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$false,
            HelpMessage='Maximum number of Objects to retrieve from AD, default is 1,000 .')]
        [int]$Limit = 1000
    )

    Begin
    {
    }
    Process
    {
        $Filter = '(sAMAccountType=805306368)'
        $objDomain = [ADSI]'' 
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $objSearcher.Filter = $Filter
        $ObjSearcher.PageSize = 500
        $objSearcher.SizeLimit = $Limit

        $objSearcher.FindAll() | ForEach-Object {
        $Userobject = [adsi]$_.path
        $deny = $Userobject.psbase.get_ObjectSecurity().getAccessRules($true, $true, [system.security.principal.NtAccount])  | ` 
           Where-Object { 
            ($_.IdentityReference -eq 
                'Everyone' -or 
                $_.IdentityReference -eq 
                'NT AUTHORITY\SELF') -and 
                $_.AccessControlType -eq '
                Deny' -and 
                $_.ActiveDirectoryRights -eq 
                'ExtendedRight'
           }
           if ($deny)
           {
                $UserProps = @{}
                $UserProps.Add('SAMAccount', "$($Userobject.properties.samaccountname)")
                $UserProps.Add('Description', ("`"$($Userobject.properties.description)`"".replace('`n','').replace(',',';')))
                $UserProps.Add('UserPrincipal', "$($Userobject.properties.userprincipalname)")
                $UserProps.Add('DN', "$($Userobject.properties.distinguishedname)")
                $UserProps.Add('Created', [dateTime]"$($Userobject.properties.whencreated)")
                $UserProps.Add('LastModified', [dateTime]"$($Userobject.properties.whenchanged)")
                $UserProps.Add('PasswordLastSet', [dateTime]::FromFileTime("$($Userobject.ConvertLargeIntegerToInt64($Userobject.properties.pwdlastset[0]))"))
                $UserProps.Add('AccountExpires',( &{
                    Try
                    {
                        $exval = "$($_.properties.accountexpires)"
                        If (($exval -eq 0) -or ($exval -gt [DateTime]::MaxValue.Ticks))
                        {
                            $AcctExpires = '<Never>'
                        }
                        Else
                        {
                            $Date = [DateTime]$exval
                            $AcctExpires = $Date.AddYears(1600).ToLocalTime()
                        }
                        $AcctExpires
                    }
                    catch
                    {
                        '<never>'
                    }
            
                }))

                if ($Userobject.properties.lastlogon -ne $null)
                {
                    $UserProps.Add('LastLogon', ([dateTime]::FromFileTime("$($Userobject.ConvertLargeIntegerToInt64($Userobject.properties.lastlogon[0]))")))
                }
                else
                {
                    $UserProps.Add('LastLogon',$null)
                }
                $UserProps.Add('GroupMembership', "`"$($Userobject.properties.memberof)`"")
                $UserProps.Add('SID', "$(&{$sidobj = [byte[]]"$($Userobject.Properties.objectsid)".split(' ');$sid = new-object System.Security.Principal.SecurityIdentifier $sidobj, 0; $sid.Value})")
                New-Object -TypeName psobject -Property $UserProps
           }
        }
    }
    End
    {
    }
}

Write-Host 'Version 1.4'
if (Test-Path -Path $Path -PathType Container)
{
    $TimeStamp = Get-Date -Format MMddyyyy_HHmmss
    $filenamedfl = "$($Path)\$($prefix)-$($TimeStamp)-DomainFunctionalLevel.csv"
    $filenamedtrusts = "$($Path)\$($prefix)-$($TimeStamp)-DomainTrusts.csv"
    $filenamedpwpol = "$($Path)\$($prefix)-$($TimeStamp)-DomainPasswordPolicy.csv"
    $filenamedsites = "$($Path)\$($prefix)-$($TimeStamp)-DomainSites.csv"
    $filenamedinfo = "$($Path)\$($prefix)-$($TimeStamp)-DomainInfo.csv"
    $filenameddcs = "$($Path)\$($prefix)-$($TimeStamp)-DomainControllers.csv"
    $filenameddcsvm = "$($Path)\$($prefix)-$($TimeStamp)-DomainControllersVMCheck.csv"
    $filenamedusers = "$($Path)\$($prefix)-$($TimeStamp)-DomainUsers.csv"
    $filenamedgroups = "$($Path)\$($prefix)-$($TimeStamp)-DomainGroups.csv"
    $filenamednlo = "$($Path)\$($prefix)-$($TimeStamp)-DomainUsersNeverLoggedOn.csv"
    $filenamedda = "$($Path)\$($prefix)-$($TimeStamp)-DomainDisabledAccount.csv"
    $filenamedaa = "$($Path)\$($prefix)-$($TimeStamp)-DomainAbbandonedAccount.csv"
    $filenamedpne = "$($Path)\$($prefix)-$($TimeStamp)-DomainNeverExpiredAccount.csv"
    $filenamema = "$($Path)\$($prefix)-$($TimeStamp)-DomainAccountMissingAttribute.csv"
    $filenamencp = "$($Path)\$($prefix)-$($TimeStamp)-DomainAccountCantChangePassword.csv"
    $filenameadmusr = "$($Path)\$($prefix)-$($TimeStamp)-Adminusers.csv"

    # PwC - Script02 - 02.2017
    $filenameblkconf = "$($Path)\$($prefix)-$($TimeStamp)-BitlockerConfigurationInfo.csv"
    $filenameblkgroups = "$($Path)\$($prefix)-$($TimeStamp)-BitlockerAssetsGroups.csv"
    $filenameblkmachines = "$($Path)\$($prefix)-$($TimeStamp)-BitlockerMachines.csv"
    $filenameDLLCheck = "$($Path)\$($prefix)-$($TimeStamp)-DLLCheckStatus.csv"
    $filenameGPOAudit = "$($Path)\$($prefix)-$($TimeStamp)-GPOAuditConfiguration.csv"
    $filenameMchActivity = "$($Path)\$($prefix)-$($TimeStamp)-MachinesActivity.csv"
    $filenameFGPolicy = "$($Path)\$($prefix)-$($TimeStamp)-DomainFGPolicies.csv"

    Write-Host -ForegroundColor Green 'Enumerating current domain Functional Level.'
    Write-Host -ForegroundColor Green "Saving information to $($filenamedfl)`n"
    Get-ADDSFunctionalLevel | Export-Csv -Path $filenamedfl -NoTypeInformation
    
    Write-Host -ForegroundColor Green 'Enumerating current domain trust relationships.'
    Write-Host -ForegroundColor Green "Saving information to $($filenamedtrusts)`n"
    Get-ADDSDomainTrust | Export-Csv -Path $filenamedtrusts -NoTypeInformation
    
    Write-Host -ForegroundColor Green 'Enumerating current domain password policy.'
    Write-Host -ForegroundColor Green "Saving information to $($filenamedpwpol)`n"
    Get-ADDSDomainPasswordPolicy | Export-Csv -Path $filenamedpwpol -NoTypeInformation
    
    Write-Host -ForegroundColor Green 'Enumerating all sites on the forest.'
    Write-Host -ForegroundColor Green "Saving information to $($filenamedsites)`n"
    Get-ADDSForestSites | Export-Csv $filenamedsites -NoTypeInformation
    
    Write-Host -ForegroundColor Green 'Enumerating domain information'
    Write-Host -ForegroundColor Green "Saving information to $($filenamedinfo)`n"
    Get-ADDSForestDomainInfo | Export-Csv -Path $filenamedinfo -NoTypeInformation
    
    Write-Host -ForegroundColor Green 'Enumerating all domain controllers'
    Write-Host -ForegroundColor Green "Saving information to $($filenameddcs)`n"
    Get-ADDSDomainController | Export-Csv -path $filenameddcs -NoTypeInformation 
    
    Write-Host -ForegroundColor Green 'Testing if domain controllers are physical or VMs'
    Write-Host -ForegroundColor Green "Saving information to $($filenameddcsvm)`n"
    Test-ADDSDCVirtual | Export-Csv -Path $filenameddcsvm -NoTypeInformation
    
    Write-Host -ForegroundColor Green 'Enumerating all groups in the current domain.'
    Write-Host -ForegroundColor Green "Saving information to $($filenamedgroups)`n"
    Get-ADDSGroups | Export-Csv -Path $filenamedgroups -NoTypeInformation
    
    Write-Host -ForegroundColor Green 'Enumerating all users'
    Write-Host -ForegroundColor Green "Saving information to $($filenamedusers)`n"
    Get-ADDSUser -Limit $Limit | export-csv -Path $filenamedusers -NoTypeInformation
    
    Write-Host -ForegroundColor Green 'Enumerating users that never logged on'
    Write-Host -ForegroundColor Green "Saving information to $($filenamednlo)`n"
    Get-ADDSUserNeverLoggedOn -Limit $Limit  | Export-Csv -Path $filenamednlo -NoTypeInformation
    
    Write-Host -ForegroundColor Green 'Enumerating disabled accounts'
    Write-Host -ForegroundColor Green "Saving information to $($filenamedda)`n"
    Get-ADDSUserDisabled -Limit $Limit | export-csv -Path $filenamedda -NoTypeInformation
    
    Write-Host -ForegroundColor Green 'Enumerating accounts that have not loggedon in 180 days'
    Write-Host -ForegroundColor Green "Saving information to $($filenamedaa)`n"
    Get-ADDSUserAbandoned -Limit $Limit | Export-Csv -Path $filenamedaa -NoTypeInformation
    
    Write-Host -ForegroundColor Green 'Enumerating accounts with password set to never expire.'
    Write-Host -ForegroundColor Green "Saving information to $($filenamedpne)`n"
    Get-ADDSUserPasswordNeverExpire -Limit $Limit | Export-Csv -Path $filenamedpne -NoTypeInformation
    
    Write-Host -ForegroundColor Green 'Enumerating accounts with either a missing email or surname'
    Write-Host -ForegroundColor Green "Saving information to $($filenamema)`n"
    Find-ADDSUserMissingAttribute -Limit $Limit | Export-Csv -Path $filenamema -NoTypeInformation
    
    Write-Host -ForegroundColor Green 'Enumerating accounts that can not change their password.'
    Write-Host -ForegroundColor Green "Saving information to $($filenamencp)`n"
    Get-ADDSAccountCantChangePassword -Limit $Limit | Export-Csv -Path $filenamencp -NoTypeInformation
    
    Write-Host -ForegroundColor Green 'Enumerating users in administrative groups.'
    Write-Host -ForegroundColor Green "Saving information to $($filenameadmusr)`n"
    Get-ADDSGroups -Limit $Limit -Name '*adm*' | Get-ADDSGroupMember | Export-Csv -Path $filenameadmusr -NoTypeInformation

    # PwC - Script02 - 02.2017
    Write-Host -ForegroundColor Green 'Enumerating Bitlocker configuration'
    Write-Host -ForegroundColor Green "Saving information to $($filenameblkconf)`n"

    Write-Host -ForegroundColor Green 'Enumerating Assets Groups using Bitlocker'
    Write-Host -ForegroundColor Green "Saving information to $($filenameblkgroups)`n"

    Write-Host -ForegroundColor Green 'Enumerating Machines using Bitlocker'
    Write-Host -ForegroundColor Green "Saving information to $($filenameblkmachines)`n"
    Get-ADDSDomainBitlockerPolicyGroups -Path $Path

    Write-Host -ForegroundColor Green 'Enumerating All domain Fine-Grain password policies'
    Write-Host -ForegroundColor Green "Saving information to $($filenameFGPolicy)`n"
    Get-ADDSAllDomainPasswordPolicy | Export-Csv -Path $filenameFGPolicy -NoTypeInformation

    write-Host -ForegroundColor Green 'Enumerating Machines belonging to PassFiltGroup'
    Write-Host -ForegroundColor Green "Saving information to $($filenameDLLCheck)`n"
    Get-ADDSGroupPasswordDLLCheck -ADGroupName "Passfilt" | Export-Csv -Path $filenameDLLCheck -NoTypeInformation

    write-Host -ForegroundColor Green 'Enumerating GPO Audit Configuration'
    Write-Host -ForegroundColor Green "Saving information to $($filenameGPOAudit)`n"
    Get-ADDSGroupAuditPolicy -GPO "Default" | Export-Csv -Path $filenameGPOAudit -NoTypeInformation

    write-Host -ForegroundColor Green 'Enumerating Machines Activity'
    Write-Host -ForegroundColor Green "Saving information to $($filenameMchActivity)`n"
    Get-ADDSDomainComputersActivity -Limit 10000 | Export-Csv -Path $filenameMchActivity -NoTypeInformation

    if ($StringSearch.Length -gt 0)
    {
        $filenamengrpsrch = "$($Path)\$($prefix)-$($TimeStamp)-UserMatchconventionn.csv" 
        $filenameusrsrch = "$($Path)\$($prefix)-$($TimeStamp)-GroupMatchconvention.csv"
    
        Write-Host -ForegroundColor Green "Enumerating users and groups that match the search string of $($StringSearch)."
        Write-Host -ForegroundColor Green "Saving users found  to $($filenamengrpsrch)"
        Get-ADDSUser -Limit $Limit -SamAccount $StringSearch | Export-Csv -Path $filenamengrpsrch -NoTypeInformation
        Write-Host -ForegroundColor Green "Saving groups found  to $($filenamengrpsrch)`n"
        Get-ADDSGroups -Limit $Limit -Name $StringSearch | Export-Csv -Path $filenameusrsrch -NoTypeInformation
    
    }
}
else
{
    Write-Error -Message 'Path provided is not valid.' -ErrorAction Stop
}
