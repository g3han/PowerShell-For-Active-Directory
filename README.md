# PowerShell Scripts for Security Assessment & Audit

### For users_in_administrator_groups.ps1 & users_in_local_rdp_groups.ps1

Administrator & Remote Desktop Users Group Members can take with these scripts. You have to install RSAT (Active Directory Module) before use.

You can get admin and remote desktop users from computers on whole domain computers. 
This script is needed a computer list file. If you need to get computer list, use this powershell script;

```sh
Get-ADComputer -Filter * | FT Name > computerlist.txt
```

Open and Replace txt file to csv file. Put the csv file under c:\temp\ and the file name must be computerlist.csv

If you cant run on powershell try to use this;
```sh
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\ScriptName.ps1
```


When the script running is finished, you can access output file on c:\temp\


### For ad_audit.ps1

.Synopsis

   Script for retrieving base Domain and Forest information for auditing purposes. No Need RSAT (Active Directory Module) installation for use.
   
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

```sh
script01.ps1 -Limit 10000 -Path .
```
   
   Retrieve a maximun of 10,000 users account instead of the default 1,000 and save the results to the cureent path.

.EXAMPLE

```sh
   script01.ps1 -Prefix ADX -Path .
```

   Retrieve the default 1,000 maximun of user accounts and save the results to the cureent path with each file having ADX appended to the beguining of each.

.NOTES

   Script has been tested against Windows PowerShell 2.0, 4.0 and 5.0. The script can be ran either form a 
   domain controller or a host that is domain joined using a domain administrator account since it does not
   have any dependency on any of the ActiveDirectory PowerShell modules and uses ADSI (Active Directory Scripting
   Interface) to retrieve all information from active directory.
