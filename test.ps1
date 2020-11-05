Import-Module ActiveDirectory
$Searcher = New-Object DirectoryServices.DirectorySearcher([ADSI]"")
$Searcher.SearchRoot = 'LDAP://OU=CLS-ONFLY,OU=MS SQL,OU=Servers,OU=Domain Computers,DC=acme,DC=int'
$Searcher.Filter = "(objectClass=computer)"
$Computers = ($Searcher.Findall())

$Results = @()
md C:\All_Local_Admins

Foreach ($Computer in $Computers){
	$Path=$Computer.Path
	$Name=([ADSI]"$Path").Name
	write-host $Name
	$members =[ADSI]"WinNT://$Name/Administrators"
	$members = @($members.psbase.Invoke("Members"))
	$members | foreach {
		$LocalAdmins = $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)    # Create a new object for the purpose of exporting as a CSV
		$pubObject = new-object PSObject
		$pubObject | add-member -membertype NoteProperty -name "Server" -Value $Path
		$pubObject | add-member -membertype NoteProperty -name "Administrators" -Value $LocalAdmins

		# Append this iteration of our for loop to our results array.
		$Results += $pubObject
	}
}

$Results | Export-Csv -Path "C:\temp\ServerLocalAdmins.csv" -NoTypeInformation
$Results = $Null
