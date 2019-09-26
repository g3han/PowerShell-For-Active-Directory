$groups = "Remote Desktop Users";
$servers = import-csv "c:\temp\computerlist.csv"
foreach ($server in $servers) {
    $servername = $server.name;
    if((test-connection -computername $servername -count 1 -quiet)) {
        foreach ($group in $groups) {
            $localgroup = [ADSI]"WinNT://$servername/$group";
            $members = @($localgroup.Invoke("Members"));
            foreach ($member in $members) {
                $memberName = $member.GetType().Invokemember("Name","GetProperty",$null,$member,$null);
                $memberType = $member.GetType().Invokemember("Class","GetProperty",$null,$member,$null);
                $outstring = $servername + "," + $group + "," + $membername + "," + $membertype;
                write-host $outstring;
                $outstring >> c:\temp\users_in_rdp_groups.csv;
            }
        }
    }
}