# Administrator & Remote Desktop Users Group Members

PowerShell Script for Security Assessment

You can get admin and remote desktop users from computers on whole domain computers. 
This script is needed a computer list file. If you need to get computer list, use this powershell script;

Get-ADComputer -Filter * | FT Name > computerlist.txt

Open and Replace txt file to csv file. Put the csv file under c:\temp\ and the file name must be computerlist.csv

If you cant run on powershell try to use this;

powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\ScriptName.ps1

When the script running is finished, you can access output file on c:\temp\
