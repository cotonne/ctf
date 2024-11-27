# Event Log

## Events

 - 4104 : Execution of a powershell script
 - 4688: A new process has been created
 - 4672 (Special privileges assigned to new logon) => 
 - 4703 (A user right was adjusted) => 
 - 4673 (A privileged service was called) 
 - 4674 (An operation was attempted on a privileged object) 

## Tools & commands

 - Search security logs (can display passwords): `wevtutil qe Security /rd:true /f:text | Select-String "/user"`
 - Search security logs `Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'} | Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}`

## Ref

 - [Windows Privilege Abuse: Auditing, Detection, and Defense](https://blog.palantir.com/windows-privilege-abuse-auditing-detection-and-defense-3078a403d74e)
