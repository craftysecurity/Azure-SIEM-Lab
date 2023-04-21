# filter failed rdp logon events from the security log
$failedlogons = Get-WinEvent -FilterHashtable @{logname="security";id=4625} | Select-Object -Property TimeCreated,Id,ProviderName,Properties 

# check if log file exists and if not create the file 
if (!(Test-Path -Path ".\failedlogins.json")) {
    New-Item -Path ".\failedlogins.json" -ItemType File
    $failedloginsfile = ".\failedlogins.json"
}

# loop through each event and get properties
