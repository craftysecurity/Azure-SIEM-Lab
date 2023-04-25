# this powershell script is made to be used in conjunction with Azure Sentinel
# it will extract failed logon events from the security log and query ip-api.com to get information about the IP address and output the information to the failedlogins.json file
# it will include the event ID, event timestamp, event source, IP address, event and username in the failedlogins.json file
# it will only extract events that have not been extracted before by checking the last event time written to the failedlogins.json file
# it will limit the number of API calls to ip-api.com to 45 per minute

# check if the failedlogins.json file exists and if it does not exist, create the file and set the variable to $failedlohinsfile 



# filter failed rdp logon events from the security log

$failedlogons = Get-WinEvent -FilterHashtable @{logname="security";id=4625} | Select-Object -Property TimeCreated,Id,ProviderName,Properties 

# check if log file exists and if it does not exist, create the file and set the variable to $failedloginsfile

if (!(Test-Path -Path ".\failedlogins.json")) {
    New-Item -Path ".\failedlogins.json" -ItemType File
    $failedloginsfile = ".\failedlogins.json"
}

# step through each event and get the event collected

foreach ($failedlogon in $failedlogons) {
   
    if (!(Test-Path -Path ".\failedlogins.json")) {
        New-Item -Path ".\failedlogins.json" -ItemType File
        $failedloginsfile = ".\failedlogins.json"
    }
    
    # if ip is not null I.E is greater then 5
    if ($failedlogon.properties[19].value.Length -ge 5) {

        # pick out the field we want
        $timestamp = $failedlogon.TimeCreated
        $year = $timestamp.TimeCreated.Y

        $month = $timestamp.TimeCreated.M
        if("$($failedlogon.TimeCreated.M)".Length -eq 1) {
            $month = "0$($failedlogon.TimeCreated.M)"
            }


        $day = $timestamp.TimeCreated.D
        if("$($failedlogon.TimeCreated.D)".Length -eq 1) {
            $day = "0$($failedlogon.TimeCreated.D)"
            }

        $hour = $timestamp.TimeCreated.H
        if("$($failedlogon.TimeCreated.H)".Length -eq 1) {
            $hour = "0$($failedlogon.TimeCreated.H)"
            }

        $minute = $timestamp.TimeCreated.m
        if("$($failedlogon.TimeCreated.m)".Length -eq 1) {
            $minute = "0$($failedlogon.TimeCreated.m)"
            }
        
        $second = $timestamp.TimeCreated.s
        if("$($failedlogon.TimeCreated.s)".Length -eq 1) {
            $second = "0$($failedlogon.TimeCreated.s)"
            }
        $timestamp = "$($year)-$($month)-$($day) $($hour):$($minute):$($second)"
        $eventid = $failedlogon.Id
        $username = $failedlogon.properties[5].value
        $sourceHostname = $failedlogon.properties[11].value

        # open the failedlogins.json file 
        $failedlogins = Get-Content -Path $failedloginsfile 

        # check if log already contains the event using timestamp 

        if(-Not ($failedloginsfile -match "$($timestamp)" -or ($failedloginsfile.Length -eq 0))) {
                       
                # if the log does not contain the event, query ip-api.com for information about the IP address and store the information in a variable called $ipinfo

                Start-Sleep -Seconds 1

                $ipinfo = Invoke-WebRequest -Uri "http://ip-api.com/json/$($failedlogon.properties[19].value)" -UseBasicParsing | ConvertFrom-Json
    
                # check if the ipinfo variable contains information about the IP address and if it does, store the information in variables
                # if the ipinfo variable does not contain information about the IP address, set the variables to "NULL"
                if ($ipinfo.status -eq "success") {
                    $ip = $ipinfo.query
                    $country = $ipinfo.country
                    $countryCode = $ipinfo.countryCode
                    $region = $ipinfo.region
                    $regionName = $ipinfo.regionName
                    $city = $ipinfo.city
                    $zip = $ipinfo.zip
                    $lat = $ipinfo.lat
                    $lon = $ipinfo.lon
                    $timezone = $ipinfo.timezone
                    $isp = $ipinfo.isp
                    $org = $ipinfo.org
                    $as = $ipinfo.as
                    $reverse = $ipinfo.reverse
                    $mobile = $ipinfo.mobile
                    $proxy = $ipinfo.proxy
                    $hosting = $ipinfo.hosting
                }
                else {
                    $ip = "NULL"
                    $country = "NULL"
                    $countryCode = "NULL"
                    $region = "NULL"
                    $regionName = "NULL"
                    $city = "NULL"
                    $zip = "NULL"
                    $lat = "NULL"
                    $lon = "NULL"
                    $timezone = "NULL"
                    $isp = "NULL"
                    $org = "NULL"
                    $as = "NULL"
                    $reverse = "NULL"
                    $mobile = "NULL"
                    $proxy = "NULL"
                    $hosting = "NULL"
                }
    
                # create a new object with the information about the event and store it in a variable called $newlog
                $newlog = New-Object -TypeName PSObject -Property @{
                    "timestamp" = $timestamp
                    "eventid" = $eventid
                    "username" = $username
                    "sourceHostname" = $sourceHostname
                    "ip" = $ip
                    "country" = $country
                    "countryCode" = $countryCode
                    "region" = $region
                    "regionName" = $regionName
                    "city" = $city
                    "zip" = $zip
                    "lat" = $lat
                    "lon" = $lon
                    "timezone" = $timezone
                    "isp" = $isp
                    "org" = $org
                    "as" = $as
                    "reverse" = $reverse
                    "mobile" = $mobile
                    "proxy" = $proxy
                    "hosting" = $hosting
    }

                # append the new object to the failedlogins.json file include the comma if the file is not empty and all the information about the event including the timestamp and username
                Add-Content -Path $failedloginsfile -Value $newlog | ConvertTo-Json -Compress




                # print the information about the event to the console  
                Write-Host "[$($timestamp)] $($eventid) $($username) $($sourceHostname) $($ip) $($country) $($countryCode) $($region) $($regionName) $($city) $($zip) $($lat) $($lon) $($timezone) $($isp) $($org) $($as) $($reverse) $($mobile) $($proxy) $($hosting)" -ForegroundColor Green
            }
}
}


        
