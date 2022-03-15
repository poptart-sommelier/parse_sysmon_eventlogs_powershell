$events = Get-WinEvent -MaxEvents 2500 -FilterHashtable @{
    LogName="Microsoft-Windows-Sysmon/Operational"
    ID=1}

$parsed_events = @()
 
foreach ($event in $events)  {
 
    $splitevent = $event.Message -split "`r`n"

    $jsonstring = "{ "
    foreach ($line in $splitevent) {
        $line = $line -replace "\\","\\\\" `
               -replace "\{"," " `
               -replace "\}"," " `
               -replace '"','\"' `
               -replace "`n"," " 

        $line = $line -replace '(\s*[\w\s]+):\s*(.*)', '"$1":"$2",'
        $jsonstring = $jsonstring + $line } 

    $jsonstring = $jsonstring.Substring(0, $jsonstring.Length - 1) + ' }'

    $pe = ConvertFrom-Json -InputObject $jsonstring

    $ps_pe = [PSCustomObject]@{
        Image = $pe.Image
        CommandLine = $pe.CommandLine
        ProcessGuid = $pe.ProcessGuid
        ParentImage = $pe.ParentImage
        ParentCommandLine = $pe.ParentCommandLine
        ParentProcessGuid = $pe.ParentProcessGuid
    }
    $parsed_events += $ps_pe       
}

# $parsed_events | ConvertTo-Csv -Delimiter `t -NoTypeInformation | Out-File C:\users\user\Desktop\file.csv
$parsed_events | ConvertTo-Csv -NoTypeInformation | Out-File C:\users\user\Desktop\file.csv
