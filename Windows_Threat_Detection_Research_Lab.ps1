#requires -Version 5.1
[CmdletBinding()]
param([int]$Hours=48,[int]$MaxEventsPerLog=1500,[string]$OutputPath)

$stamp=Get-Date -Format 'yyyyMMdd_HHmmss'
if([string]::IsNullOrWhiteSpace($OutputPath)){$OutputPath=Join-Path ([Environment]::GetFolderPath('Desktop')) 'Windows_Threat_Detection_Research'}
New-Item -Path $OutputPath -ItemType Directory -Force|Out-Null
$start=(Get-Date).AddHours(-1*$Hours)

$logNames=@(
 'Security',
 'System',
 'Microsoft-Windows-PowerShell/Operational',
 'Microsoft-Windows-Windows Defender/Operational',
 'Microsoft-Windows-TaskScheduler/Operational'
)

$availability=foreach($log in $logNames){
 $info=Get-WinEvent -ListLog $log -ErrorAction SilentlyContinue
 [PSCustomObject]@{LogName=$log;Available=[bool]$info;Enabled=$info.IsEnabled;RecordCount=$info.RecordCount;LastWriteTime=$info.LastWriteTime}
}

$events=[System.Collections.Generic.List[object]]::new()
foreach($log in $logNames){
 try{
  $items=Get-WinEvent -FilterHashtable @{LogName=$log;StartTime=$start} -ErrorAction Stop|Select-Object -First $MaxEventsPerLog
  foreach($item in $items){
   $events.Add([PSCustomObject]@{TimeCreated=$item.TimeCreated;LogName=$item.LogName;EventId=$item.Id;Provider=$item.ProviderName;Level=$item.LevelDisplayName;RecordId=$item.RecordId})
  }
 }catch{}
}

$frequency=$events|Group-Object LogName,Provider,EventId|Sort-Object Count -Descending|ForEach-Object{
 [PSCustomObject]@{Count=$_.Count;LogName=$_.Group[0].LogName;Provider=$_.Group[0].Provider;EventId=$_.Group[0].EventId;FirstSeen=($_.Group|Sort-Object TimeCreated|Select-Object -First 1).TimeCreated;LastSeen=($_.Group|Sort-Object TimeCreated -Descending|Select-Object -First 1).TimeCreated}
}

$coverage=[PSCustomObject]@{Computer=$env:COMPUTERNAME;LookbackHours=$Hours;LogsRequested=$logNames.Count;LogsAvailable=@($availability|Where-Object Available).Count;EventsCollected=@($events).Count;DistinctEventGroups=@($frequency).Count;Generated=Get-Date}

$availability|Export-Csv (Join-Path $OutputPath "log_availability_$stamp.csv") -NoTypeInformation -Encoding UTF8
$events|Export-Csv (Join-Path $OutputPath "event_metadata_$stamp.csv") -NoTypeInformation -Encoding UTF8
$frequency|Export-Csv (Join-Path $OutputPath "event_frequency_$stamp.csv") -NoTypeInformation -Encoding UTF8
@{Summary=$coverage;LogAvailability=$availability;Frequency=$frequency}|ConvertTo-Json -Depth 8|Set-Content (Join-Path $OutputPath "research_summary_$stamp.json") -Encoding UTF8
$html="<h1>Windows Threat Detection Research Lab</h1><p>Generated $(Get-Date)</p><h2>Coverage</h2>$(@($coverage)|ConvertTo-Html -Fragment)<h2>Log Availability</h2>$($availability|ConvertTo-Html -Fragment)<h2>Most Frequent Event Groups</h2>$($frequency|Select-Object -First 150|ConvertTo-Html -Fragment)"
$html|ConvertTo-Html -Title 'Windows Threat Detection Research Lab'|Set-Content (Join-Path $OutputPath "research_report_$stamp.html") -Encoding UTF8
$coverage|Format-List
Write-Host "Research output saved to: $OutputPath" -ForegroundColor Green
