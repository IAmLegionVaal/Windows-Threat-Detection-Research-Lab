# ATT&CK and Data-Source Coverage

All rules and events in this repository are synthetic unless explicitly labelled otherwise.

| Rule | ATT&CK technique | Data source | Event ID | Status |
|---|---|---|---:|---|
| PowerShell Encoded Command Execution | T1059.001 PowerShell | Process creation | 4688 | Experimental, CI tested |
| Suspicious Windows Service Creation | T1543.003 Windows Service | System service installation | 7045 | Experimental, CI tested |
| Windows Security Audit Log Cleared | T1070.001 Clear Windows Event Logs | Security audit log | 1102 | Experimental, CI tested |
| Member Added to Local Administrators Group | T1098 Account Manipulation | Security group management | 4732 | Experimental, CI tested |
| Suspicious Scheduled Task Creation | T1053.005 Scheduled Task | Security task creation | 4698 | Experimental, CI tested |
| Defender Preference Changed Through PowerShell | T1562.001 Impair Defenses | Process creation | 4688 | Experimental, CI tested |

## Required telemetry

- Process creation with command lines enabled for event 4688 or an equivalent EDR process source
- Security auditing for group management and scheduled task creation
- System event collection for service installation
- Security log-clearing events
- Reliable hostname, account, process, and command-line fields

## Known gaps

- No behavioral correlation across multiple hosts yet
- No network, DNS, registry, WMI, or authentication-anomaly rule pack yet
- No platform-specific deployment conversion for Microsoft Sentinel, Splunk, Elastic, or Security Onion yet
- Production thresholds and allow lists require environment-specific tuning
