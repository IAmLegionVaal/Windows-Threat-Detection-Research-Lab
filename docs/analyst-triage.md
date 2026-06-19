# Analyst Triage Guide

This guide supports the experimental detection pack. It is not a substitute for organizational incident-response procedures.

## General triage sequence

1. Confirm the event timestamp, hostname, account, parent process, and command line.
2. Determine whether the activity was approved administration, deployment, or maintenance.
3. Review adjacent process, authentication, service, task, Defender, and network events.
4. Identify whether the same account or behavior appears on additional endpoints.
5. Preserve relevant logs and escalate according to the incident-response process.

## Encoded PowerShell

- Decode the command in an isolated analysis environment.
- Review parent process, user context, network destinations, and script-block logs.
- Compare with approved management tooling and known automation.

## Service creation

- Review the service image path, signer, creation account, start type, and first execution.
- Validate the binary or script hash and deployment source.
- Check for remote service creation and lateral-movement evidence.

## Security log cleared

- Confirm who cleared the log and whether a maintenance ticket exists.
- Review remote log collectors to recover preceding activity.
- Treat unexplained clearing as high-priority defense-evasion evidence.

## Local Administrators membership

- Verify the added identity, initiator, approval, and expected expiry.
- Review subsequent logons and privileged activity.
- Remove unauthorized membership through the approved response process.

## Scheduled task creation

- Inspect task XML, triggers, action, run-as account, hidden state, and file paths.
- Review whether the task executes from user-writable or temporary locations.
- Correlate with process creation and file-creation telemetry.

## Defender preference changes

- Identify the exact preference changed and whether endpoint management initiated it.
- Review Defender operational events and tamper-protection status.
- Investigate associated exclusions, disabled protections, and follow-on execution.
