# Windows Threat Detection Research Lab

A defensive detection-as-code and telemetry research repository for Windows. All included fixture events are synthetic unless explicitly labelled otherwise.

## Enterprise v2 detection pack

The current experimental pack includes:

- PowerShell encoded-command execution
- Suspicious Windows service creation
- Windows Security audit-log clearing
- Membership changes to the local Administrators group
- Suspicious scheduled task creation
- Microsoft Defender preference changes through PowerShell

## Automated validation

GitHub Actions validates:

- YAML syntax
- Required rule metadata
- ATT&CK tags
- Expected matches against positive fixtures
- Clean results against negative fixtures
- Rule coverage across the synthetic dataset

```bash
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -p 'test_*.py' -v
```

## Existing Windows research tool

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Windows_Threat_Detection_Research_Lab.ps1 -Hours 48
```

The PowerShell tool remains read-only and supports event-frequency and timeline research.

## Documentation

- `docs/enterprise-v2-roadmap.md` — architecture and delivery plan
- `docs/attack-coverage.md` — ATT&CK and data-source coverage
- `docs/analyst-triage.md` — investigation guidance
- `docs/release-readiness.md` — release scope and remaining operational work

## Research workflow

1. Define the detection hypothesis and required telemetry.
2. Create synthetic positive and negative fixtures.
3. Implement the rule and ATT&CK mapping.
4. Run automated regression tests.
5. Document false positives, triage steps, and coverage gaps.
6. Convert and tune the rule for the authorized target SIEM before operational use.

## Safety

This project performs defensive, read-only event research. It does not execute attack simulations or modify endpoint controls. The included rules remain experimental until validated and tuned for a specific environment.
