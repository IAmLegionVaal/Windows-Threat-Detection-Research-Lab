# Windows Threat Detection Research Lab — Enterprise v2 Roadmap

## Objective

Turn the current detection research repository into a senior-level Windows detection-engineering lab with reproducible event datasets, ATT&CK coverage, Sigma rules, automated tests, tuning evidence, and analyst-ready documentation.

## v2 architecture

- Research cases organized by behavior and ATT&CK technique
- Detection-as-code using Sigma and platform-specific queries
- Synthetic Windows event datasets
- Reproducible benign and suspicious test scenarios
- Rule metadata, severity, confidence, assumptions, and data-source requirements
- Automated syntax and schema validation
- Regression tests against positive and negative datasets
- Coverage and false-positive reporting

## Senior-level capabilities

### Detection content

- Process creation and command-line abuse
- PowerShell and script-host activity
- Credential access indicators
- Persistence through services, tasks, startup, and registry locations
- Account and group changes
- Remote execution and lateral movement
- Defender, Firewall, and security-control tampering
- Log clearing and defense evasion
- Suspicious network and DNS behavior

### Research workflow

1. Define a detection hypothesis.
2. Map required data sources and ATT&CK techniques.
3. Generate or collect synthetic positive events.
4. Generate benign negative events.
5. Write the Sigma rule or platform query.
6. Validate syntax and required fields.
7. Test expected matches and non-matches.
8. Document false positives and tuning decisions.
9. Record coverage gaps and assumptions.

### Evidence and reporting

- ATT&CK coverage matrix
- Data-source readiness matrix
- Rule catalog
- Test-result reports
- False-positive and suppression register
- Detection-quality scorecards
- Analyst triage notes and response recommendations

## Engineering standards

- Sigma schema and syntax validation
- Automated rule tests in GitHub Actions
- Pester or Python-based dataset tests
- Synthetic data only unless sanitized evidence is explicitly approved
- Semantic versioning for detection packs
- Changelog and release notes
- Contribution and review standards
- Clear separation between emulation, detection, and response content

## Delivery phases

### Phase 1

- Standard directory structure
- Rule metadata schema
- Initial Sigma rule pack
- Synthetic event fixtures
- CI validation and test harness
- ATT&CK coverage report

### Phase 2

- Expanded PowerShell, persistence, account, service, and task detections
- False-positive datasets
- Tuning profiles and analyst runbooks

### Phase 3

- Detection deployment adapters
- Coverage trend reporting
- Integration with a SIEM lab or Windows Event Forwarding pipeline

## Completion standard

The upgrade is merge-ready only after every rule validates, positive fixtures match, negative fixtures remain clean, false-positive considerations are documented, and all datasets are clearly labelled as synthetic or sanitized.