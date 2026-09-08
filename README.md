# Sentinel-DefenderXDR-KQL-Detections

Production-oriented Microsoft Sentinel and Microsoft Defender XDR detections for Windows workloads, with a focus on Azure Windows VMs.

## Detection Pack

The current Windows detection pack contains 10 analytics rules:

| ID | Detection | Severity | Primary ATT&CK | Data Source |
|---|---|---|---|---|
| WIN-001 | Windows VM - Brute Force Attack Detected | High | T1110 | SecurityEvent |
| WIN-002 | Windows VM - Password Spraying Attack Detected | High | T1110.003 | SecurityEvent |
| WIN-003 | Windows VM - Successful RDP After Multiple Failures | High | T1110 / T1110.001 | SecurityEvent |
| WIN-004 | Windows VM - Privileged Account Added to Admin Group | High | T1098 / T1098.007 | SecurityEvent |
| WIN-005 | Windows VM - Suspicious PowerShell Execution | High | T1059.001 / T1027 / T1105 | DeviceProcessEvents |
| WIN-006 | Windows VM - Suspicious Service Creation | High | T1543.003 | SecurityEvent |
| WIN-007 | Windows VM - Suspicious Scheduled Task Creation | High | T1053.005 | SecurityEvent |
| WIN-008 | Windows VM - Unexpected LOLBin Execution | High | T1218 and sub-techniques | DeviceProcessEvents |
| WIN-009 | Windows VM - Security Control Disabled or Tampered | Critical | T1562.001 / T1070.001 | DeviceEvents + WindowsEvent |
| WIN-010 | Windows VM - Lateral Movement or Remote Execution Detected | High | T1021 / T1047 / T1569.002 | SecurityEvent + DeviceProcessEvents |

## Repository Structure

```text
.
├── README.md
└── detections/
    └── windows/
        ├── WIN-001-brute-force.yml
        ├── WIN-002-password-spraying.yml
        ├── WIN-003-successful-rdp-after-failures.yml
        ├── WIN-004-privileged-account-added-to-admin-group.yml
        ├── WIN-005-suspicious-powershell.yml
        ├── WIN-006-suspicious-service-creation.yml
        ├── WIN-007-suspicious-scheduled-task.yml
        ├── WIN-008-unexpected-lolbin-execution.yml
        ├── WIN-009-security-control-tampering.yml
        └── WIN-010-lateral-movement-remote-execution.yml
```

## Prerequisites

These rules assume Microsoft Sentinel is connected to the relevant Windows and/or Defender XDR telemetry sources.

### Windows Event Collection

Depending on the rule and ingestion architecture, enable the appropriate Windows security/event connector and verify that the expected events are reaching the workspace.

Common Windows events used by this pack include:

- `4624` - Successful logon
- `4625` - Failed logon
- `4698` - Scheduled task created
- `4702` - Scheduled task updated
- `4728` - Member added to global security group
- `4732` - Member added to local security group
- `4756` - Member added to universal security group
- `7045` - Windows service installed
- `1102` - Security audit log cleared
- `4719` - Audit policy changed
- `5025` - Windows Firewall service stopped

### Microsoft Defender XDR

WIN-005, WIN-008, WIN-009, and WIN-010 use Defender telemetry where applicable, including:

- `DeviceProcessEvents`
- `DeviceEvents`
- `WindowsEvent`

Confirm the Defender for Endpoint connector is enabled and that the target Azure VMs are onboarded and reporting telemetry.

## Deployment

Each detection is stored as a Sentinel analytics-rule YAML definition. Before deployment, review the rule metadata and adapt the environment-specific values.

Recommended deployment workflow:

1. Validate that the required data connector is enabled.
2. Confirm the target Windows VMs are sending telemetry.
3. Review the KQL in the Azure Monitor Logs query editor.
4. Tune exclusions and trusted entities for the environment.
5. Deploy the YAML as a Scheduled analytics rule.
6. Validate alert generation using controlled test activity.
7. Review incident grouping and entity mapping in Sentinel.
8. Monitor false positives and adjust thresholds/watchlists as needed.

For Microsoft Sentinel repository-based deployments, keep the rule files in source control and use your preferred CI/CD process to promote changes between environments.

## Watchlists and Tuning

Some detections are intentionally conservative but should still be tuned for the local environment.

### Recommended watchlists

Suggested watchlists include:

- `Windows_LateralMovement_TrustedSources` - trusted administration/jump-host IPs or source systems.
- Privileged/admin account allowlist - approved administrative identities.
- Service allowlist - expected enterprise, Azure, monitoring, backup, patching, and security services.
- Scheduled task allowlist - approved automation, patching, management, and monitoring tasks.
- PowerShell/LOLBin parent-process allowlist - approved automation and management tooling.

### Tuning principles

Avoid broad exclusions such as excluding all administrators or all PowerShell activity. Prefer narrowly scoped conditions using combinations of account, host, source IP, process, parent process, service/task name, and command-line context.

Start with production baselines, then adjust thresholds, lookback windows, trusted sources, and known-good automation paths based on observed telemetry.

## Incident Handling

The rules include entity mappings and custom details intended to improve investigation context. Where possible, incidents are grouped by host, account, IP, process, security group, or detection type to reduce duplicate cases while preserving useful context.

During triage, prioritize:

1. The affected VM and account.
2. Source IP and authentication history.
3. Process/parent-process relationships and command lines.
4. Persistence changes such as services, scheduled tasks, or group membership.
5. Security-control tampering or log-clearing activity.
6. Follow-on network, credential, or lateral-movement activity.

## False-Positive Management

Common legitimate sources of noise include:

- Vulnerability scanners and infrastructure monitoring.
- Domain administration and jump servers.
- Azure/enterprise management agents.
- Patch and software deployment systems.
- Approved automation using PowerShell or scheduled tasks.
- Backup and security tooling.

Document approved exceptions in source control and keep them specific enough to prevent a real attacker from inheriting the same exclusion.

## Testing Guidance

Before enabling a detection in production, test it against both positive and negative cases.

Examples:

- Brute-force rules: controlled failed authentication bursts.
- RDP correlation: multiple failed RDP attempts followed by a successful RDP authentication.
- Group membership: add and remove a test account from an approved administrative group.
- PowerShell: test encoded commands, download patterns, and normal administrative scripts.
- Service/task persistence: create benign test services or scheduled tasks and verify allowlisting.
- LOLBins: validate approved software deployment paths versus suspicious command-line patterns.
- Tampering: validate telemetry for expected security-tool configuration changes in a controlled test environment.
- Lateral movement: use an approved test account from a known jump host and verify trusted-source tuning.

Do not perform adversarial testing on production systems without an approved change and security-testing process.

## Operational Notes

These rules are detection-engineering starting points, not universal one-size-fits-all signatures. Event schemas, connector coverage, Defender telemetry, and Sentinel capabilities can differ between environments. Always validate the exact fields and event content present in your workspace before production rollout.

Thresholds and lookback windows should be reviewed after collecting a representative baseline. High and Critical alerts should have an associated incident response playbook or documented analyst procedure.

## MITRE ATT&CK Coverage

The pack currently covers the following major behaviors:

- Credential Access: Brute Force and password spraying.
- Persistence and Privilege Escalation: privileged group membership, services, and scheduled tasks.
- Execution and Defense Evasion: PowerShell and LOLBin proxy execution.
- Impair Defenses: Defender/security-control tampering and audit-log clearing.
- Lateral Movement: RDP, SMB/Windows Admin Shares, WinRM, WMI, and service-based remote execution indicators.

## Disclaimer

Use these detections only in environments where you have authorization to monitor the systems and accounts involved. Validate each rule against your Microsoft Sentinel and Defender XDR schema, data availability, operational requirements, and change-management process before production deployment.
