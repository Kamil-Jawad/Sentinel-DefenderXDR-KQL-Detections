# Sentinel-DefenderXDR-KQL-Detections

Production-oriented Microsoft Sentinel and Microsoft Defender XDR detections for Windows and Azure workloads, formatted as native Microsoft Sentinel Scheduled Analytics Rule YAML files ready for direct deployment.

---

## Detection Pack

The current detection pack contains 10 simplified analytics rules:

| ID | Rule Name | Severity | Primary ATT&CK | Data Source |
| :--- | :--- | :--- | :--- | :--- |
| **01** | Member Added to Privileged Domain Group | High | Persistence / Privilege Escalation (T1098) | SecurityEvent |
| **02** | High Volume Failed Logons (Possible Brute Force) | Medium | Credential Access (T1110) | SecurityEvent |
| **03** | Encoded PowerShell Command Execution | Medium | Execution / Defense Evasion (T1059.001, T1027) | SecurityEvent |
| **04** | Windows Security Log Cleared | High | Defense Evasion (T1070.001) | SecurityEvent |
| **05** | Command Line Network Discovery Commands | Low | Discovery (T1016, T1049) | SecurityEvent |
| **06** | New Scheduled Task Created via CLI | Medium | Persistence / Execution (T1053.005) | SecurityEvent |
| **07** | Volume Shadow Copy Deletion (Ransomware Activity) | High | Impact (T1490) | SecurityEvent |
| **08** | Entra ID Global Administrator Role Assigned | High | Persistence / Privilege Escalation (T1098) | AuditLogs |
| **09** | Microsoft Defender Real-time Protection Disabled | Medium | Defense Evasion (T1562.001) | SecurityEvent |
| **10** | High Volume Outbound Network Denials | Low | Command and Control (T1071) | AzureDiagnostics |

---

## Repository Structure

```text
.
├── README.md
├── Detections/
│   ├── 1. Account_Added_To_Privileged_Group.yaml
│   ├── 2. Failed_Logon_Spike.yaml
│   ├── 3. Encoded_PowerShell_Execution.yaml
│   ├── 4. Cleared_Windows_Event_Log.yaml
│   ├── 5. Command_Line_Network_Recon.yaml
│   ├── 6. Suspicious_Scheduled_Task_Creation.yaml
│   ├── 7. Shadow_Copy_Deletion.yaml
│   ├── 8. EntraID_Global_Admin_Assigned.yaml
│   ├── 9. Defender_Antivirus_Disabled.yaml
│   └── 10. Excessive_Denied_Network_Connections.yaml
└── .github/
    └── workflows/
        └── sentinel-deploy.yml
