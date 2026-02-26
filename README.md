# SOC Detection Rules Repository

A collection of production-ready detection rules for common attack patterns observed in enterprise environments. These rules are designed for Splunk SIEM and aligned with the MITRE ATT&CK framework.

**Author:** Bryan Jorge | [LinkedIn](https://linkedin.com/in/bryanjorge) | [GitHub](https://github.com/BryanJ417)

---

## Overview

This repository contains **23 detection rules** covering critical security scenarios across **on-premises infrastructure and cloud environments**:

**On-Premises Coverage:**
- Authentication attacks
- Lateral movement
- Privilege escalation
- Persistence mechanisms

**Cloud Coverage (AWS & Azure):**
- IAM credential abuse
- Cloud privilege escalation
- Storage exfiltration (S3, Blob)
- Compute resource hijacking

Each rule includes:
- Splunk SPL query
- MITRE ATT&CK mapping
- Severity classification
- False positive guidance
- Response recommendations

---

## Repository Structure

```
detection-rules/
├── README.md
├── authentication/
│   ├── brute_force_detection.spl
│   ├── multiple_failed_logins.spl
│   └── account_lockout_spike.spl
├── lateral-movement/
│   ├── psexec_execution.spl
│   ├── admin_share_access.spl
│   └── pass_the_hash.spl
├── privilege-escalation/
│   ├── mimikatz_usage.spl
│   ├── unauthorized_admin_account.spl
│   └── service_creation_privesc.spl
├── persistence/
│   ├── scheduled_task_creation.spl
│   ├── registry_run_key.spl
│   └── new_service_installation.spl
├── aws/
│   ├── access_key_new_geolocation.spl
│   ├── root_account_usage.spl
│   ├── iam_policy_privilege_escalation.spl
│   ├── role_assumption_chaining.spl
│   ├── s3_high_volume_getobject.spl
│   ├── s3_bucket_made_public.spl
│   └──ec2_cryptomining_instance_launch.spl
├── azure/
│   ├──entra_id_impossible_travel.spl
│   ├──privileged_role_assignment.spl
│   ├── blob_storage_anomalous_download.spl
│   └── vm_extension_rce_backdoor.spl
└── templates/
    └── detection_rule_template.md
```

---

## Detection Rule Categories

### On-Premises Detection

#### Authentication Attacks
| Rule | File | Description |
|------|------|-------------|
| Brute Force Detection | `brute_force_detection.spl` | Identifies multiple failed login attempts from single source |
| Account Lockout Spike | `account_lockout_spike.spl` | Detects unusual volume of account lockouts |
| Multiple Failed Logins | `multiple_failed_logins.spl` | Tracks repeated authentication failures across multiple accounts |

#### Lateral Movement
| Rule | File | Description |
|------|------|-------------|
| PSExec Execution | `psexec_execution.spl` | Detects remote command execution via PSExec |
| Admin Share Access | `admin_share_access.spl` | Monitors suspicious administrative share access patterns |
| Pass-the-Hash | `pass_the_hash.spl` | Identifies potential pass-the-hash attack indicators |

#### Privilege Escalation
| Rule | File | Description |
|------|------|-------------|
| Mimikatz Usage | `mimikatz_usage.spl` | Detects credential dumping tools in memory |
| Unauthorized Admin Account | `unauthorized_admin_account.spl` | Alerts on unexpected administrative account creation |
| Service Creation PrivEsc | `service_creation_privesc.spl` | Monitors suspicious service installations for privilege escalation |

#### Persistence Mechanisms
| Rule | File | Description |
|------|------|-------------|
| Scheduled Task Creation | `scheduled_task_creation.spl` | Tracks suspicious scheduled task creation |
| Registry Run Key Modification | `registry_run_key.spl` | Detects persistence via registry run keys |
| New Service Installation | `new_service_installation.spl` | Monitors unauthorized service installations |

---

### Cloud Detection (AWS & Azure)

#### AWS — IAM & Credential Abuse
| Rule | File | Description |
|------|------|-------------|
| Access Key from New Geolocation | `access_key_new_geolocation.spl` | Detects IAM key usage from a country not seen in 30-day baseline |
| Root Account Usage | `root_account_usage.spl` | Zero-tolerance alert on any AWS root account activity |

#### AWS — Privilege Escalation
| Rule | File | Description |
|------|------|-------------|
| IAM Policy Privilege Escalation | `iam_policy_privilege_escalation.spl` | Self-escalation via AttachUserPolicy, PutUserPolicy, or admin policy creation |
| Role Assumption Chaining | `role_assumption_chaining.spl` | Rapid multi-hop AssumeRole pivoting, especially cross-account |

#### AWS — S3 Data Exfiltration
| Rule | File | Description |
|------|------|-------------|
| High-Volume S3 GetObject | `s3_high_volume_getobject.spl` | Bulk object downloads exceeding volume/count thresholds |
| S3 Bucket Made Public | `s3_bucket_made_public.spl` | Bucket policy/ACL changes enabling public read access |

#### AWS — Compute Abuse
| Rule | File | Description |
|------|------|-------------|
| EC2 Cryptomining Launch | `ec2_cryptomining_instance_launch.spl` | GPU/compute-heavy instance launches indicative of crypto mining |

#### Azure — IAM & Credential Abuse
| Rule | File | Description |
|------|------|-------------|
| Entra ID Impossible Travel | `entra_id_impossible_travel.spl` | Logins from two geolocations >500km apart within 60 minutes |

#### Azure — Privilege Escalation
| Rule | File | Description |
|------|------|-------------|
| Privileged Role Assignment | `privileged_role_assignment.spl` | Direct (non-PIM) assignment of Global Admin and other high-privilege roles |

#### Azure — Blob Storage Exfiltration
| Rule | File | Description |
|------|------|-------------|
| Blob Storage Anomalous Download | `blob_storage_anomalous_download.spl` | High-volume Blob reads, AzCopy transfers, or anonymous access |

#### Azure — Compute Abuse
| Rule | File | Description |
|------|------|-------------|
| VM Extension RCE Backdoor | `vm_extension_rce_backdoor.spl` | CustomScript/VMAccess extension installs enabling remote code execution |

---

## MITRE ATT&CK Coverage

### On-Premises
| Technique ID | Technique Name | Detection Rule |
|---|---|---|
| T1110 | Brute Force | `brute_force_detection.spl` |
| T1021.002 | SMB/Windows Admin Shares | `admin_share_access.spl` |
| T1550.002 | Pass the Hash | `pass_the_hash.spl` |
| T1003.001 | LSASS Memory | `mimikatz_usage.spl` |
| T1136.001 | Create Account: Local Account | `unauthorized_admin_account.spl` |
| T1053.005 | Scheduled Task/Job | `scheduled_task_creation.spl` |
| T1547.001 | Registry Run Keys | `registry_run_key.spl` |
| T1569.002 | Service Execution | `service_creation_privesc.spl` |

### Cloud (AWS & Azure)
| Technique ID | Technique Name | Detection Rule |
|---|---|---|
| T1078.004 | Valid Accounts: Cloud Accounts | `access_key_new_geolocation.spl`, `root_account_usage.spl`, `entra_id_impossible_travel.spl` |
| T1098.001 | Account Manipulation: Additional Cloud Credentials | `iam_policy_privilege_escalation.spl` |
| T1098.003 | Account Manipulation: Additional Cloud Roles | `privileged_role_assignment.spl` |
| T1548.005 | Abuse Elevation: Temporary Elevated Access | `role_assumption_chaining.spl` |
| T1530 | Data from Cloud Storage | `s3_high_volume_getobject.spl`, `s3_bucket_made_public.spl`, `blob_storage_anomalous_download.spl` |
| T1496 | Resource Hijacking | `ec2_cryptomining_instance_launch.spl` |
| T1059.004 | Command and Scripting: Unix Shell | `vm_extension_rce_backdoor.spl` |
| T1546 | Event Triggered Execution | `vm_extension_rce_backdoor.spl` |

---

## How On-Prem and Cloud Rules Complement Each Other

| Your On-Prem Coverage | Cloud Extension | Attack Flow |
|---|---|---|
| `brute_force_detection.spl` (Windows Event 4625) | `entra_id_impossible_travel.spl` (Azure sign-in anomalies) | Attacker steals cloud creds → uses from anomalous location → pivots into on-prem via VPN/sync |
| `mimikatz_usage.spl` (credential dumping) | `access_key_new_geolocation.spl` (stolen key usage) | Attacker dumps creds from workstation → finds AWS keys in config files → uses from external IP |
| `unauthorized_admin_account.spl` | `privileged_role_assignment.spl` + `iam_policy_privilege_escalation.spl` | Attacker escalates in cloud → syncs to on-prem AD → creates backdoor admin account |
| `pass_the_hash.spl` (lateral movement) | `role_assumption_chaining.spl` (cloud lateral movement) | Attacker pivots between AWS accounts → assumes role into prod → accesses on-prem via Site-to-Site VPN |
| `scheduled_task_creation.spl` (persistence) | `vm_extension_rce_backdoor.spl` (cloud persistence) | Attacker establishes persistence in cloud VMs → uses as C2 relay → establishes scheduled tasks on domain controllers |

---

## Prerequisites & Log Sources

### On-Premises
- **Windows Security Event Logs** (Event IDs: 4625, 4740, 4776, 4672, etc.)
- **Sysmon Logs** (Event IDs: 1, 3, 7, 10, etc.)
- **System Event Logs** (Service creation, scheduled task events)
- Splunk Universal Forwarder configured on endpoints and domain controllers
- Recommended indexes: `wineventlog`, `sysmon`

### AWS
- **CloudTrail** with multi-region trails enabled in all active regions
- **S3 Data Events** enabled in CloudTrail (required for `s3_high_volume_getobject.spl`)
- Splunk Add-on for AWS installed and configured with `aws:cloudtrail` sourcetype
- Recommended indexes: `aws_cloudtrail`

### Azure
- **Azure Activity Logs** forwarded to Splunk via Event Hub or Azure Monitor connector
- **Entra ID Sign-In Logs** and **Audit Logs** enabled and ingested
- **Azure Storage Diagnostic Logs** enabled per-storage-account (for blob exfiltration detection)
- Splunk Add-on for Microsoft Cloud Services or Azure Log Analytics connector
- Recommended indexes: `azure_activity`, `azure_aad`, `azure_storage`

---

## Implementation Guide

### Phase 1: Deploy On-Premises Rules
1. **Adjust index names** — update `index=wineventlog` to match your Splunk environment
2. **Test in search mode** — run each rule over 7 days of historical data before enabling as alerts
3. **Establish baselines** — measure normal authentication failures, service creations, share access
4. **Apply exclusions** — whitelist known service accounts, management servers, legitimate admin activity
5. **Enable as scheduled alerts** — use recommended schedule from each rule's header

### Phase 2: Deploy Cloud Rules
1. **Verify log ingestion** — confirm CloudTrail and Azure logs are flowing into Splunk
2. **Enable S3 data events** — required for AWS exfiltration detection (not enabled by default)
3. **Test in search mode** — run over 14 days to establish cloud activity baselines
4. **Tune volume thresholds** — cloud environments often have higher API call volumes than expected
5. **Enable as scheduled alerts** — cloud rules typically run every 15-30 minutes vs. hourly for on-prem

### Phase 3: SOAR Integration
1. **Configure enrichment** — auto-pull geolocation, threat intel, user context on alert creation
2. **Implement correlation** — alert if the same principal/user triggers both on-prem and cloud rules
3. **One-click containment** — prepare disable-credential and revoke-session actions
4. **Automated documentation** — capture full investigation timeline in ticketing system

---

## Testing & Validation

All rules have been tested against:
- MITRE ATT&CK evaluation datasets
- Red team simulation scenarios
- Production SOC alert queues
- Known false positive scenarios

Before production deployment:
- [ ] Tested against known malicious samples
- [ ] Tested against normal baseline activity
- [ ] Tuning parameters documented
- [ ] False positive scenarios identified
- [ ] Response playbook created
- [ ] Investigation queries validated
- [ ] MITRE ATT&CK mapping verified
- [ ] Peer reviewed by another analyst

---

## Response Playbooks

Each detection includes a standardized response workflow:

1. **Initial Triage:** Validation steps to confirm true positive
2. **Investigation:** Key artifacts to collect for analysis
3. **Containment:** Immediate actions to limit impact
4. **Remediation:** Steps to resolve root cause
5. **Recovery:** Actions to restore normal operations

Cloud-specific additions:
- Credential rotation procedures for AWS access keys and Azure service principals
- STS session revocation commands
- Storage access restriction via network ACLs
- Cost impact assessment for compute abuse scenarios

---

## Tuning Guidelines

Each rule includes recommended tuning parameters organized by category:

**Volume Thresholds:**
- Time windows (adjust based on environment size and activity patterns)
- Count thresholds (tune based on baseline measurements)
- Byte transfer limits (for exfiltration detection)

**Exclusions:**
- Service accounts and automation principals
- Known-good source IPs (corporate VPN gateways, cloud CI/CD runners)
- Approved administrative activity windows
- Development/sandbox account IDs

**Environment-Specific:**
- Geographic whitelists for global organizations
- VPC endpoint and private link configurations
- Federated identity provider trust relationships

---

## Contributing

Improvements and additional detection rules are welcome. Please include:
- Complete SPL query following the template format
- MITRE ATT&CK mapping with technique IDs
- Test cases and expected results
- False positive analysis and tuning guidance
- Response playbook with investigation queries

---

## Changelog

**Version 2.0 (February 2026)**
- Added 11 cloud detection rules (7 AWS + 4 Azure)
- Expanded MITRE ATT&CK coverage to include Cloud matrix
- Added unified implementation guide for hybrid environments
- Documented on-prem + cloud attack flow correlation patterns

**Version 1.0 (January 2026)**
- Initial release with 12 on-premises detection rules
- Coverage across 5 MITRE ATT&CK tactics
- Production-tested in lab environment

---

## License

MIT License — Free to use and modify for security operations

---

## Contact

For questions or collaboration: **bryanjorge417@gmail.com**

---

*These detection rules are provided for educational and defensive security purposes. Test thoroughly in your environment before production deployment.*
