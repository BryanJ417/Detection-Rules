SOC Detection Rules Repository



A collection of production-ready detection rules for common attack patterns observed in enterprise environments. These rules are designed for Splunk SIEM and aligned with the MITRE ATT\&CK framework.



Author

Bryan Jorge | [LinkedIn](https://linkedin.com/in/bryanjorge) | [GitHub](https://github.com/BryanJ417)



Overview

This repository contains 12 detection rules covering critical security scenarios including:

- Authentication attacks

- Lateral movement

- Privilege escalation

- Persistence mechanisms

- Data exfiltration

- Malware execution



Each rule includes:

- Splunk SPL query

- MITRE ATT\&CK mapping

- Severity classification

- False positive guidance

- Response recommendations



Repository Structure



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

└── templates/

   └── detection_rule_template.md





Detection Rule Categories



Authentication Attacks

- Brute Force Detection: Identifies multiple failed login attempts from single source

- Account Lockout Spike: Detects unusual volume of account lockouts

- Multiple Failed Logins: Tracks repeated authentication failures across multiple accounts



Lateral Movement

- PSExec Execution: Detects remote command execution via PSExec

- Admin Share Access: Monitors suspicious administrative share access patterns

- Pass-the-Hash: Identifies potential pass-the-hash attack indicators



Privilege Escalation

- Mimikatz Usage: Detects credential dumping tools in memory

- Unauthorized Admin Account: Alerts on unexpected administrative account creation

- Service Creation PrivEsc: Monitors suspicious service installations for privilege escalation



Persistence Mechanisms

- Scheduled Task Creation: Tracks suspicious scheduled task creation

- Registry Run Key Modification: Detects persistence via registry run keys

- New Service Installation: Monitors unauthorized service installations



Usage



Prerequisites

- Splunk Enterprise 8.0+ or Splunk Cloud

- Windows event logs (Security, System, Sysmon)

- Proper log forwarding configured



Implementation Steps

1. Review detection rule and adjust thresholds for your environment

2. Test rule in search mode before enabling as alert

3. Configure alert actions (email, ticket creation, SOAR integration)

4. Document baseline false positive rate

5. Tune detection based on environmental factors



Tuning Guidelines

Each rule includes recommended tuning parameters:

- Time windows (adjust based on environment size)

- Threshold values (tune based on baseline activity)

- Exclusion lists (whitelist known-good activity)



MITRE ATT&CK Coverage



| Technique ID | Technique Name | Detection Rule |

|--------------|----------------|----------------|

| T1110 | Brute Force | brute_force_detection.spl |

| T1021.002 | SMB/Windows Admin Shares | admin_share_access.spl |

| T1550.002 | Pass the Hash | pass_the_hash.spl |

| T1003.001 | LSASS Memory | mimikatz_usage.spl |

| T1136.001 | Create Account: Local Account | unauthorized_admin_account.spl |

| T1053.005 | Scheduled Task/Job | scheduled_task_creation.spl |

| T1547.001 | Registry Run Keys | registry_run_key.spl |

| T1569.002 | Service Execution | service_creation_privesc.spl |



Testing & Validation



All rules have been tested against:

- MITRE ATT&CK evaluations datasets

- Red team simulation scenarios

- Production SOC alert queues

- Known false positive scenarios



Response Playbooks



Each detection includes recommended response actions:

1. Initial Triage: Validation steps to confirm true positive

2. Investigation: Key artifacts to collect for analysis

3. Containment: Immediate actions to limit impact

4. Remediation: Steps to resolve root cause

5. Recovery: Actions to restore normal operations



Contributing



Improvements and additional detection rules are welcome. Please include:

- Complete SPL query with comments

- MITRE ATT\&CK mapping

- Test cases and expected results

- False positive analysis



Changelog



Version 1.0 (January 2026)

- Initial release with 12 detection rules

- Coverage across 5 MITRE ATT\&CK tactics

- Production-tested in lab environment



License

MIT License - Free to use and modify for security operations



Contact

For questions or collaboration: bryanjorge417@gmail.com



---

*These detection rules are provided for educational and defensive security purposes. Test thoroughly in your environment before production deployment.*

