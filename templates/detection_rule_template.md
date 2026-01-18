\# Detection Rule Template



Use this template when creating new detection rules for consistency and completeness.



\## Rule Metadata



```spl

/\*

Detection Rule: \[DESCRIPTIVE NAME]

Author: Bryan Jorge

MITRE ATT\&CK: \[TECHNIQUE ID] - \[TECHNIQUE NAME]

Severity: \[Critical/High/Medium/Low]

Description: \[Brief description of what this rule detects and why it matters]

\*/

```



\## Detection Query



```spl

\[YOUR SPLUNK SPL QUERY HERE]



/\*

TUNING PARAMETERS:

\- \[parameter1]: \[Description and recommended values]

\- \[parameter2]: \[Description and recommended values]

\- Whitelist examples: | where NOT \[condition]



FALSE POSITIVES:

\- \[Common legitimate activity that might trigger this rule]

\- \[Environmental factors that cause false alerts]

\- \[Known systems or processes that need whitelisting]



RECOMMENDED RESPONSE:

1\. \[Immediate triage step]

2\. \[Investigation step]

3\. \[Validation step]

4\. \[Containment action if confirmed malicious]

5\. \[Remediation step]

6\. \[Recovery/restoration step]



INVESTIGATION QUERIES:

\- \[Related query 1]: index=... \[brief description]

\- \[Related query 2]: index=... \[brief description]

\- \[Timeline query]: index=... \[brief description]



\[ADDITIONAL CONTEXT SECTIONS AS NEEDED]:

\- Data sources required

\- Detection variants

\- Common attacker patterns

\- Prevention measures

\- Related techniques

\*/

```



\## Template Sections Explained



\### Required Sections

Every detection rule must include:

1\. \*\*Rule Metadata\*\*: Name, author, MITRE mapping, severity, description

2\. \*\*Detection Query\*\*: The actual SPL search logic

3\. \*\*Tuning Parameters\*\*: How to adjust for different environments

4\. \*\*False Positives\*\*: Known benign scenarios

5\. \*\*Recommended Response\*\*: Action steps for analysts

6\. \*\*Investigation Queries\*\*: Follow-up searches



\### Optional But Recommended Sections

Include when relevant:

\- \*\*High-Risk Indicators\*\*: Conditions that increase confidence

\- \*\*Data Sources Required\*\*: Specific logs needed

\- \*\*Detection Variants\*\*: Alternative query approaches

\- \*\*Common Attacker Patterns\*\*: Known malicious behaviors

\- \*\*Prevention Measures\*\*: How to reduce attack surface

\- \*\*Related Techniques\*\*: Connected MITRE ATT\&CK techniques

\- \*\*Attack Chain Context\*\*: Where this fits in typical attacks



\## Severity Guidelines



\*\*Critical\*\*: 

\- Active exploitation detected

\- Credential compromise confirmed

\- Data exfiltration in progress

\- Requires immediate response



\*\*High\*\*: 

\- Strong indicators of malicious activity

\- Persistence mechanism detected

\- Privilege escalation attempt

\- Requires urgent investigation



\*\*Medium\*\*: 

\- Suspicious behavior detected

\- Policy violation

\- Reconnaissance activity

\- Requires timely investigation



\*\*Low\*\*: 

\- Informational alert

\- Potential misconfiguration

\- Baseline deviation

\- Review during normal operations



\## Query Best Practices



\### Performance

\- Use index and sourcetype early in search

\- Limit time ranges appropriately

\- Use stats instead of transaction when possible

\- Avoid wildcards at beginning of strings



\### Accuracy

\- Test queries against known true positives

\- Validate against known false positives

\- Use specific EventCodes when possible

\- Include multiple detection points when available



\### Maintainability

\- Comment complex regex patterns

\- Explain scoring logic

\- Document thresholds and why they were chosen

\- Include version history for significant changes



\## Example Scoring Logic



When using risk scoring:

```spl

| eval risk\_score=0

| eval risk\_score=if(\[condition1], risk\_score+\[weight1], risk\_score)

| eval risk\_score=if(\[condition2], risk\_score+\[weight2], risk\_score)

| where risk\_score >= \[threshold]

```



Document what each condition detects and why it has that weight.



\## Testing Checklist



Before deploying a new detection rule:

\- \[ ] Tested against known malicious samples

\- \[ ] Tested against normal baseline activity

\- \[ ] Tuning parameters documented

\- \[ ] False positive scenarios identified

\- \[ ] Response playbook created

\- \[ ] Investigation queries validated

\- \[ ] MITRE ATT\&CK mapping verified

\- \[ ] Peer reviewed by another analyst



\## Documentation Standards



\### Comments in SPL

\- Explain complex logic

\- Document regex patterns

\- Note any non-obvious field names

\- Explain mathematical calculations



\### Response Procedures

\- Number steps in logical order

\- Be specific about actions to take

\- Include what to look for

\- Explain why each step matters



\### Investigation Queries

\- Provide actual runnable queries

\- Include brief description of what they show

\- Explain when to use each query

\- Note any prerequisites (permissions, data sources)



\## Version Control



When updating existing rules:

```spl

/\*

CHANGELOG:

v1.2 (YYYY-MM-DD): \[Description of changes]

v1.1 (YYYY-MM-DD): \[Description of changes]  

v1.0 (YYYY-MM-DD): Initial release

\*/

```



\## Additional Resources



\- MITRE ATT\&CK: https://attack.mitre.org/

\- Splunk Search Reference: https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/

\- Sigma Rules Repository: https://github.com/SigmaHQ/sigma

\- Detection Rules: https://github.com/elastic/detection-rules

