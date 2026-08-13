# SOC Detection Lab

## Overview

This project documents a hands-on Security Operations Center lab built to generate, detect, and investigate simulated security activity in a Windows environment.

The goal was to practice the workflow of a SOC analyst by collecting endpoint telemetry, generating controlled adversary activity, searching for relevant events, and documenting the investigation process.

## Tools Used

* Splunk Enterprise
* Sysmon
* Atomic Red Team
* Windows Event Viewer
* PowerShell
* Splunk Universal Forwarder

## Lab Objectives

* Configure Windows telemetry for security monitoring
* Forward security events into Splunk
* Generate simulated attacker activity using Atomic Red Team
* Search and analyze endpoint events
* Identify suspicious process activity
* Practice troubleshooting when expected events do not appear
* Document findings and investigation steps

## Security Techniques Tested

Examples of techniques tested in the lab include:

* PowerShell execution
* Account discovery
* Credential-related activity
* Credential discovery in files

These exercises were performed in a controlled lab environment for defensive security training.

## Investigation Process

The general workflow used during the lab was:

1. Generate controlled security activity.
2. Confirm that endpoint telemetry was being created.
3. Search Splunk and Windows Event Viewer for relevant events.
4. Review Sysmon process creation and other event data.
5. Compare observed activity with the expected technique.
6. Troubleshoot missing telemetry, service configuration, permissions, or forwarding issues.
7. Document results and lessons learned.

## Key Skills Practiced

* SIEM searching and log analysis
* Endpoint telemetry analysis
* Windows security event investigation
* PowerShell troubleshooting
* Security tool configuration
* Detection validation
* Incident investigation methodology
* Technical documentation

## What I Learned

This lab helped me understand how endpoint activity moves from a Windows system into a SIEM and how analysts can use that telemetry during an investigation.

One of the most valuable parts of the project was troubleshooting situations where expected events did not immediately appear. This required checking services, configurations, permissions, forwarding settings, and the underlying Windows logs before continuing the investigation.

The project reinforced that security monitoring is not only about finding alerts. It also requires understanding the data pipeline, validating telemetry, and methodically troubleshooting when information is missing.

## Next Steps

Future improvements to this lab will include:

* Additional Atomic Red Team techniques
* More advanced Splunk searches
* Custom detection queries
* MITRE ATT&CK mapping
* Screenshots and investigation evidence
* Additional endpoint and network telemetry
