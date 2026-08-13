# SOC Detection & Threat Hunting Lab

## Overview

This project documents two hands-on SOC analyst workflows performed in a controlled Windows home-lab environment using Splunk, Sysmon, Windows event telemetry, and PowerShell.

The project focused on moving beyond simply generating security events and instead practicing the full analyst workflow:

**Generate → Detect → Investigate → Correlate → Troubleshoot → Disposition**

The two investigations were:

1. **Repeated Windows Authentication Failures**
2. **Encoded PowerShell Account Discovery**

## Lab Environment

* Windows 11
* Splunk Enterprise
* Splunk Universal Forwarder
* Sysmon
* Windows Security Logs
* PowerShell Operational Logs
* PowerShell

---

# Investigation 1 — Failed Logon Detection

## Objective

Generate controlled failed logons, identify Windows Security Event ID `4625`, correlate repeated authentication failures in Splunk, and create a scheduled detection for five or more failures within a ten-minute window.

## Observed Activity

Five incorrect password attempts were generated against a purpose-built local test account.

Analysis identified:

| Field               | Observed Value  |
| ------------------- | --------------- |
| Event ID            | 4625            |
| Target User         | SOC-Lab         |
| Logon Type          | 2 — Interactive |
| Source IP           | 127.0.0.1       |
| Status              | 0xC000006D      |
| Substatus           | 0xC000006A      |
| Detection Threshold | 5 attempts      |

The source address and logon type established that these were **local interactive authentication attempts**, not remote login attempts.

## Detection Logic

```spl
index=* (EventCode=4625 OR EventID=4625) earliest=-10m
| stats count AS failed_attempts earliest(_time) AS first_attempt latest(_time) AS last_attempt BY target_user logon_type source_ip workstation status substatus
| where failed_attempts >= 5
```

The search was saved as a **medium-severity scheduled Splunk alert** named:

`Multiple Failed Login Attempts`

The rule runs every five minutes and triggers when at least one correlated result reaches the threshold.

## Troubleshooting

During testing, newly generated events initially appeared outside the expected Splunk search window.

Investigation identified a clock synchronization mismatch between the Windows endpoint and SIEM timeline.

Correcting Windows time synchronization restored expected event timing.

### Analyst Takeaway

Reliable security investigations depend on accurate timestamps. Even functioning telemetry can produce misleading investigation results when endpoint and SIEM clocks are inconsistent.

---

# Investigation 2 — Encoded PowerShell Threat Hunt

## Objective

Detect an encoded PowerShell process, recover the readable command through PowerShell Script Block Logging, and correlate process telemetry with executed content in Splunk.

## Controlled Technique

A harmless account-discovery command was Base64 encoded and executed using PowerShell's `-EncodedCommand` option.

Original command:

```powershell
Get-LocalUser | Select-Object Name, Enabled
```

The technique simulated an obfuscation pattern that may require investigation in a SOC environment.

## Telemetry Correlation

Two primary event sources were correlated:

| Source                 | Event ID | Evidence                                                                                             |
| ---------------------- | -------: | ---------------------------------------------------------------------------------------------------- |
| Sysmon Operational     |        1 | PowerShell process creation, parent process, user, integrity level, hashes, and encoded command line |
| PowerShell Operational |     4104 | Decoded PowerShell script-block content                                                              |

Sysmon showed **how the process executed**.

Event ID `4104` revealed **what the PowerShell command actually executed**.

Correlating the two provided substantially more context than either event source alone.

## MITRE ATT&CK Mapping

The observed behavior was mapped to:

**T1087.001 — Account Discovery: Local Account**

The presence of encoded PowerShell was treated as a suspicious indicator rather than automatic proof of compromise.

The investigation considered:

* Decoded command content
* User context
* Source host
* Execution time
* Parent-child process relationships
* Authorization context

## Closing the Visibility Gap

PowerShell Script Block Logging was enabled through Windows policy configuration and the PowerShell Operational event channel.

Splunk was then configured to ingest this channel.

This resolved an initial visibility gap where Event ID `4104` existed locally but was not visible in the SIEM.

---

# Analyst Findings

* Five incorrect passwords produced a threshold-based authentication finding.
* Authentication failures were local interactive attempts rather than remote activity.
* Sysmon captured the encoded PowerShell process and execution context.
* Event ID 4104 revealed the decoded PowerShell command.
* Sysmon and PowerShell telemetry were correlated to reconstruct the activity.
* Duplicate Sysmon events with different host labels revealed an ingestion/host-label configuration issue that could inflate production alert counts.
* Detection and telemetry operated as expected after troubleshooting configuration and timing issues.

# Final Disposition

**Classification: Benign Positive**

The activity was intentionally generated in an authorized home-lab environment.

The detection logic successfully identified the activity, and investigation of the supporting telemetry established that the behavior was authorized.

For an unrecognized occurrence in a production environment, the next steps would include validating the user and host, safely recovering script content, reviewing parent-child processes and network activity, and escalating if authorization could not be confirmed.

---

# Evidence

Portfolio screenshots will document:

1. Failed-logon correlation and threshold detection in Splunk
2. Correlated Sysmon Event ID 1 and PowerShell Event ID 4104 telemetry

---

# Skills Demonstrated

* SIEM monitoring
* SPL searching and field extraction
* Windows authentication analysis
* Alert creation
* Detection engineering
* Windows event analysis
* Sysmon telemetry analysis
* PowerShell threat hunting
* Event correlation
* MITRE ATT&CK mapping
* Incident triage
* Evidence-based disposition
* Troubleshooting telemetry gaps
* Technical documentation

---

# Key Takeaway

**A suspicious indicator is not the same as a confirmed security incident.**

This project reinforced the importance of correlating multiple telemetry sources, understanding the context surrounding suspicious activity, validating detection logic, and making an evidence-based analyst disposition.
