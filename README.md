# Alert Triage With Elastic – TryHackMe

![Elastic](https://img.shields.io/badge/SIEM-Elastic-005571?logo=elastic)
![Kibana](https://img.shields.io/badge/Tool-Kibana-E8478B?logo=kibana)
![Windows](https://img.shields.io/badge/Platform-Windows_Server-0078D4?logo=windows)
![SOC](https://img.shields.io/badge/Domain-SOC_Analysis-blue)
![Status](https://img.shields.io/badge/Status-Completed-success)

## Overview

This repository contains study notes, investigation queries, and practical SOC investigation techniques from the **Alert Triage With Elastic** room on TryHackMe.

The challenge focuses on using Elastic SIEM and Kibana to investigate suspicious activity targeting an IIS web server and Windows Server 2019.

The investigation covers web exploitation, web shell activity, suspicious authentication, account creation, privilege modification, PowerShell execution, and archive creation.

## Learning Objectives

- Analyze security alerts using Kibana.
- Investigate IIS web server logs.
- Identify Indicators of Compromise (IoCs).
- Investigate suspicious HTTP requests.
- Analyze Windows Security Event Logs.
- Investigate process execution using Sysmon.
- Detect unauthorized account creation.
- Identify privilege escalation activity.
- Analyze PowerShell Script Block Logging.
- Correlate events across multiple log sources.
- Reconstruct an attack timeline and escalate incidents with evidence.

## Tools and Technologies

| Tool / Technology | Purpose |
|---|---|
| Elastic Stack | Security monitoring and log analysis |
| Kibana | Log visualization and investigation |
| KQL | Searching and filtering security events |
| Sysmon | Windows process and endpoint telemetry |
| Windows Security Logs | Authentication and account activity |
| IIS Logs | Web server activity investigation |
| PowerShell Logging | Script execution monitoring |

## 1. Kibana Environment Setup

Initial configuration:

1. Start the TryHackMe virtual machine.
2. Access the provided Kibana URL.
3. Select the `Alert Triage With Elastic` data view.
4. Set the time range to `Entire data range`.
5. Select the IIS web server index.

Initial KQL query:

```kql
_index:weblogs
```

The investigation uses web server and Windows endpoint logs.

## 2. Web Attack Investigation

### 2.1 ProxyLogon Exploitation

**Alert:** SOC-20250720-0012

**Observed indicators:**

- Source IP: `203.0.113.55`
- Target: `winserv2019.some.corp`
- Endpoint: `proxyLogon.ecp`
- HTTP method: `POST`
- Severity: High

Investigation query:

```kql
_index:weblogs
and client.ip:203.0.113.55
and http.request.method:POST
```

Important fields:

- `client.ip`
- `user.agent`
- `http.request.method`
- `url.path`
- `http.response.status_code`

**Finding:** Automated POST requests targeting the ProxyLogon endpoint indicate potential exploitation activity.

### 2.2 Web Shell Investigation

**Alert:** SOC-20250720-0013

**Observed indicators:**

- Source IP: `203.0.113.55`
- ASPX file: `errorEE.aspx`
- HTTP method: `GET`
- Suspicious parameter: `cmd=`

Investigation query:

```kql
_index:weblogs
and client.ip:203.0.113.55
and http.request.method:GET
and errorEE.aspx
```

Example web shell request:

```text
errorEE.aspx?cmd=id
```

**Finding:** The `cmd=` parameter indicates potential remote command execution through a web shell. The observed commands in the logs provide evidence of compromise.

## 3. Windows Authentication Investigation

### 3.1 Successful Administrator Login

**Alert:** SOC-20250720-0014

Windows Security Event ID `4624` records successful logons.

Investigation query:

```kql
@timestamp >= "2025-07-20T05:11:22"
and winlog.event_id:4624
and host.name:winserv2019.some.corp
and winlog.event_data.TargetUserName:Administrator
```

Important fields:

- `winlog.event_id`
- `host.name`
- `winlog.event_data.TargetUserName`
- `winlog.logon.type`
- `winlog.event_data.IpAddress`

**Finding:** The Administrator account authenticated from the same source IP involved in the earlier web attacks.

### 3.2 Sysmon Process Creation

Sysmon Event ID `1` records process creation.

Investigation query:

```kql
@timestamp >= "2025-07-20T05:11:22"
and winlog.event_id:1
and user.name:Administrator
```

Important fields:

- `user.name`
- `process.parent.name`
- `process.command_line`
- `process.pid`

**Purpose:** Establish process execution context and identify suspicious parent-child relationships.

## 4. Account Creation Investigation

**Alert:** SOC-20250720-0015

Investigate Windows Security logs:

```kql
@timestamp >= "2025-07-20T05:13:10.000"
and winlog.channel:Security
and winlog.task:"User Account Management"
```

Important fields:

- `winlog.event_id`
- `winlog.task`
- `message`
- `winlog.record_id`

Important Windows Security Event IDs:

| Event ID | Description |
|---|---|
| 4624 | Successful logon |
| 4720 | User account created |
| 4732 | Member added to a security-enabled local group |

**Investigation goals:**

- Identify the newly created account.
- Determine who created the account.
- Establish the creation timestamp.
- Record the relevant Windows event details.

## 5. Command Execution and Privilege Modification

**Alert:** SOC-20250720-0016

### 5.1 CMD Investigation

Investigation query:

```kql
@timestamp >= "2025-07-20T05:13:15"
and process.parent.name:cmd.exe
and user.name:Administrator
```

Important fields:

- `process.command_line`
- `process.name`
- `process.parent.name`

Look for commands involving user creation and local security group modification.

### 5.2 Correlation with Event ID 4732

Windows Security Event ID `4732` identifies additions to security-enabled local groups.

Investigation query:

```kql
@timestamp >= "2025-07-20T05:13:15"
and (winlog.event_id:4732 or process.parent.name:cmd.exe)
```

Correlate:

- Sysmon Event ID `1`: Process Creation.
- Windows Security Event ID `4732`: Group Membership Changes.

This correlation helps confirm whether an executed command resulted in unauthorized privilege modification.

## 6. PowerShell Investigation

PowerShell Script Block Logging provides visibility into executed PowerShell commands.

Investigation query:

```kql
@timestamp >= "2025-07-20T05:13:15"
and event.module:powershell
and event.code:4104
```

Important field:

```text
powershell.file.script_block_text
```

Commands identified:

```powershell
whoami
whoami /priv
```

**Relevant Event ID:**

- `4104` – PowerShell Script Block Logging.

These commands are associated with account and privilege discovery.

## 7. Investigating Unalerted Activity – RAR.exe

Not every suspicious action generates a security alert.

The investigation identified the use of `Rar.exe`, a legitimate compression utility.

Investigation query:

```kql
process.name:"Rar.exe"
```

Examine:

- Executing username.
- Process creation timestamp.
- Parent process.
- Command-line arguments.
- Created archive name.
- Files included in the archive.

**Security takeaway:** Legitimate tools can be abused by attackers for staging and compressing data. Always investigate execution context rather than judging an executable by its name alone.

## 8. Attack Timeline

The investigation established the following sequence:

| Time (July 20, 2025) | Activity |
|---|---|
| 04:38:40 | Suspicious POST requests to `proxyLogon.ecp` |
| 04:45:31 | GET requests to `errorEE.aspx` containing `cmd=` |
| 05:11:22 | Administrator successful login |
| 05:11:27 | Sysmon process creation activity |
| 05:13:09 | New account creation alert |
| 05:13:15 | Suspicious CMD execution and privilege modification |
| After 05:13:15 | PowerShell discovery activity |
| Further investigation | RAR.exe archive creation |

## 9. Important Event IDs Reference

| Event ID | Log Source | Description |
|---|---|---|
| 4624 | Windows Security | Successful logon |
| 4720 | Windows Security | User account created |
| 4732 | Windows Security | Member added to local security group |
| 1 | Sysmon | Process creation |
| 4104 | PowerShell | Script Block Logging |

## 10. Important Fields Reference

| Field | Description |
|---|---|
| `client.ip` | Client/source IP address |
| `user.agent` | HTTP user-agent |
| `url.path` | Requested URL and parameters |
| `http.request.method` | HTTP request method |
| `http.response.status_code` | HTTP response status |
| `host.name` | Target hostname |
| `user.name` | Account executing a process |
| `process.name` | Process executable |
| `process.parent.name` | Parent executable |
| `process.command_line` | Full process command line |
| `process.pid` | Process identifier |
| `winlog.event_id` | Windows event identifier |
| `winlog.record_id` | Windows event record identifier |
| `powershell.file.script_block_text` | PowerShell script content |

## 11. Key SOC Analyst Takeaways

1. **Start with alert context:** Review severity, timestamps, source IPs, and target assets.
2. **Investigate web traffic:** Identify suspicious HTTP methods, endpoints, and parameters.
3. **Correlate authentication:** Connect suspicious network activity with Windows logon events.
4. **Analyze process trees:** Investigate parent processes and command-line arguments.
5. **Monitor account changes:** Detect unauthorized users and group membership modifications.
6. **Review PowerShell logs:** Identify attacker discovery and execution commands.
7. **Investigate without alerts:** Search for suspicious activity that automated detection may have missed.
8. **Build an attack timeline:** Combine multiple evidence sources before escalating an incident.

## 12. Repository Structure

```text
Alert-Triage-With-Elastic/
│
├── README.md
│
├── Notes/
│   ├── Web-Attack-Investigation.md
│   ├── Windows-Authentication.md
│   ├── Sysmon-Process-Investigation.md
│   ├── Account-Creation.md
│   ├── Privilege-Modification.md
│   └── PowerShell-Investigation.md
│
└── References/
    └── Event-IDs-Cheat-Sheet.md
```

## Conclusion

This challenge demonstrated how SOC analysts can use Elastic SIEM and Kibana to investigate a multi-stage security incident.

By correlating IIS web logs, Windows Security events, Sysmon process telemetry, and PowerShell logs, an analyst can move beyond individual alerts and reconstruct attacker activity.

The most important lesson is that effective alert triage requires evidence correlation, contextual analysis, and accurate incident escalation.

---

**Platform:** TryHackMe  
**Room:** Alert Triage With Elastic  
**Focus:** SOC Analysis | SIEM | Alert Triage | Threat Detection | Windows Event Logs | Sysmon | Elastic Security
