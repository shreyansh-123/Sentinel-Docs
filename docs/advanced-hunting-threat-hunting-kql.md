# Advanced Hunting Threat Hunting Queries (KQL)

This document provides Microsoft Defender XDR Advanced Hunting queries written in Kusto Query Language (KQL). Use these hunts to identify suspicious account activity, endpoint behavior, persistence, credential access, and potential data exfiltration.

> Review and tune thresholds, allowlists, and time windows for your environment before operational use.

## Usage

1. Open **Microsoft Defender XDR**.
2. Go to **Hunting** > **Advanced hunting**.
3. Copy a query from this document into the query editor.
4. Adjust variables such as `lookback`, thresholds, and allowlists.
5. Run the query and investigate returned entities.

## Account and Identity Hunting

### Multiple failed sign-ins followed by success

Detects potential password spraying or brute-force attempts where repeated failures are followed by a successful login.

```kql
let lookback = 24h;
let failureThreshold = 10;
AADSignInEventsBeta
| where Timestamp > ago(lookback)
| summarize
    FailedAttempts = countif(ErrorCode != 0),
    SuccessfulAttempts = countif(ErrorCode == 0),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    IPAddresses = make_set(IPAddress, 20),
    Apps = make_set(Application, 20)
    by AccountUpn
| where FailedAttempts >= failureThreshold and SuccessfulAttempts > 0
| order by FailedAttempts desc
```

### Sign-ins from unfamiliar countries or regions

Identifies users authenticating from countries or regions not commonly observed in the previous baseline period.

```kql
let baselineWindow = 14d;
let huntWindow = 24h;
let baseline =
    AADSignInEventsBeta
    | where Timestamp between (ago(baselineWindow) .. ago(huntWindow))
    | summarize KnownLocations = make_set(Country, 100) by AccountUpn;
AADSignInEventsBeta
| where Timestamp > ago(huntWindow)
| join kind=leftouter baseline on AccountUpn
| where isempty(KnownLocations) or Country !in (KnownLocations)
| project Timestamp, AccountUpn, IPAddress, Country, City, Application, ErrorCode, LogonType
| order by Timestamp desc
```

### Impossible travel activity

Finds users signing in from multiple countries within a short period.

```kql
let lookback = 24h;
let travelWindow = 2h;
AADSignInEventsBeta
| where Timestamp > ago(lookback)
| where isnotempty(Country)
| project Timestamp, AccountUpn, IPAddress, Country, City, Application
| sort by AccountUpn asc, Timestamp asc
| serialize
| extend PreviousUser = prev(AccountUpn), PreviousTimestamp = prev(Timestamp), PreviousCountry = prev(Country), PreviousIP = prev(IPAddress)
| where AccountUpn == PreviousUser
| where Country != PreviousCountry and Timestamp - PreviousTimestamp <= travelWindow
| project AccountUpn, PreviousTimestamp, Timestamp, PreviousCountry, Country, PreviousIP, IPAddress, City, Application
| order by Timestamp desc
```

## Endpoint Hunting

### Suspicious PowerShell execution

Detects PowerShell commands commonly associated with obfuscation, download cradles, or in-memory execution.

```kql
let lookback = 7d;
let suspiciousTerms = dynamic([
    "-enc", "-encodedcommand", "iex", "invoke-expression", "downloadstring",
    "frombase64string", "bypass", "hidden", "nop", "-w hidden"
]);
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any (suspiciousTerms)
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId
| order by Timestamp desc
```

### Encoded command execution

Highlights processes using encoded command patterns.

```kql
let lookback = 7d;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where ProcessCommandLine matches regex @"(?i)(-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{20,}"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### LOLBin network activity

Finds living-off-the-land binaries making outbound network connections.

```kql
let lookback = 7d;
let lolbins = dynamic([
    "certutil.exe", "bitsadmin.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe",
    "wmic.exe", "powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe"
]);
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName in~ (lolbins)
| where RemoteUrl != "" or RemoteIPType == "Public"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, Protocol
| order by Timestamp desc
```

## Persistence Hunting

### Suspicious scheduled task creation

Detects scheduled task creation using command-line utilities.

```kql
let lookback = 7d;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has_any ("/create", "-create")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Run key modification

Finds registry changes to common autostart locations.

```kql
let lookback = 7d;
DeviceRegistryEvents
| where Timestamp > ago(lookback)
| where RegistryKey has_any (
    @"\Software\Microsoft\Windows\CurrentVersion\Run",
    @"\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    @"\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
)
| project Timestamp, DeviceName, InitiatingProcessAccountName, RegistryKey, RegistryValueName,
          RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### New service installation

Identifies service creation events.

```kql
let lookback = 7d;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FileName =~ "sc.exe"
| where ProcessCommandLine has " create "
| project Timestamp, DeviceName, InitiatingProcessAccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Credential Access Hunting

### LSASS access by uncommon processes

Detects processes accessing `lsass.exe`, excluding common known Microsoft Defender and Windows components.

```kql
let lookback = 7d;
let allowedProcesses = dynamic([
    "MsMpEng.exe", "MsSense.exe", "SenseIR.exe", "csrss.exe", "wininit.exe", "taskmgr.exe"
]);
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where ProcessCommandLine has_any ("lsass", "comsvcs.dll", "MiniDump", "procdump")
| where InitiatingProcessFileName !in~ (allowedProcesses)
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Credential dumping tool indicators

Searches for known credential dumping tool names and command patterns.

```kql
let lookback = 30d;
let indicators = dynamic([
    "mimikatz", "sekurlsa", "logonpasswords", "lsadump", "dcsync",
    "nanodump", "procdump", "comsvcs.dll", "minidump"
]);
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where ProcessCommandLine has_any (indicators) or FileName has_any (indicators)
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Lateral Movement Hunting

### Remote service execution indicators

Detects command-line patterns associated with remote service creation or execution.

```kql
let lookback = 7d;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where ProcessCommandLine has_any ("\\\\", "psexec", "admin$", "c$", "wmic", "/node:")
| where FileName in~ ("psexec.exe", "paexec.exe", "wmic.exe", "sc.exe", "cmd.exe", "powershell.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### RDP logons from unusual source IPs

Identifies RDP logons where the source IP has not been seen for that account in the baseline period.

```kql
let baselineWindow = 14d;
let huntWindow = 24h;
let baseline =
    DeviceLogonEvents
    | where Timestamp between (ago(baselineWindow) .. ago(huntWindow))
    | where LogonType =~ "RemoteInteractive"
    | summarize KnownRemoteIPs = make_set(RemoteIP, 100) by AccountName;
DeviceLogonEvents
| where Timestamp > ago(huntWindow)
| where LogonType =~ "RemoteInteractive"
| join kind=leftouter baseline on AccountName
| where isempty(KnownRemoteIPs) or RemoteIP !in (KnownRemoteIPs)
| project Timestamp, DeviceName, AccountName, RemoteIP, RemoteDeviceName, ActionType, LogonType
| order by Timestamp desc
```

## Exfiltration Hunting

### Large outbound data transfers

Finds devices with unusually high outbound traffic volume.

```kql
let lookback = 24h;
let outboundThresholdBytes = 500000000;
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where RemoteIPType == "Public"
| summarize TotalOutboundBytes = sum(SentBytes), Connections = count(), RemoteIPs = dcount(RemoteIP)
    by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName
| where TotalOutboundBytes >= outboundThresholdBytes
| order by TotalOutboundBytes desc
```

### Archive creation followed by network activity

Identifies archive utilities followed by outbound network connections from the same device and account.

```kql
let lookback = 24h;
let archiveWindow = 30m;
let archiveProcesses =
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where FileName in~ ("7z.exe", "winrar.exe", "rar.exe", "tar.exe", "powershell.exe")
    | where ProcessCommandLine has_any (".zip", ".7z", ".rar", "Compress-Archive")
    | project ArchiveTime = Timestamp, DeviceName, AccountName = InitiatingProcessAccountName,
              ArchiveProcess = FileName, ArchiveCommandLine = ProcessCommandLine;
archiveProcesses
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp > ago(lookback)
    | where RemoteIPType == "Public"
    | project NetworkTime = Timestamp, DeviceName, AccountName = InitiatingProcessAccountName,
              InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort, SentBytes
) on DeviceName, AccountName
| where NetworkTime between (ArchiveTime .. ArchiveTime + archiveWindow)
| project ArchiveTime, NetworkTime, DeviceName, AccountName, ArchiveProcess, ArchiveCommandLine,
          InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort, SentBytes
| order by NetworkTime desc
```

## Email and Phishing Hunting

### Suspicious email with URL clicks

Correlates delivered email messages with URL click activity.

```kql
let lookback = 7d;
EmailEvents
| where Timestamp > ago(lookback)
| where DeliveryAction in~ ("Delivered", "Junked")
| join kind=inner (
    UrlClickEvents
    | where Timestamp > ago(lookback)
    | project ClickTime = Timestamp, NetworkMessageId, AccountUpn, Url, ActionType
) on NetworkMessageId
| project EmailTime = Timestamp, ClickTime, RecipientEmailAddress, AccountUpn, SenderFromAddress,
          SenderIPv4, Subject, Url, ActionType, ThreatTypes, DetectionMethods
| order by ClickTime desc
```

### Newly observed sender domains with attachments

Finds messages with attachments from domains not seen in the baseline period.

```kql
let baselineWindow = 30d;
let huntWindow = 24h;
let baselineDomains =
    EmailEvents
    | where Timestamp between (ago(baselineWindow) .. ago(huntWindow))
    | summarize by SenderFromDomain;
EmailEvents
| where Timestamp > ago(huntWindow)
| where AttachmentCount > 0
| join kind=leftanti baselineDomains on SenderFromDomain
| project Timestamp, RecipientEmailAddress, SenderFromAddress, SenderFromDomain, SenderIPv4,
          Subject, AttachmentCount, ThreatTypes, DetectionMethods, DeliveryAction
| order by Timestamp desc
```

## Cloud App and OAuth Hunting

### Suspicious OAuth application consent activity

Detects OAuth app consent events with high-risk permissions.

```kql
let lookback = 14d;
let riskyPermissions = dynamic(["Mail.Read", "Mail.ReadWrite", "Files.Read.All", "Files.ReadWrite.All", "offline_access", "User.ReadWrite.All"]);
CloudAppEvents
| where Timestamp > ago(lookback)
| where ActionType has_any ("Consent", "Add service principal", "Add app role assignment")
| where RawEventData has_any (riskyPermissions)
| project Timestamp, AccountDisplayName, AccountId, Application, ActionType, IPAddress, RawEventData
| order by Timestamp desc
```

### Unusual cloud app download volume

Finds accounts with high download activity from cloud applications.

```kql
let lookback = 24h;
let downloadThreshold = 100;
CloudAppEvents
| where Timestamp > ago(lookback)
| where ActionType has_any ("Download", "FileDownloaded")
| summarize Downloads = count(), Apps = make_set(Application, 20), IPAddresses = make_set(IPAddress, 20)
    by AccountDisplayName, AccountId
| where Downloads >= downloadThreshold
| order by Downloads desc
```

## Investigation Enrichment

### Timeline for a user

Replace `user@example.com` with the account under investigation.

```kql
let targetUser = "user@example.com";
let lookback = 7d;
union isfuzzy=true
(
    AADSignInEventsBeta
    | where Timestamp > ago(lookback)
    | where AccountUpn =~ targetUser
    | project Timestamp, Source = "AADSignInEventsBeta", DeviceName = "", Account = AccountUpn,
              Action = tostring(ErrorCode), Detail = strcat(Application, " from ", IPAddress)
),
(
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where InitiatingProcessAccountUpn =~ targetUser or AccountUpn =~ targetUser
    | project Timestamp, Source = "DeviceProcessEvents", DeviceName, Account = InitiatingProcessAccountUpn,
              Action = FileName, Detail = ProcessCommandLine
),
(
    DeviceNetworkEvents
    | where Timestamp > ago(lookback)
    | where InitiatingProcessAccountUpn =~ targetUser
    | project Timestamp, Source = "DeviceNetworkEvents", DeviceName, Account = InitiatingProcessAccountUpn,
              Action = InitiatingProcessFileName, Detail = strcat(RemoteUrl, " ", RemoteIP, ":", RemotePort)
)
| order by Timestamp desc
```

### Timeline for a device

Replace `HOSTNAME` with the device under investigation.

```kql
let targetDevice = "HOSTNAME";
let lookback = 7d;
union isfuzzy=true
(
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where DeviceName =~ targetDevice
    | project Timestamp, Source = "DeviceProcessEvents", DeviceName, Account = InitiatingProcessAccountName,
              Action = FileName, Detail = ProcessCommandLine
),
(
    DeviceNetworkEvents
    | where Timestamp > ago(lookback)
    | where DeviceName =~ targetDevice
    | project Timestamp, Source = "DeviceNetworkEvents", DeviceName, Account = InitiatingProcessAccountName,
              Action = InitiatingProcessFileName, Detail = strcat(RemoteUrl, " ", RemoteIP, ":", RemotePort)
),
(
    DeviceRegistryEvents
    | where Timestamp > ago(lookback)
    | where DeviceName =~ targetDevice
    | project Timestamp, Source = "DeviceRegistryEvents", DeviceName, Account = InitiatingProcessAccountName,
              Action = RegistryValueName, Detail = strcat(RegistryKey, " = ", RegistryValueData)
)
| order by Timestamp desc
```

## Tuning Guidance

- Add known administrative accounts, approved tools, and expected service activity to allowlists.
- Tune thresholds based on baseline behavior for each business unit or device group.
- Investigate correlated signals across identity, endpoint, email, and cloud app telemetry.
- Prefer high-confidence hunts that combine multiple weak signals instead of relying on one noisy indicator.
- Document false positives and update queries regularly.
