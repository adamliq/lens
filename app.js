const REQUIRED_FIELDS = [{"id": "log_received_time", "category": "Log received date/time", "names": "@timestamp, eventtime, _time", "example": "2026-07-08T04:15:22Z", "validation": "Must be present and normalised to UTC", "notes": "Represents when the SIEM received, indexed, or normalised the event time.", "weight": 12}, {"id": "log_creation_time", "category": "Log creation date/time", "names": "event.created, created_time, device_time", "example": "2026-07-08T04:15:18Z", "validation": "Must be present where the source provides it", "notes": "Represents when the event was created by the originating system.", "weight": 9}, {"id": "system_type", "category": "System type", "names": "device_type, product, vendor, sourcetype", "example": "firewall, Windows Security, FortiGate", "validation": "Must identify the source technology or product", "notes": "Example: firewall, endpoint, operating system, identity provider, vendor/product name.", "weight": 8}, {"id": "source_address", "category": "Source address", "names": "src_ip, src_host, source.ip, host, host.name", "example": "10.10.25.14, workstation-01", "validation": "Must identify the source system where applicable", "notes": "May be IP address, hostname, device name, or workload identity.", "weight": 10}, {"id": "device_asset_identifier", "category": "Device / asset identifier", "names": "mac_address, device_id, asset_id, host.id, agent.id, endpoint_id, serial_number, instance_id, computer_id", "example": "00:1A:2B:3C:4D:5E, i-0abc123def456", "validation": "Required where the source provides a stable identifier", "notes": "Used to correlate activity to a specific device or asset, especially where IP address or hostname may change.", "weight": 9}, {"id": "user_identity", "category": "User identity", "names": "user, usrName, user.name, src_user", "example": "jsmith, DOMAIN\\jsmith", "validation": "Must be present for authenticated activity", "notes": "Mark as Partial where only populated for authenticated or user-linked events.", "weight": 12}, {"id": "severity_priority", "category": "Severity / priority", "names": "level, severity, priority, risk", "example": "high, critical, 5", "validation": "Must indicate event importance where supported", "notes": "Confirm whether values are vendor-specific or normalised.", "weight": 6}, {"id": "action_message", "category": "Action / message", "names": "event.action, action, event.type, event_type, msg, message, status_code", "example": "user_login, connection_blocked, 4625", "validation": "Must describe what occurred", "notes": "Should include event type, action taken, message, or status code to clarify the activity.", "weight": 13}, {"id": "command_process", "category": "Command / process executed", "names": "command, command_line, process.command_line, process.name, process.executable, cmdline, process.args, script_block_text", "example": "powershell.exe -enc ..., net user test /add", "validation": "Required where execution or administrative action is recorded", "notes": "Important for endpoint, server, EDR, PowerShell, Linux auditd, cloud admin, and privileged activity logs.", "weight": 10}, {"id": "impacted_object", "category": "Impacted object", "names": "object, file, account, target, dest, destination, resource", "example": "C:\\Temp\\payload.exe, admin_user, server-02", "validation": "Required where the event involves a target object", "notes": "May relate to file, account, process, configuration, resource, destination, or access events.", "weight": 8}, {"id": "result_activity", "category": "Result of activity", "names": "status, outcome, result, event.outcome, status_code, response_code", "example": "success, failure, 403, blocked", "validation": "Must indicate success, failure, allowed, blocked, denied, error, or equivalent", "notes": "Status codes should be mapped or interpreted where possible.", "weight": 12}, {"id": "session_transaction_id", "category": "Session / transaction ID", "names": "session_id, transaction_id, trace_id, correlation_id, request_id, event.id", "example": "abc123-session-789, req-45f9a1", "validation": "Required where session, transaction, request, or correlation tracking is supported", "notes": "Links related events across a user session, network connection, API request, or investigation timeline.", "weight": 7}, {"id": "unique_event_id", "category": "Unique event identifier", "names": "event.id, event_id, id, record_id, uid, uuid, guid, message_id", "example": "550e8400-e29b-41d4-a716-446655440000", "validation": "Required where the source provides a unique identifier for each event", "notes": "Assists deduplication, event correlation, investigation traceability, and cross-system referencing.", "weight": 7}];

const TIME_FORMATS = [
  [
        "ISO 8601 / RFC 3339 - Basic UTC (Zulu)",
        "2026-07-09T14:30:45Z",
        "%Y-%m-%dT%H:%M:%SZ",
        "From spreadsheet: Basic UTC (Zulu). Pattern/notes: %Y-%m-%dT%H:%M:%SZ.",
        "Timezone or UTC context is present, but confirm precision and UTC normalisation."
  ],
  [
        "ISO 8601 / RFC 3339 - With numeric offset",
        "2026-07-09T14:30:45+00:00",
        "%Y-%m-%dT%H:%M:%S%:z",
        "From spreadsheet: With numeric offset. Pattern/notes: %Y-%m-%dT%H:%M:%S%z (%:z gives colon, GNU).",
        "Timezone context is present; confirm parser support and UTC normalisation. Abbreviated zone names can be ambiguous outside UTC/GMT."
  ],
  [
        "ISO 8601 / RFC 3339 - Milliseconds",
        "2026-07-09T14:30:45.123Z",
        "%Y-%m-%dT%H:%M:%S.%QZ",
        "From spreadsheet: Milliseconds. Pattern/notes: framework-formatted; strftime has no ms field.",
        "Good candidate when mapped to event occurrence time and normalised to UTC during ingestion."
  ],
  [
        "ISO 8601 / RFC 3339 - Microseconds",
        "2026-07-09T14:30:45.123456Z",
        "%Y-%m-%dT%H:%M:%S.%fZ (Python %f = 6 digits)",
        "From spreadsheet: Microseconds. Pattern/notes: %Y-%m-%dT%H:%M:%S.%fZ (Python %f = 6 digits).",
        "Good candidate when mapped to event occurrence time and normalised to UTC during ingestion."
  ],
  [
        "ISO 8601 / RFC 3339 - Nanoseconds",
        "2026-07-09T14:30:45.123456789Z",
        "%Y-%m-%dT%H:%M:%S.%QZ",
        "From spreadsheet: Nanoseconds. Pattern/notes: framework-specific (e.g. Go RFC3339Nano).",
        "Good candidate when mapped to event occurrence time and normalised to UTC during ingestion."
  ],
  [
        "ISO 8601 / RFC 3339 - Space separator (RFC 3339 section5.6)",
        "2026-07-09 14:30:45Z",
        "%Y-%m-%d %H:%M:%SZ",
        "From spreadsheet: Space separator (RFC 3339 section5.6). Pattern/notes: %Y-%m-%d %H:%M:%SZ.",
        "Timezone or UTC context is present, but confirm precision and UTC normalisation."
  ],
  [
        "ISO 8601 / RFC 3339 - Comma decimal sign",
        "2026-07-09T14:30:45,123Z",
        "%Y-%m-%dT%H:%M:%S,%QZ",
        "From spreadsheet: Comma decimal sign. Pattern/notes: ISO 8601 permits ',' as the decimal sign.",
        "Good candidate when mapped to event occurrence time and normalised to UTC during ingestion."
  ],
  [
        "ISO 8601 / RFC 3339 - Basic / compact (no delimiters)",
        "20260709T143045Z",
        "%Y%m%dT%H%M%SZ",
        "From spreadsheet: Basic / compact (no delimiters). Pattern/notes: %Y%m%dT%H%M%SZ.",
        "Timezone or UTC context is present, but confirm precision and UTC normalisation."
  ],
  [
        "ISO 8601 / RFC 3339 - Date only",
        "2026-07-09",
        "%Y-%m-%d",
        "From spreadsheet: Date only. Pattern/notes: %Y-%m-%d.",
        "Not suitable as the primary event timestamp unless combined with a reliable event date/time source."
  ],
  [
        "ISO 8601 / RFC 3339 - Time only",
        "14:30:45.123",
        "%H:%M:%S.%Q",
        "From spreadsheet: Time only. Pattern/notes: %H:%M:%S (+ optional fraction).",
        "Not suitable as the primary event timestamp unless combined with a reliable event date/time source."
  ],
  [
        "ISO 8601 / RFC 3339 - Week date",
        "2026-W28-4",
        "%G-W%V-%u",
        "From spreadsheet: Week date. Pattern/notes: %G-W%V-%u.",
        "Not suitable as the primary event timestamp unless combined with a reliable event date/time source."
  ],
  [
        "ISO 8601 / RFC 3339 - Ordinal (day-of-year) date",
        "2026-190",
        "%Y-%j",
        "From spreadsheet: Ordinal (day-of-year) date. Pattern/notes: %Y-%j.",
        "Not suitable as the primary event timestamp unless combined with a reliable event date/time source."
  ],
  [
        "Internet message / RFC - RFC 5322 / 2822 (email)",
        "Thu, 09 Jul 2026 14:30:45 +0000",
        "%a, %d %b %Y %H:%M:%S %z",
        "From spreadsheet: RFC 5322 / 2822 (email). Pattern/notes: %a, %d %b %Y %H:%M:%S %z.",
        "Timezone context is present; confirm parser support and UTC normalisation. Abbreviated zone names can be ambiguous outside UTC/GMT."
  ],
  [
        "Internet message / RFC - RFC 1123 (HTTP date)",
        "Thu, 09 Jul 2026 14:30:45 GMT",
        "%a, %d %b %Y %H:%M:%S GMT",
        "From spreadsheet: RFC 1123 (HTTP date). Pattern/notes: %a, %d %b %Y %H:%M:%S GMT.",
        "Timezone or UTC context is present, but confirm precision and UTC normalisation."
  ],
  [
        "Internet message / RFC - RFC 822 (2-digit year)",
        "Thu, 09 Jul 26 14:30:45 +0000",
        "%a, %d %b %y %H:%M:%S %z",
        "From spreadsheet: RFC 822 (2-digit year). Pattern/notes: %a, %d %b %y %H:%M:%S %z.",
        "Timezone context is present; confirm parser support and UTC normalisation. Abbreviated zone names can be ambiguous outside UTC/GMT."
  ],
  [
        "Internet message / RFC - RFC 850 (obsolete HTTP)",
        "Thursday, 09-Jul-26 14:30:45 GMT",
        "%A, %d-%b-%y %H:%M:%S GMT",
        "From spreadsheet: RFC 850 (obsolete HTTP). Pattern/notes: %A, %d-%b-%y %H:%M:%S GMT.",
        "Timezone or UTC context is present, but confirm precision and UTC normalisation."
  ],
  [
        "Internet message / RFC - ANSI C asctime()",
        "Thu Jul 9 14:30:45 2026",
        "%a %b %e %H:%M:%S %Y",
        "From spreadsheet: ANSI C asctime(). Pattern/notes: %a %b %e %H:%M:%S %Y.",
        "Timezone or UTC context is present, but confirm precision and UTC normalisation."
  ],
  [
        "Web server & proxy - Apache Common Log Format",
        "09/Jul/2026:14:30:45 +0000",
        "%d/%b/%Y:%H:%M:%S %z",
        "From spreadsheet: Apache Common Log Format. Pattern/notes: %d/%b/%Y:%H:%M:%S %z.",
        "Timezone context is present; confirm parser support and UTC normalisation. Abbreviated zone names can be ambiguous outside UTC/GMT."
  ],
  [
        "Web server & proxy - Apache error log",
        "[Thu Jul 09 14:30:45.123456 2026]",
        "[%a %b %d %H:%M:%S.%Q %Y]",
        "From spreadsheet: Apache error log. Pattern/notes: bracketed, microseconds.",
        "Sub-second precision is present, but source timezone must be documented or supplied separately."
  ],
  [
        "Web server & proxy - Nginx access (default)",
        "09/Jul/2026:14:30:45 +0000",
        "%d/%b/%Y:%H:%M:%S %z",
        "From spreadsheet: Nginx access (default). Pattern/notes: same as Common Log Format.",
        "Timezone or UTC context is present, but confirm precision and UTC normalisation."
  ],
  [
        "Web server & proxy - Nginx error log",
        "2026/07/09 14:30:45",
        "%Y/%m/%d %H:%M:%S",
        "From spreadsheet: Nginx error log. Pattern/notes: %Y/%m/%d %H:%M:%S.",
        "Seconds-only or timezone-less format; document source timezone and parsing assumptions."
  ],
  [
        "Web server & proxy - IIS W3C Extended",
        "2026-07-09 14:30:45",
        "%Y-%m-%d %H:%M:%S",
        "From spreadsheet: IIS W3C Extended. Pattern/notes: date & time in two separate fields.",
        "Seconds-only or timezone-less format; document source timezone and parsing assumptions."
  ],
  [
        "Web server & proxy - HAProxy",
        "09/Jul/2026:14:30:45.123",
        "%d/%b/%Y:%H:%M:%S.%Q",
        "From spreadsheet: HAProxy. Pattern/notes: Common Log Format + milliseconds.",
        "Sub-second precision is present, but source timezone must be documented or supplied separately."
  ],
  [
        "Web server & proxy - Traefik / common JSON",
        "2026-07-09T14:30:45Z",
        "RFC 3339",
        "From spreadsheet: Traefik / common JSON. Pattern/notes: RFC 3339.",
        "Timezone or UTC context is present, but confirm precision and UTC normalisation."
  ],
  [
        "Syslog & system - RFC 3164 (BSD syslog)",
        "Jul 9 14:30:45",
        "%b %e %H:%M:%S",
        "From spreadsheet: RFC 3164 (BSD syslog). Pattern/notes: %b %e %H:%M:%S (no year).",
        "Timezone or UTC context is present, but confirm precision and UTC normalisation."
  ],
  [
        "Syslog & system - RFC 5424 (modern syslog)",
        "2026-07-09T14:30:45.123456Z",
        "%Y-%m-%dT%H:%M:%S.%QZ",
        "From spreadsheet: RFC 5424 (modern syslog). Pattern/notes: full RFC 3339.",
        "Good candidate when mapped to event occurrence time and normalised to UTC during ingestion."
  ],
  [
        "Syslog & system - systemd journal (short)",
        "Jul 09 14:30:45",
        "%b %d %H:%M:%S",
        "From spreadsheet: systemd journal (short). Pattern/notes: %b %d %H:%M:%S.",
        "Seconds-only or timezone-less format; document source timezone and parsing assumptions."
  ],
  [
        "Syslog & system - systemd (short-iso)",
        "2026-07-09T14:30:45+0000",
        "%Y-%m-%dT%H:%M:%S%z",
        "From spreadsheet: systemd (short-iso). Pattern/notes: ISO 8601.",
        "Timezone or UTC context is present, but confirm precision and UTC normalisation."
  ],
  [
        "Syslog & system - systemd (short-precise)",
        "Jul 09 14:30:45.123456",
        "%b %d %H:%M:%S.%Q",
        "From spreadsheet: systemd (short-precise). Pattern/notes: microseconds.",
        "Sub-second precision is present, but source timezone must be documented or supplied separately."
  ],
  [
        "Syslog & system - dmesg (kernel, uptime)",
        "[ 1234.567890]",
        "Custom uptime conversion required",
        "From spreadsheet: dmesg (kernel, uptime). Pattern/notes: seconds since boot, not wall clock.",
        "Not suitable as the primary event timestamp unless combined with a reliable event date/time source."
  ],
  [
        "Syslog & system - Windows Event Log",
        "7/9/2026 2:30:45 PM",
        "%m/%d/%Y %I:%M:%S %p",
        "From spreadsheet: Windows Event Log. Pattern/notes: locale-dependent.",
        "Parseable only when locale, timezone, and day/month ordering are documented and tested."
  ],
  [
        "Unix epoch - Seconds",
        "1783607445",
        "%s",
        "From spreadsheet: Seconds. Pattern/notes: seconds since 1970-01-01 UTC.",
        "Timezone or UTC context is present, but confirm precision and UTC normalisation."
  ],
  [
        "Unix epoch - Milliseconds",
        "1783607445123",
        "%s%Q",
        "From spreadsheet: Milliseconds. Pattern/notes: ms since Unix epoch.",
        "Good candidate when mapped to event occurrence time and normalised to UTC during ingestion."
  ],
  [
        "Unix epoch - Microseconds",
        "1783607445123456",
        "Custom epoch microsecond conversion",
        "From spreadsheet: Microseconds. Pattern/notes: microseconds since Unix epoch.",
        "Good candidate when mapped to event occurrence time and normalised to UTC during ingestion."
  ],
  [
        "Unix epoch - Nanoseconds",
        "1783607445123456000",
        "ns since Unix epoch (micros-precision instant)",
        "From spreadsheet: Nanoseconds. Pattern/notes: ns since Unix epoch (micros-precision instant).",
        "Good candidate when mapped to event occurrence time and normalised to UTC during ingestion."
  ],
  [
        "Unix epoch - Float seconds",
        "1783607445.123",
        "%s.%Q",
        "From spreadsheet: Float seconds. Pattern/notes: seconds.fraction.",
        "Good candidate when mapped to event occurrence time and normalised to UTC during ingestion."
  ],
  [
        "Unix epoch - Windows FILETIME",
        "134280810451234560",
        "Custom conversion required",
        "From spreadsheet: Windows FILETIME. Pattern/notes: 100-ns ticks since 1601-01-01 UTC.",
        "Requires conversion before normal SIEM event-time parsing; confirm UTC mapping after conversion."
  ],
  [
        "Unix epoch - .NET DateTime.Ticks",
        "639192042451234560",
        "Custom .NET ticks conversion",
        "From spreadsheet: .NET DateTime.Ticks. Pattern/notes: 100-ns ticks since 0001-01-01.",
        "Requires conversion before normal SIEM event-time parsing; confirm UTC mapping after conversion."
  ],
  [
        "Database - MySQL DATETIME",
        "2026-07-09 14:30:45",
        "%Y-%m-%d %H:%M:%S",
        "From spreadsheet: MySQL DATETIME. Pattern/notes: second precision.",
        "Seconds-only or timezone-less format; document source timezone and parsing assumptions."
  ],
  [
        "Database - MySQL DATETIME(6)",
        "2026-07-09 14:30:45.123456",
        "%Y-%m-%d %H:%M:%S.%Q",
        "From spreadsheet: MySQL DATETIME(6). Pattern/notes: microsecond precision.",
        "Sub-second precision is present, but source timezone must be documented or supplied separately."
  ],
  [
        "Database - PostgreSQL timestamptz",
        "2026-07-09 14:30:45.123456+00",
        "micros + offset",
        "From spreadsheet: PostgreSQL timestamptz. Pattern/notes: micros + offset.",
        "Good candidate when mapped to event occurrence time and normalised to UTC during ingestion."
  ],
  [
        "Database - SQL Server datetime2",
        "2026-07-09 14:30:45.1234567",
        "%Y-%m-%d %H:%M:%S.%Q",
        "From spreadsheet: SQL Server datetime2. Pattern/notes: 100-ns precision.",
        "Sub-second precision is present, but source timezone must be documented or supplied separately."
  ],
  [
        "Database - Oracle TIMESTAMP",
        "09-JUL-26 02.30.45.123456 PM",
        "%d-%b-%y %I.%M.%S.%Q %p",
        "From spreadsheet: Oracle TIMESTAMP. Pattern/notes: default NLS format.",
        "Sub-second precision is present, but source timezone must be documented or supplied separately."
  ],
  [
        "Database - SQLite (text)",
        "2026-07-09 14:30:45",
        "%Y-%m-%d %H:%M:%S",
        "From spreadsheet: SQLite (text). Pattern/notes: stored as ISO string.",
        "Seconds-only or timezone-less format; document source timezone and parsing assumptions."
  ],
  [
        "Database - MongoDB ISODate",
        "2026-07-09T14:30:45.123Z",
        "%Y-%m-%dT%H:%M:%S.%QZ",
        "From spreadsheet: MongoDB ISODate. Pattern/notes: BSON millisecond.",
        "Good candidate when mapped to event occurrence time and normalised to UTC during ingestion."
  ],
  [
        "Language / framework - Python logging default",
        "2026-07-09 14:30:45,123",
        "%Y-%m-%d %H:%M:%S,%Q",
        "From spreadsheet: Python logging default. Pattern/notes: comma before ms.",
        "Sub-second precision is present, but source timezone must be documented or supplied separately."
  ],
  [
        "Language / framework - Python asctime()",
        "Thu Jul 9 14:30:45 2026",
        "%a %b %e %H:%M:%S %Y",
        "From spreadsheet: Python asctime(). Pattern/notes: %a %b %e %H:%M:%S %Y.",
        "Seconds-only or timezone-less format; document source timezone and parsing assumptions."
  ],
  [
        "Language / framework - Java Log4j / Logback default",
        "2026-07-09 14:30:45,123",
        "%Y-%m-%d %H:%M:%S,%Q",
        "From spreadsheet: Java Log4j / Logback default. Pattern/notes: comma before ms.",
        "Sub-second precision is present, but source timezone must be documented or supplied separately."
  ],
  [
        "Language / framework - Java Date.toString()",
        "Thu Jul 09 14:30:45 UTC 2026",
        "%a %b %d %H:%M:%S %Z %Y",
        "From spreadsheet: Java Date.toString(). Pattern/notes: includes zone name.",
        "Timezone or UTC context is present, but confirm precision and UTC normalisation."
  ],
  [
        "Language / framework - Go time.String()",
        "2026-07-09 14:30:45.123456789 +0000 UTC",
        "%Y-%m-%d %H:%M:%S.%Q %z %Z",
        "From spreadsheet: Go time.String(). Pattern/notes: default String().",
        "Timezone context is present; confirm parser support and UTC normalisation. Abbreviated zone names can be ambiguous outside UTC/GMT."
  ],
  [
        "Language / framework - Go RFC3339Nano",
        "2026-07-09T14:30:45.123456789Z",
        "%Y-%m-%dT%H:%M:%S.%QZ",
        "From spreadsheet: Go RFC3339Nano. Pattern/notes: layout constant.",
        "Good candidate when mapped to event occurrence time and normalised to UTC during ingestion."
  ],
  [
        "Language / framework - JavaScript toISOString()",
        "2026-07-09T14:30:45.123Z",
        "%Y-%m-%dT%H:%M:%S.%QZ",
        "From spreadsheet: JavaScript toISOString(). Pattern/notes: always UTC, ms.",
        "Good candidate when mapped to event occurrence time and normalised to UTC during ingestion."
  ],
  [
        "Language / framework - JavaScript toUTCString()",
        "Thu, 09 Jul 2026 14:30:45 GMT",
        "%a, %d %b %Y %H:%M:%S GMT",
        "From spreadsheet: JavaScript toUTCString(). Pattern/notes: RFC 1123 style.",
        "Timezone or UTC context is present, but confirm precision and UTC normalisation."
  ],
  [
        "Language / framework - Rust chrono RFC 3339",
        "2026-07-09T14:30:45.123456789+00:00",
        "%Y-%m-%dT%H:%M:%S.%Q%:z",
        "From spreadsheet: Rust chrono RFC 3339. Pattern/notes: to_rfc3339().",
        "Good candidate when mapped to event occurrence time and normalised to UTC during ingestion."
  ],
  [
        "Language / framework - Ruby Time#to_s",
        "2026-07-09 14:30:45 +0000",
        "%Y-%m-%d %H:%M:%S %z",
        "From spreadsheet: Ruby Time#to_s. Pattern/notes: default to_s.",
        "Timezone or UTC context is present, but confirm precision and UTC normalisation."
  ],
  [
        "Language / framework - Rails log tag",
        "2026-07-09T14:30:45.123456Z",
        "%Y-%m-%dT%H:%M:%S.%QZ",
        "From spreadsheet: Rails log tag. Pattern/notes: tagged logger.",
        "Good candidate when mapped to event occurrence time and normalised to UTC during ingestion."
  ],
  [
        "Language / framework - .NET \"o\" round-trip",
        "2026-07-09T14:30:45.1234560Z",
        "%Y-%m-%dT%H:%M:%S.%QZ",
        "From spreadsheet: .NET \"o\" round-trip. Pattern/notes: round-trip specifier.",
        "Good candidate when mapped to event occurrence time and normalised to UTC during ingestion."
  ],
  [
        "Human-readable / locale - US 12-hour",
        "07/09/2026 02:30:45 PM",
        "%m/%d/%Y %I:%M:%S %p",
        "From spreadsheet: US 12-hour. Pattern/notes: %m/%d/%Y %I:%M:%S %p.",
        "Parseable only when locale, timezone, and day/month ordering are documented and tested."
  ],
  [
        "Human-readable / locale - US medium",
        "Jul 9, 2026 2:30:45 PM",
        "%b %-d, %Y %-I:%M:%S %p",
        "From spreadsheet: US medium. Pattern/notes: %b %-d, %Y %-I:%M:%S %p.",
        "Parseable only when locale, timezone, and day/month ordering are documented and tested."
  ],
  [
        "Human-readable / locale - US long",
        "Thursday, July 9, 2026 at 2:30:45 PM",
        "%A, %B %-d, %Y at %-I:%M:%S %p",
        "From spreadsheet: US long. Pattern/notes: %A, %B %-d, %Y at %-I:%M:%S %p.",
        "Parseable only when locale, timezone, and day/month ordering are documented and tested."
  ],
  [
        "Human-readable / locale - European (DMY)",
        "09/07/2026 14:30:45",
        "%d/%m/%Y %H:%M:%S",
        "From spreadsheet: European (DMY). Pattern/notes: %d/%m/%Y %H:%M:%S.",
        "Parseable only when locale, timezone, and day/month ordering are documented and tested."
  ],
  [
        "Human-readable / locale - German (dotted)",
        "09.07.2026 14:30:45",
        "%d.%m.%Y %H:%M:%S",
        "From spreadsheet: German (dotted). Pattern/notes: %d.%m.%Y %H:%M:%S.",
        "Parseable only when locale, timezone, and day/month ordering are documented and tested."
  ],
  [
        "Human-readable / locale - RFC-ish readable",
        "Thu 09 Jul 2026 14:30:45",
        "%a %d %b %Y %H:%M:%S",
        "From spreadsheet: RFC-ish readable. Pattern/notes: %a %d %b %Y %H:%M:%S.",
        "Parseable only when locale, timezone, and day/month ordering are documented and tested."
  ],
  [
        "Compact / sortable - Compact timestamp",
        "20260709143045",
        "%Y%m%d%H%M%S",
        "From spreadsheet: Compact timestamp. Pattern/notes: %Y%m%d%H%M%S.",
        "Seconds-only or timezone-less format; document source timezone and parsing assumptions."
  ],
  [
        "Compact / sortable - Compact + millis",
        "20260709143045123",
        "%Y%m%d%H%M%S + ms",
        "From spreadsheet: Compact + millis. Pattern/notes: %Y%m%d%H%M%S + ms.",
        "Seconds-only or timezone-less format; document source timezone and parsing assumptions."
  ],
  [
        "Compact / sortable - Date-only compact",
        "20260709",
        "%Y%m%d",
        "From spreadsheet: Date-only compact. Pattern/notes: %Y%m%d.",
        "Seconds-only or timezone-less format; document source timezone and parsing assumptions."
  ],
  [
        "Compact / sortable - Reverse (log-file suffix)",
        "2026-07-09_14-30-45",
        "%Y-%m-%d_%H-%M-%S",
        "From spreadsheet: Reverse (log-file suffix). Pattern/notes: %Y-%m-%d_%H-%M-%S.",
        "Seconds-only or timezone-less format; document source timezone and parsing assumptions."
  ],
  [
        "Compact / sortable - Julian-style (YYDDD)",
        "26190",
        "%y%j",
        "From spreadsheet: Julian-style (YYDDD). Pattern/notes: %y%j.",
        "Not suitable as the primary event timestamp unless combined with a reliable event date/time source."
  ],
  [
        "ISO 8601-style (non-standard) - Space sep + zone in parens",
        "2026-07-09 14:30:45 (UTC)",
        "%Y-%m-%d %H:%M:%S (%Z) - not RFC 3339; zone is an abbreviation, e.g. (AEST)",
        "From spreadsheet: Space sep + zone in parens. Pattern/notes: %Y-%m-%d %H:%M:%S (%Z) - not RFC 3339; zone is an abbreviation, e.g. (AEST).",
        "Timezone context is present; confirm parser support and UTC normalisation. Abbreviated zone names can be ambiguous outside UTC/GMT."
  ],
  [
        "ISO 8601-style (non-standard) - Space sep + bare zone name",
        "2026-07-09 14:30:45 UTC",
        "%Y-%m-%d %H:%M:%S %Z - e.g. ...45 AEST; abbreviations are region-ambiguous",
        "From spreadsheet: Space sep + bare zone name. Pattern/notes: %Y-%m-%d %H:%M:%S %Z - e.g. ...45 AEST; abbreviations are region-ambiguous.",
        "Timezone context is present; confirm parser support and UTC normalisation. Abbreviated zone names can be ambiguous outside UTC/GMT."
  ],
  [
        "ISO 8601-style (non-standard) - Space sep + zone in brackets",
        "2026-07-09 14:30:45 [UTC]",
        "%Y-%m-%d %H:%M:%S [%Z]",
        "From spreadsheet: Space sep + zone in brackets. Pattern/notes: %Y-%m-%d %H:%M:%S [%Z] - non-standard bracketed zone.",
        "Timezone context is present; confirm parser support and UTC normalisation. Abbreviated zone names can be ambiguous outside UTC/GMT."
  ],
  [
        "ISO 8601-style (non-standard) - Space sep + ms + zone in parens",
        "2026-07-09 14:30:45.123 (UTC)",
        "%Y-%m-%d %H:%M:%S.%3N (%Z) - %3N=ms, %6N=micros, %9N=ns",
        "From spreadsheet: Space sep + ms + zone in parens. Pattern/notes: %Y-%m-%d %H:%M:%S.%3N (%Z) - %3N=ms, %6N=micros, %9N=ns.",
        "Timezone context is present; confirm parser support and UTC normalisation. Abbreviated zone names can be ambiguous outside UTC/GMT."
  ],
  [
        "ISO 8601-style (non-standard) - Space sep + offset in parens",
        "2026-07-09 14:30:45 (+00:00)",
        "%Y-%m-%d %H:%M:%S (%:z)",
        "From spreadsheet: Space sep + offset in parens. Pattern/notes: %Y-%m-%d %H:%M:%S (%z) - drop the parens \u2192 RFC 3339 (space form).",
        "Timezone context is present; confirm parser support and UTC normalisation. Abbreviated zone names can be ambiguous outside UTC/GMT."
  ],
  [
        "ISO 8601 (Extended) - Offset with milliseconds",
        "2026-07-09T07:20:00.123+10:00",
        "%Y-%m-%dT%H:%M:%S.%Q%:z",
        "Existing scorer format: modern API/cloud timestamp with explicit UTC offset.",
        "Preferred when the offset is parsed and normalised to UTC; has millisecond precision."
  ],
  [
        "ISO 8601 (Basic / Compact) - Offset with milliseconds",
        "20260709T072000.123+1000",
        "%Y%m%dT%H%M%S.%Q%z",
        "Existing scorer format: compact ISO 8601 with offset and milliseconds.",
        "Acceptable if documented and parsed reliably; confirm UTC normalisation."
  ],
  [
        "Windows Event Log XML SystemTime",
        "2026-07-09T07:20:00.1230000Z",
        "%Y-%m-%dT%H:%M:%S.%QZ",
        "Windows Event XML SystemTime-style UTC timestamp.",
        "Preferred over local Event Viewer display when available and mapped as event occurrence time."
  ],
  [
        "Oracle DB Default (DD-MON-RR) with offset",
        "09-JUL-26 07.20.00.123000 AM +10:00",
        "%d-%b-%y %I.%M.%S.%Q %p %:z",
        "Existing scorer format: Oracle-style timestamp with explicit UTC offset.",
        "Offset and sub-second precision are present; confirm two-digit year handling and UTC conversion."
  ],
  [
        "Vendor-specific timestamp with timezone abbreviation",
        "Thu Jul 09 07:20:00 AEST 2026",
        "%a %b %d %H:%M:%S %Z %Y",
        "Custom vendor/platform/application timestamp.",
        "Acceptable only if reliable, documented, and tested; timezone abbreviations can be ambiguous."
  ]
];

function flattenObject(obj, prefix='', out={}){
  if(obj === null || obj === undefined) return out;
  if(Array.isArray(obj)){
    obj.forEach((v,i)=>flattenObject(v, prefix ? `${prefix}.${i}` : String(i), out));
  } else if(typeof obj === 'object'){
    for(const [k,v] of Object.entries(obj)) flattenObject(v, prefix ? `${prefix}.${k}` : k, out);
  } else out[prefix] = obj;
  return out;
}

function normKey(s=''){
  return String(s || '').toLowerCase().replace(/[^a-z0-9]+/g,'_').replace(/^_|_$/g,'');
}

const FIELD_ALIASES = {
  log_received_time: ['@timestamp','timestamp','time','date_time','datetime','eventtime','event_time','_time','indextime','index_time','received_time','ingest_time','rt','deviceReceiptTime','TimeGenerated','TimeCreated','UtcTime'],
  log_creation_time: ['event.created','created','created_time','creation_time','device_time','event.created_time','event_time','timestamp','time','TimeCreated','UtcTime','start','end','eventStartTime','eventEndTime'],
  system_type: ['device_type','source_type','sourcetype','vendor','product','product_name','application','app','service','deviceVendor','deviceProduct','productName','event.provider','provider','type','category'],
  source_address: ['src_ip','src','srcaddr','src_addr','source.ip','source_ip','sourceAddress','src_host','shost','host','hostname','host.name','computer','computer_name','ComputerName','client_ip','client.address','dvc','deviceAddress','device_name','source'],
  device_asset_identifier: ['device_id','asset_id','host.id','agent.id','endpoint_id','serial_number','instance_id','computer_id','deviceExternalId','device.name','dvc','host','hostname','computer','ComputerName','machine_id','sensor_id'],
  user_identity: ['user','username','user.name','src_user','source_user','suser','duser','account','account_name','AccountName','SubjectUserName','TargetUserName','principal','principal_name','actor','actor.name','upn','userPrincipalName','login','identity'],
  severity_priority: ['level','severity','priority','risk','sev','event.severity','deviceSeverity','Severity','log_level','importance','rating'],
  action_message: ['event.action','action','activity','operation','OperationName','event.type','event_type','msg','message','Message','status_code','EventCode','event_id','eventid','EventID','signature','name','event.name','method','request.method','category'],
  command_process: ['command','cmd','command_line','cmdline','process.command_line','process.name','process.executable','process.args','Image','CommandLine','ParentImage','NewProcessName','process','process_path','executable','script_block_text','ScriptBlockText'],
  impacted_object: ['object','object_name','ObjectName','file','file.name','file.path','target','target.name','dest','destination','dst','dst_ip','dhost','resource','resource_id','url','uri','request','request_url','TargetUserName','account','process.name','registry_key'],
  result_activity: ['status','outcome','result','event.outcome','status_code','response_code','reason','disposition','verdict','result_code','action','allowed','blocked','success','failure','Success','Failure','http.status','statusCode'],
  session_transaction_id: ['session_id','sessionid','session','transaction_id','trace_id','correlation_id','request_id','event.id','sessionId','conn_id','connection_id','flow_id','uuid','process_guid','ProcessGuid','LogonId','activity_id'],
  unique_event_id: ['event.id','event_id','id','record_id','uid','uuid','guid','message_id','EventRecordID','RecordNumber','eventRecordId','correlation_id','request_id']
};

function expectedNamesFor(row){
  return [...(row.names || '').split(',').map(s => s.trim()).filter(Boolean), ...(FIELD_ALIASES[row.id] || [])];
}

function findFields(keys, names, rowId=''){
  const expected = [...names.split(',').map(s => s.trim()).filter(Boolean), ...(FIELD_ALIASES[rowId] || [])];
  const expectedNorm = expected.map(normKey).filter(Boolean);
  const lowerKeys = keys.map(k => [k, String(k).toLowerCase(), normKey(k)]);
  const hits = [];
  for(const [orig, low, norm] of lowerKeys){
    if(expected.some(e => low === String(e).toLowerCase() || low.endsWith('.'+String(e).toLowerCase())) || expectedNorm.some(e => norm === e || norm.endsWith('_'+e) || norm.includes(e+'_') || norm.includes('_'+e+'_'))) hits.push(orig);
  }
  return [...new Set(hits)];
}

function parseKeyValues(raw){
  const out = {};
  const text = String(raw || '');
  const re = /(?:^|[\s,{;])([A-Za-z_][\w.-]{1,80})=("[^"]*"|'[^']*'|[^\s,;]+)/g;
  let m;
  while((m = re.exec(text))){
    out[m[1]] = String(m[2] || '').replace(/^['"]|['"]$/g,'');
  }
  return out;
}

function extractCefFields(raw){
  const out = {};
  const idx = String(raw || '').indexOf('CEF:');
  if(idx < 0) return out;
  const cef = String(raw).slice(idx);
  const parts = cef.split('|');
  if(parts.length >= 7){
    out.cefVersion = parts[0].replace(/^CEF:/,'');
    out.deviceVendor = parts[1] || '';
    out.deviceProduct = parts[2] || '';
    out.deviceVersion = parts[3] || '';
    out.deviceEventClassId = parts[4] || '';
    out.name = parts[5] || '';
    out.severity = parts[6] || '';
    Object.assign(out, parseKeyValues(parts.slice(7).join('|')));
  }
  return out;
}

function normaliseLogFormatName(formatName){
  const raw = String(formatName || '').trim();
  const name = raw.toLowerCase();
  if(!raw) return '';
  if(/malformed|broken|invalid/.test(name)) return 'Malformed structured payload';
  if(/structured\s+json|^json$|json log|application\/json/.test(name)) return 'Structured JSON';
  if(/common event format|\bcef\b/.test(name)) return 'Common Event Format (CEF)';
  if(/rfc\s*5424|structured syslog|syslog 5424/.test(name)) return 'RFC 5424 structured syslog';
  if(/rfc\s*3164|bsd syslog|legacy syslog/.test(name)) return 'RFC 3164 syslog';
  if(/windows event xml|xmlwineventlog|wineventlog|event xml/.test(name)) return 'Windows Event XML';
  if(/\bxml\b/.test(name)) return 'XML log';
  if(/key[- ]?value|\bkv\b|key=value/.test(name)) return 'Key-value formatted logs';
  if(/tab-separated|\btsv\b/.test(name)) return 'Tab-separated values (TSV)';
  if(/comma-separated|\bcsv\b/.test(name)) return 'Comma-separated values (CSV)';
  if(/unstructured|unknown|plain text|free text/.test(name)) return 'Unstructured or unknown';
  return raw;
}

function logFormatGuidance(formatName, parseStatus='ok', extractedCount=0){
  const canonical = normaliseLogFormatName(formatName);
  const lower = canonical.toLowerCase();
  const base = (name, confidence, cls, splunk, structure, schema, siemStatus, validation, notes=[]) => ({
    formatName: name, confidence, cls, splunk, structure, schema, siemStatus, validation, notes
  });

  if(!canonical){
    return base('No log format selected or detected yet','None','info','Not assessed','Not assessed','Not assessed','Not assessed','Validation not started',['Enter an observed format in Source details or analyse a sample raw event.']);
  }
  if(parseStatus === 'malformed' || /malformed/.test(lower)){
    return base('Malformed structured payload','High','bad','Parser failure / fix source payload or line-breaking','Broken JSON, XML, or structured message','Schema cannot be trusted until payload is valid','Not suitable for SIEM validation until corrected','N - malformed or truncated',['Check transport truncation, escaping, event breaking, max event size, and whether multi-line events are being split.']);
  }
  if(/structured json/.test(lower)){
    return base('Structured JSON','High','good','INDEXED_EXTRACTIONS=json, KV_MODE=json, or sourcetype JSON parser','Structured key/value object; may include nested fields','Self-describing keys, but validate stable field names and value types','Strong candidate for search, detection, CIM mapping, and dashboards','Y - structured/vendor-supported',['Confirm the event timestamp field is mapped correctly, nested fields are extracted consistently, and large JSON events are not truncated.']);
  }
  if(/rfc 5424/.test(lower)){
    return base('RFC 5424 structured syslog','High','good','Syslog sourcetype with RFC 5424 timestamp/header parsing plus REPORT/EXTRACT for payload','PRI, version, timestamp, host, app, procid, msgid, structured-data, message','Stable syslog header; payload schema depends on vendor/application','Good SIEM format when structured-data and message payload are parsed','Y - structured syslog',['Prefer this over RFC 3164. Confirm host/app fields, structured-data extraction, and vendor payload field mapping.']);
  }
  if(/common event format/.test(lower)){
    return base('Common Event Format (CEF)','High','good','CEF-aware sourcetype/parser; extract extension key=value fields','Pipe-delimited CEF header plus key=value extension fields','Documented CEF header fields and extension keys','Good SIEM format where vendor CEF mappings are complete','Y - vendor-supported common format',['Confirm pipe escaping, extension key extraction, severity mapping, and vendor/product/event class fields.']);
  }
  if(/windows event xml/.test(lower)){
    return base('Windows Event XML','High','good','XmlWinEventLog sourcetype or Windows Event XML parser','Structured XML-derived event data with provider, EventID, channel, computer, and event data fields','Stable by provider/EventID, but field presence varies by event type','Strong for Windows security detections and correlation','Y - vendor/platform-supported',['Confirm EventID, Computer, Account, LogonId, Process, Object, and result fields are extracted for the required event types.']);
  }
  if(/key-value/.test(lower)){
    return base('Key-value formatted logs','Medium','warn','KV_MODE=auto where safe, or explicit REPORT/EXTRACT transforms','Delimiter-separated key=value pairs','Schema is usable if quoting, escaping, delimiters, and repeated keys are consistent','Usable for SIEM if keys are stable and required fields are present','Partial/Y - depends on delimiter reliability',['Validate quoted values, spaces in values, duplicate keys, empty values, and field names that change between event types.']);
  }
  if(/comma-separated/.test(lower)){
    return base('Comma-separated values (CSV)','Medium','warn','FIELD_NAMES + DELIMS, INDEXED_EXTRACTIONS=csv, or explicit CSV sourcetype','Delimited columns; meaning comes from header or fixed column order','Schema must be documented: delimiter, header, field order, quoting, and escaping','Usable only when the schema is stable and headers/field order are controlled','Partial - schema documentation required',['Confirm header handling, delimiter escaping, commas inside quoted values, column count drift, and versioned schema changes.']);
  }
  if(/tab-separated/.test(lower)){
    return base('Tab-separated values (TSV)','Medium','warn','FIELD_NAMES + DELIMS="\\t" or explicit TSV sourcetype','Tab-delimited columns; meaning comes from header or fixed column order','Schema must be documented: delimiter, header, field order, quoting, and escaping','Usually cleaner than CSV but still dependent on stable column order','Partial - schema documentation required',['Confirm tab escaping, missing columns, extra columns, header handling, and versioned schema changes.']);
  }
  if(/rfc 3164/.test(lower)){
    return base('RFC 3164 syslog','Medium','warn','Syslog parser with TIME_FORMAT=%b %d %H:%M:%S and vendor payload transforms','Legacy syslog header followed by vendor/application message text','Header is limited; payload schema is vendor-specific and often semi-structured','Usable, but timestamp and payload parsing need extra validation','Partial - legacy syslog constraints',['RFC 3164 lacks year and timezone in the timestamp. Confirm source timezone, year inference, host mapping, and vendor payload extraction.']);
  }
  if(/^xml log$/.test(lower)){
    return base('XML log','Medium','warn','KV_MODE=xml, XML-aware sourcetype, or explicit field extraction','Structured XML document or fragment','Schema depends on elements/attributes and namespace stability','Good if XML is valid and field extraction is deterministic','Partial/Y - validate XML structure and namespaces',['Confirm XML is not truncated, namespaces are handled, repeated elements are predictable, and timestamp fields are extracted.']);
  }
  if(/unstructured|unknown/.test(lower)){
    return base('Unstructured or unknown','Low','bad','Custom EXTRACT/REPORT transforms or source-side format change required','Free text or unknown layout','No reliable schema until parsing rules are designed and tested','Weak SIEM format; detections will be fragile until structured fields are available','N/Partial - parser required',['Prefer changing the source output to JSON, CEF, RFC 5424, or documented key-value. Otherwise create parser tests and sample coverage.']);
  }
  return base(canonical, extractedCount >= 3 ? 'Medium' : 'Low', extractedCount >= 3 ? 'warn' : 'bad', 'Custom sourcetype/parser required', 'Format not in the built-in guidance list', 'Schema must be documented from vendor/source samples', 'Validate before relying on detections or reporting', 'Partial - custom validation required', ['Document the source format, event breakers, timestamp parser, field extraction method, and required-field mapping.']);
}

function findTimestampCandidates(raw, values={}){
  const candidates = [];
  const add = (value, key='sample') => {
    if(value === null || value === undefined || value === '') return;
    const text = String(value).trim();
    const detection = detectDateTimeFormat(text);
    if(detection && detection.formatName !== 'Unknown or unsupported timestamp format') candidates.push({key, value:text, detection});
  };
  Object.entries(values || {}).forEach(([k,v]) => {
    if(/time|date|timestamp|created|occurred|event_time|_time|rt$/i.test(k) && (typeof v === 'string' || typeof v === 'number')) add(v, k);
  });
  const sample = String(raw || '').slice(0,8000);
  const timestampPatterns = [
    /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[\.,]\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})/g,
    /\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:[\.,]\d{1,9})?\s+\((?:[A-Z]{2,8}|[+-]\d{2}:\d{2})\)/g,
    /\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:[\.,]\d{1,9})?\s+\[[A-Z]{2,8}\]/g,
    /\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:[\.,]\d{1,9})?\s+[A-Z]{2,8}/g,
    /\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:[\.,]\d{1,9})?(?:\s*[+-]\d{2}:?\d{2}|\s+UTC)?/g,
    /\d{8}T\d{6}(?:\.\d{1,9})?(?:Z|[+-]\d{4})/g,
    /(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),\s+\d{2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{2,4}\s+\d{2}:\d{2}:\d{2}\s+(?:[+-]\d{4}|GMT)/gi,
    /(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday),\s+\d{2}-(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)-\d{2}\s+\d{2}:\d{2}:\d{2}\s+GMT/gi,
    /(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\s+[A-Z]{2,5})?\s+\d{4}/gi,
    /\d{2}\/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\/\d{4}:\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?\s+[+-]\d{4}/gi,
    /\[(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?\s+\d{4}\]/gi,
    /(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?/gi,
    /\d{1,2}\/\d{1,2}\/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s*(?:AM|PM)?/gi,
    /\d{2}\.\d{2}\.\d{4}\s+\d{2}:\d{2}:\d{2}/g,
    /\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2}/g,
    /\d{4}-W\d{2}-\d/g,
    /\d{4}-\d{3}/g,
    /\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}/g,
    /\b\d{19}\b|\b\d{18}\b|\b\d{17}\b|\b\d{16}\b|\b\d{14}\b|\b\d{13}\b|\b\d{10}\.\d{1,9}\b|\b\d{10}\b|\b\d{8}\b|\b\d{5}\b/g,
    /\d{2}-[A-Z]{3}-\d{2}\s+\d{2}\.\d{2}\.\d{2}\.\d{1,6}\s+(?:AM|PM)(?:\s+[+-]\d{2}:\d{2})?/gi,
    /[A-Z][a-z]{2}\s+\d{1,2},\s+\d{4}\s+\d{1,2}:\d{2}:\d{2}\s+(?:AM|PM)/g,
    /(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday),\s+[A-Z][a-z]+\s+\d{1,2},\s+\d{4}\s+at\s+\d{1,2}:\d{2}:\d{2}\s+(?:AM|PM)/g
  ];
  const genericMatches = [];
  timestampPatterns.forEach(re => {
    const matches = sample.match(re) || [];
    matches.forEach(v => genericMatches.push(v));
  });
  genericMatches.forEach(v => add(v, 'raw text'));
  return candidates.filter((c, idx, arr) => arr.findIndex(x => x.value === c.value && x.detection.formatName === c.detection.formatName) === idx);
}

function detectDateTimeFormat(value){
  const input = String(value || '').trim();
  if(!input) return null;
  const result = (formatName, timeFormat, confidence, cls, details={}) => ({
    input, formatName, timeFormat, confidence, cls,
    precision: details.precision || 'Unknown',
    timezone: details.timezone || 'Unknown',
    utcStatus: details.utcStatus || 'Unknown',
    normalisation: details.normalisation || 'Confirm during ingestion',
    notes: details.notes || [],
    example: details.example || input,
    description: details.description || ''
  });
  const fracPrecision = (frac, label='fractional digits') => frac ? (frac.length >= 3 ? `${frac.length} ${label}` : 'Sub-second but below milliseconds') : 'Seconds only - no milliseconds';
  const goodUtc = {timezone:'UTC / Z suffix', utcStatus:'Already UTC', normalisation:'Y - normalised to UTC'};
  const offset = {timezone:'Explicit UTC offset', utcStatus:'Offset supplied; convert to UTC', normalisation:'Partial / inconsistent'};
  const noTz = {timezone:'No timezone in value', utcStatus:'Timezone missing', normalisation:'Unknown'};
  const epoch = {timezone:'Epoch is UTC-based', utcStatus:'UTC-based value', normalisation:'Y - normalised to UTC'};

  let m;
  if((m = input.match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.(\d{9})Z$/))) return result('ISO 8601 / RFC 3339 - Nanoseconds','%Y-%m-%dT%H:%M:%S.%QZ','High','good',{...goodUtc, example:'2026-07-09T14:30:45.123456789Z', precision:'9 fractional digits', notes:['Nanosecond-style RFC 3339 value. Confirm Splunk/parser preserves or intentionally rounds precision.']});
  if((m = input.match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.(\d{7})Z$/))) return result(m[1].endsWith('0000') ? 'Windows Event Log XML SystemTime' : 'Language / framework - .NET "o" round-trip','%Y-%m-%dT%H:%M:%S.%QZ','High','good',{...goodUtc, example:input, precision:'7 fractional digits', notes:['UTC timestamp with 100-nanosecond style precision. Confirm parser precision handling.']});
  if((m = input.match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.(\d{3,6})Z$/))) return result(m[1].length === 3 ? 'ISO 8601 / RFC 3339 - Milliseconds' : 'ISO 8601 / RFC 3339 - Microseconds','%Y-%m-%dT%H:%M:%S.%QZ','High','good',{...goodUtc, example:input, precision:fracPrecision(m[1]), notes:['Preferred SIEM style when mapped to event occurrence time.']});
  if((m = input.match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2},(\d{1,9})Z$/))) return result('ISO 8601 / RFC 3339 - Comma decimal sign','%Y-%m-%dT%H:%M:%S,%QZ','High','good',{...goodUtc, example:'2026-07-09T14:30:45,123Z', precision:fracPrecision(m[1]), notes:['ISO 8601 permits comma as decimal sign. Confirm the parser accepts comma or normalise to a dot.']});
  if(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(input)) return result('ISO 8601 / RFC 3339 - Basic UTC (Zulu)','%Y-%m-%dT%H:%M:%SZ','High','warn',{...goodUtc, example:'2026-07-09T14:30:45Z', precision:'Seconds only - no milliseconds', notes:['UTC is present, but the timestamp does not meet the millisecond precision requirement.']});
  if((m = input.match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.(\d{1,9})([+-]\d{2}:\d{2})$/))) return result('ISO 8601 (Extended) - Offset with milliseconds','%Y-%m-%dT%H:%M:%S.%Q%:z','High','good',{...offset, example:'2026-07-09T07:20:00.123+10:00', precision:fracPrecision(m[1]), notes:['Acceptable when ingestion reliably converts the offset value to UTC.']});
  if((m = input.match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.(\d{1,9})([+-]\d{4})$/))) return result('ISO 8601 with UTC offset','%Y-%m-%dT%H:%M:%S.%Q%z','High','good',{...offset, example:'2026-07-09T07:20:00.123+1000', precision:fracPrecision(m[1]), notes:['Acceptable when ingestion reliably converts the offset value to UTC.']});
  if(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}$/.test(input)) return result('ISO 8601 / RFC 3339 - With numeric offset','%Y-%m-%dT%H:%M:%S%:z','High','warn',{...offset, example:'2026-07-09T14:30:45+00:00', precision:'Seconds only - no milliseconds', notes:['Timezone offset is present, but millisecond precision is not.']});
  if(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{4}$/.test(input)) return result('Syslog & system - systemd (short-iso)','%Y-%m-%dT%H:%M:%S%z','High','warn',{...offset, example:'2026-07-09T14:30:45+0000', precision:'Seconds only - no milliseconds', notes:['Offset is present; confirm UTC conversion.']});
  if((m = input.match(/^\d{8}T\d{6}\.(\d{1,9})(?:Z|[+-]\d{4})$/))) return result('ISO 8601 (Basic / Compact) - Offset with milliseconds','%Y%m%dT%H%M%S.%Q%z','High','good',{...(input.endsWith('Z') ? goodUtc : offset), example:'20260709T072000.123+1000', precision:fracPrecision(m[1]), notes:['Compact ISO 8601 removes separators. Confirm the Splunk parser uses the compact TIME_FORMAT exactly.']});
  if(/^\d{8}T\d{6}(?:Z|[+-]\d{4})$/.test(input)) return result('ISO 8601 / RFC 3339 - Basic / compact (no delimiters)','%Y%m%dT%H%M%S%z','High','warn',{...(input.endsWith('Z') ? goodUtc : offset), example:'20260709T143045Z', precision:'Seconds only - no milliseconds', notes:['Compact ISO 8601 is parseable but seconds only.']});
  if((m = input.match(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.(\d{1,9})([+-]\d{2}:?\d{2})$/))) return result(m[2].includes(':') ? 'RFC 3339' : 'Database - PostgreSQL timestamptz', m[2].includes(':') ? '%Y-%m-%d %H:%M:%S.%Q%:z' : '%Y-%m-%d %H:%M:%S.%Q%z','High','good',{...offset, example:input, precision:fracPrecision(m[1]), notes:['Explicit offset is present. Confirm parser support for the space separator and UTC conversion.']});
  if((m = input.match(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.(\d{1,9})([+-]\d{2})$/))) return result('Database - PostgreSQL timestamptz','%Y-%m-%d %H:%M:%S.%Q%z','High','good',{...offset, example:'2026-07-09 14:30:45.123456+00', precision:fracPrecision(m[1]), notes:['Explicit hour offset is present. Confirm parser support and UTC conversion.']});
  if((m = input.match(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.(\d{1,9}) [+-]\d{4} [A-Z]{2,5}$/))) return result('Language / framework - Go time.String()','%Y-%m-%d %H:%M:%S.%Q %z %Z','High','good',{...offset, example:'2026-07-09 14:30:45.123456789 +0000 UTC', precision:fracPrecision(m[1]), notes:['Go default string includes numeric offset and zone name. Prefer RFC3339/RFC3339Nano output where possible.']});
  if(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}Z$/.test(input)) return result('ISO 8601 / RFC 3339 - Space separator (RFC 3339 section 5.6)','%Y-%m-%d %H:%M:%SZ','High','warn',{...goodUtc, example:'2026-07-09 14:30:45Z', precision:'Seconds only - no milliseconds', notes:['RFC 3339 permits a space separator.']});
  if((m = input.match(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.(\d{1,9}) \(([A-Z]{2,8})\)$/))) return result('ISO 8601-style (non-standard) - Space sep + ms + zone in parens','%Y-%m-%d %H:%M:%S.%Q (%Z)','Medium','warn',{timezone:'Timezone abbreviation/name in parentheses', utcStatus:m[2].toUpperCase()==='UTC' || m[2].toUpperCase()==='GMT' ? 'Already UTC' : 'Depends on timezone abbreviation', normalisation:m[2].toUpperCase()==='UTC' || m[2].toUpperCase()==='GMT' ? 'Y - normalised to UTC' : 'Unknown', example:'2026-07-09 14:30:45.123 (UTC)', precision:fracPrecision(m[1]), notes:['Non-standard ISO-style timestamp. Zone abbreviations can be ambiguous; prefer RFC 3339 with Z or numeric offset.']});
  if(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \(([A-Z]{2,8})\)$/.test(input)){ const zone=input.match(/\(([A-Z]{2,8})\)$/)[1].toUpperCase(); return result('ISO 8601-style (non-standard) - Space sep + zone in parens','%Y-%m-%d %H:%M:%S (%Z)','Medium','warn',{timezone:'Timezone abbreviation/name in parentheses', utcStatus:zone==='UTC' || zone==='GMT' ? 'Already UTC' : 'Depends on timezone abbreviation', normalisation:zone==='UTC' || zone==='GMT' ? 'Y - normalised to UTC' : 'Unknown', example:'2026-07-09 14:30:45 (UTC)', precision:'Seconds only - no milliseconds', notes:['Non-standard ISO-style timestamp. Zone abbreviations can be ambiguous; prefer RFC 3339 with Z or numeric offset.']}); }
  if(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \[[A-Z]{2,8}\]$/.test(input)){ const zone=input.match(/\[([A-Z]{2,8})\]$/)[1].toUpperCase(); return result('ISO 8601-style (non-standard) - Space sep + zone in brackets','%Y-%m-%d %H:%M:%S [%Z]','Medium','warn',{timezone:'Timezone abbreviation/name in brackets', utcStatus:zone==='UTC' || zone==='GMT' ? 'Already UTC' : 'Depends on timezone abbreviation', normalisation:zone==='UTC' || zone==='GMT' ? 'Y - normalised to UTC' : 'Unknown', example:'2026-07-09 14:30:45 [UTC]', precision:'Seconds only - no milliseconds', notes:['Non-standard ISO-style timestamp. Zone abbreviations can be ambiguous; prefer RFC 3339 with Z or numeric offset.']}); }
  if(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [A-Z]{2,8}$/.test(input)){ const zone=input.match(/ ([A-Z]{2,8})$/)[1].toUpperCase(); return result('ISO 8601-style (non-standard) - Space sep + bare zone name','%Y-%m-%d %H:%M:%S %Z','Medium','warn',{timezone:'Bare timezone abbreviation/name', utcStatus:zone==='UTC' || zone==='GMT' ? 'Already UTC' : 'Depends on timezone abbreviation', normalisation:zone==='UTC' || zone==='GMT' ? 'Y - normalised to UTC' : 'Unknown', example:'2026-07-09 14:30:45 UTC', precision:'Seconds only - no milliseconds', notes:['Non-standard ISO-style timestamp. Zone abbreviations can be ambiguous; prefer RFC 3339 with Z or numeric offset.']}); }
  if(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \([+-]\d{2}:\d{2}\)$/.test(input)) return result('ISO 8601-style (non-standard) - Space sep + offset in parens','%Y-%m-%d %H:%M:%S (%:z)','High','warn',{...offset, example:'2026-07-09 14:30:45 (+00:00)', precision:'Seconds only - no milliseconds', notes:['Explicit offset is present but wrapped in parentheses. Prefer RFC 3339 space form without parentheses.']});
  if(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4}$/.test(input)) return result('Language / framework - Ruby Time#to_s','%Y-%m-%d %H:%M:%S %z','High','warn',{...offset, example:'2026-07-09 14:30:45 +0000', precision:'Seconds only - no milliseconds', notes:['Offset is present; confirm UTC conversion.']});
  if((m = input.match(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.(\d{7})$/))) return result('Database - SQL Server datetime2','%Y-%m-%d %H:%M:%S.%Q','Medium','warn',{...noTz, example:'2026-07-09 14:30:45.1234567', precision:'7 fractional digits', notes:['Sub-second precision is present, but timezone is absent unless supplied separately.']});
  if((m = input.match(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.(\d{4,6})$/))) return result('Database - MySQL DATETIME(6)','%Y-%m-%d %H:%M:%S.%Q','Medium','warn',{...noTz, example:'2026-07-09 14:30:45.123456', precision:fracPrecision(m[1]), notes:['Microsecond precision is present, but timezone is absent unless supplied separately.']});
  if((m = input.match(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.(\d{1,3})$/))) return result('ANSI SQL Standard Timestamp','%Y-%m-%d %H:%M:%S.%Q','Medium','warn',{...noTz, example:'2026-07-09 07:20:00.123', precision:fracPrecision(m[1]), notes:['Also matches Windows Event Viewer readable style; document the source timezone.']});
  if((m = input.match(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},(\d{1,6})$/))) return result('Language / framework - Python logging default','%Y-%m-%d %H:%M:%S,%Q','Medium','warn',{...noTz, example:'2026-07-09 14:30:45,123', precision:fracPrecision(m[1]), notes:['Common Python/Java logging style. Timezone is not present in the timestamp value.']});
  if(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(input)) return result('W3C Extended Log Format','%Y-%m-%d %H:%M:%S','Medium','warn',{...noTz, example:'2026-07-09 14:30:45', precision:'Seconds only - no milliseconds', notes:['Requires documented source timezone and does not meet millisecond precision requirement. Common in IIS/W3C and database logs.']});
  if(/^\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}$/.test(input)) return result('Web server & proxy - Nginx error log','%Y/%m/%d %H:%M:%S','Medium','warn',{...noTz, example:'2026/07/09 14:30:45', precision:'Seconds only - no milliseconds', notes:['Nginx error log style. Confirm source timezone.']});
  if(/^\d{4}-\d{2}-\d{2}$/.test(input)) return result('ISO 8601 / RFC 3339 - Date only','%Y-%m-%d','High','bad',{...noTz, example:'2026-07-09', precision:'Date only', utcStatus:'Not suitable', notes:['Not suitable as the primary event timestamp because there is no time component.']});
  if(/^\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?$/.test(input)) return result('ISO 8601 / RFC 3339 - Time only','%H:%M:%S.%Q','High','bad',{...noTz, example:'14:30:45.123', precision:input.includes('.') ? 'Sub-second time only' : 'Seconds only - no date', utcStatus:'Not suitable', notes:['Not suitable as the primary event timestamp unless a reliable date is available elsewhere.']});
  if(/^\d{4}-W\d{2}-\d$/.test(input)) return result('ISO 8601 / RFC 3339 - Week date','%G-W%V-%u','Medium','bad',{...noTz, example:'2026-W28-4', precision:'Date only', utcStatus:'Not suitable', notes:['Week dates need conversion and do not include time-of-day.']});
  if(/^\d{4}-\d{3}$/.test(input)) return result('ISO 8601 / RFC 3339 - Ordinal (day-of-year) date','%Y-%j','Medium','bad',{...noTz, example:'2026-190', precision:'Date only', utcStatus:'Not suitable', notes:['Ordinal dates need conversion and do not include time-of-day.']});

  if(/^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} [+-]\d{4}$/i.test(input)) return result('Internet message / RFC - RFC 5322 / 2822 (email)','%a, %d %b %Y %H:%M:%S %z','High','warn',{...offset, example:'Thu, 09 Jul 2026 14:30:45 +0000', precision:'Seconds only - no milliseconds', notes:['Offset is present, but timestamp precision is seconds only.']});
  if(/^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} GMT$/i.test(input)) return result('Internet message / RFC - RFC 1123 (HTTP date)','%a, %d %b %Y %H:%M:%S GMT','High','warn',{timezone:'GMT / UTC', utcStatus:'Already UTC', normalisation:'Y - normalised to UTC', example:'Thu, 09 Jul 2026 14:30:45 GMT', precision:'Seconds only - no milliseconds', notes:['HTTP-date style; UTC context is present via GMT.']});
  if(/^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{2} \d{2}:\d{2}:\d{2} [+-]\d{4}$/i.test(input)) return result('Internet message / RFC - RFC 822 (2-digit year)','%a, %d %b %y %H:%M:%S %z','Medium','warn',{...offset, example:'Thu, 09 Jul 26 14:30:45 +0000', precision:'Seconds only - no milliseconds', notes:['Confirm two-digit year handling.']});
  if(/^(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), \d{2}-(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)-\d{2} \d{2}:\d{2}:\d{2} GMT$/i.test(input)) return result('Internet message / RFC - RFC 850 (obsolete HTTP)','%A, %d-%b-%y %H:%M:%S GMT','Medium','warn',{timezone:'GMT / UTC', utcStatus:'Already UTC', normalisation:'Y - normalised to UTC', example:'Thursday, 09-Jul-26 14:30:45 GMT', precision:'Seconds only - no milliseconds', notes:['Obsolete HTTP-date style. Confirm two-digit year handling.']});
  if(/^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2} \d{2}:\d{2}:\d{2} \d{4}$/i.test(input)) return result('Internet message / RFC - ANSI C asctime()','%a %b %e %H:%M:%S %Y','Medium','warn',{...noTz, example:'Thu Jul  9 14:30:45 2026', precision:'Seconds only - no milliseconds', notes:['No timezone in value; document source timezone.']});
  if(/^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2} \d{2}:\d{2}:\d{2} [A-Z]{2,5} \d{4}$/i.test(input)) return result('Vendor-specific timestamp with timezone abbreviation','%a %b %d %H:%M:%S %Z %Y','Medium','warn',{timezone:'Timezone abbreviation', utcStatus:'Depends on timezone abbreviation', normalisation:'Unknown', example:'Thu Jul 09 07:20:00 AEST 2026', precision:'Seconds only - no milliseconds', notes:['Timezone abbreviations can be ambiguous. Prefer numeric offset or UTC Z.']});
  if(/^\[(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{2} \d{2}:\d{2}:\d{2}(?:\.\d{1,6})? \d{4}\]$/i.test(value.trim())) return result('Web server & proxy - Apache error log','[%a %b %d %H:%M:%S.%Q %Y]','Medium','warn',{...noTz, example:'[Thu Jul 09 14:30:45.123456 2026]', precision:input.includes('.') ? 'Sub-second precision' : 'Seconds only - no milliseconds', notes:['Bracketed Apache error log timestamp. Confirm source timezone.']});
  if(/^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}$/.test(input)) return result('Syslog & system - RFC 3164 (BSD syslog)','%b %e %H:%M:%S','High','warn',{timezone:'No year or timezone in value', utcStatus:'Timezone missing', normalisation:'Unknown', example:'Jul  9 14:30:45', precision:'Seconds only - no milliseconds', notes:['Traditional syslog timestamp requires year and timezone inference.']});
  if(/^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{2} \d{2}:\d{2}:\d{2}\.\d{1,6}$/i.test(input)) return result('Syslog & system - systemd (short-precise)','%b %d %H:%M:%S.%Q','Medium','warn',{...noTz, example:'Jul 09 14:30:45.123456', precision:'Sub-second precision', notes:['No year or timezone in value.']});
  if(/^\d{2}\/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}$/i.test(input)) return result('Web server & proxy - Apache Common Log Format','%d/%b/%Y:%H:%M:%S %z','High','warn',{...offset, example:'09/Jul/2026:14:30:45 +0000', precision:'Seconds only - no milliseconds', notes:['Common web log format. Offset is parseable, but millisecond precision is not present.']});
  if(/^\d{2}\/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\/\d{4}:\d{2}:\d{2}:\d{2}\.\d{1,6}$/i.test(input)) return result('Web server & proxy - HAProxy','%d/%b/%Y:%H:%M:%S.%Q','Medium','warn',{...noTz, example:'09/Jul/2026:14:30:45.123', precision:'Sub-second precision', notes:['Common log format with milliseconds but no timezone in this value.']});
  if(/^\d{2}-[A-Z]{3}-\d{2} \d{2}\.\d{2}\.\d{2}\.\d{1,6} (?:AM|PM)(?: [+-]\d{2}:\d{2})?$/i.test(input)) return result(input.includes('+') || / -\d{2}:\d{2}$/.test(input) ? 'Oracle DB Default (DD-MON-RR) with offset' : 'Database - Oracle TIMESTAMP', input.includes('+') || / -\d{2}:\d{2}$/.test(input) ? '%d-%b-%y %I.%M.%S.%Q %p %:z' : '%d-%b-%y %I.%M.%S.%Q %p','High','good',{...(input.includes('+') || / -\d{2}:\d{2}$/.test(input) ? offset : noTz), example:input, precision:'Sub-second precision', notes:['Confirm two-digit year handling and timezone/UTC conversion.']});

  if(/^\d{10}\.\d{1,9}$/.test(input)){ const frac = input.split('.')[1]; return result('Unix epoch - Float seconds','%s.%Q','High','good',{...epoch, example:'1783607445.123', precision:fracPrecision(frac), notes:['Unix timestamp with fractional seconds. Preserve the fractional component during parsing.']}); }
  if(/^\d{19}$/.test(input)) return result('Unix epoch - Nanoseconds','Custom epoch nanosecond conversion','High','good',{...epoch, example:'1783607445123456000', precision:'Nanoseconds', normalisation:'Custom conversion required', notes:['Convert from nanoseconds since Unix epoch before normal event-time parsing.']});
  if(/^\d{18}$/.test(input)) return result(input.startsWith('63') ? 'Unix epoch - .NET DateTime.Ticks' : 'Unix epoch - Windows FILETIME', input.startsWith('63') ? 'Custom .NET ticks conversion' : 'Custom conversion required','Medium','warn',{timezone:'UTC-based tick value', utcStatus:'UTC-based value', normalisation:'Custom conversion required', example:input, precision:'100-nanosecond intervals', notes:['Requires conversion before normal SIEM time parsing.']});
  if(/^\d{17}$/.test(input) && input.startsWith('20')) return result('Compact / sortable - Compact + millis','%Y%m%d%H%M%S%Q','Medium','warn',{...noTz, example:'20260709143045123', precision:'Milliseconds', notes:['Compact local timestamp; confirm source timezone.']});
  if(/^\d{16}$/.test(input)) return result('Unix epoch - Microseconds','Custom epoch microsecond conversion','High','good',{...epoch, example:'1783607445123456', precision:'Microseconds', normalisation:'Custom conversion required', notes:['Convert from microseconds since Unix epoch before normal event-time parsing.']});
  if(/^\d{14}$/.test(input) && input.startsWith('20')) return result('Compact / sortable - Compact timestamp','%Y%m%d%H%M%S','Medium','warn',{...noTz, example:'20260709143045', precision:'Seconds only - no milliseconds', notes:['Compact local timestamp; confirm source timezone.']});
  if(/^\d{13}$/.test(input)) return result('Unix epoch - Milliseconds','%s%Q','High','good',{...epoch, example:'1783607445123', precision:'Milliseconds', notes:['Acceptable when parsed as milliseconds, not seconds.']});
  if(/^\d{10}$/.test(input)) return result('Unix epoch - Seconds','%s','High','warn',{...epoch, example:'1783607445', precision:'Seconds only - no milliseconds', notes:['UTC-based, but it does not meet millisecond precision unless a separate millisecond field exists.']});
  if(/^\d{8}$/.test(input) && input.startsWith('20')) return result('Compact / sortable - Date-only compact','%Y%m%d','Medium','bad',{...noTz, example:'20260709', precision:'Date only', utcStatus:'Not suitable', notes:['Not suitable as a primary event timestamp because no time component is present.']});
  if(/^\d{5}$/.test(input)) return result('Compact / sortable - Julian-style (YYDDD)','%y%j','Medium','bad',{...noTz, example:'26190', precision:'Date only', utcStatus:'Not suitable', notes:['Julian-style date only; no time component.']});
  if(/^\[\s*\d+\.\d{1,6}\]$/.test(value.trim())) return result('Syslog & system - dmesg (kernel, uptime)','Custom uptime conversion required','Medium','bad',{timezone:'Seconds since boot', utcStatus:'Not wall clock time', normalisation:'Custom conversion required', example:'[  1234.567890]', precision:'Sub-second uptime', notes:['Kernel uptime is not a wall-clock event timestamp without boot-time conversion.']});

  if(/^\d{1,2}\/\d{1,2}\/\d{4} \d{1,2}:\d{2}:\d{2} PM$/i.test(input) || /^\d{1,2}\/\d{1,2}\/\d{4} \d{1,2}:\d{2}:\d{2} AM$/i.test(input)) return result('Human-readable / locale - US 12-hour','%m/%d/%Y %I:%M:%S %p','Medium','warn',{...noTz, example:'07/09/2026 02:30:45 PM', precision:'Seconds only - no milliseconds', notes:['Locale-dependent; confirm month/day ordering and timezone.']});
  if(/^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2}, \d{4} \d{1,2}:\d{2}:\d{2} (?:AM|PM)$/i.test(input)) return result('Human-readable / locale - US medium','%b %e, %Y %I:%M:%S %p','Medium','warn',{...noTz, example:'Jul 9, 2026 2:30:45 PM', precision:'Seconds only - no milliseconds', notes:['Locale-dependent and timezone-less.']});
  if(/^(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), (?:January|February|March|April|May|June|July|August|September|October|November|December) \d{1,2}, \d{4} at \d{1,2}:\d{2}:\d{2} (?:AM|PM)$/i.test(input)) return result('Human-readable / locale - US long','%A, %B %e, %Y at %I:%M:%S %p','Medium','warn',{...noTz, example:'Thursday, July 9, 2026 at 2:30:45 PM', precision:'Seconds only - no milliseconds', notes:['Human-readable format; document locale and source timezone before using as event time.']});
  if(/^\d{2}\/\d{2}\/\d{4} \d{2}:\d{2}:\d{2}$/.test(input)) return result('Human-readable / locale - European (DMY)','%d/%m/%Y %H:%M:%S','Medium','warn',{...noTz, example:'09/07/2026 14:30:45', precision:'Seconds only - no milliseconds', notes:['Ambiguous with US date ordering. Document locale.']});
  if(/^\d{2}\.\d{2}\.\d{4} \d{2}:\d{2}:\d{2}$/.test(input)) return result('Human-readable / locale - German (dotted)','%d.%m.%Y %H:%M:%S','Medium','warn',{...noTz, example:'09.07.2026 14:30:45', precision:'Seconds only - no milliseconds', notes:['Locale-specific and timezone-less.']});
  if(/^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) \d{2} (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2}$/i.test(input)) return result('Human-readable / locale - RFC-ish readable','%a %d %b %Y %H:%M:%S','Medium','warn',{...noTz, example:'Thu 09 Jul 2026 14:30:45', precision:'Seconds only - no milliseconds', notes:['Readable but timezone-less.']});
  if(/^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}$/.test(input)) return result('Compact / sortable - Reverse (log-file suffix)','%Y-%m-%d_%H-%M-%S','Medium','warn',{...noTz, example:'2026-07-09_14-30-45', precision:'Seconds only - no milliseconds', notes:['Common filename suffix format; usually not ideal as event time.']});

  return result('Unknown or unsupported timestamp format','Custom parser required','Low','bad',{example:input, precision:'Unknown', timezone:'Unknown', utcStatus:'Unknown', normalisation:'Unknown', notes:['No known pattern matched. Document the vendor format and create a parsing test before relying on the source.']});
}

function disambiguateDate(value){
  const trimmed = String(value || '').trim();
  const m = trimmed.match(/^(\d{1,2})([/.-])(\d{1,2})\2(\d{2,4})(.*)$/);
  if(!m) return {applicable:false};
  const [, firstRaw, sep, secondRaw, yearRaw, rest] = m;
  const first = Number(firstRaw), second = Number(secondRaw);
  const yearAssumed = yearRaw.length === 2;
  const year = yearAssumed ? Number(yearRaw) + (Number(yearRaw) < 70 ? 2000 : 1900) : Number(yearRaw);

  const buildIso = (mm, dd) => {
    if(mm < 1 || mm > 12 || dd < 1 || dd > 31) return null;
    const daysInMonth = new Date(year, mm, 0).getDate();
    if(dd > daysInMonth) return null;
    return `${String(year).padStart(4,'0')}-${String(mm).padStart(2,'0')}-${String(dd).padStart(2,'0')}`;
  };

  const usIso = buildIso(first, second);
  const euIso = buildIso(second, first);
  const bothValid = usIso !== null && euIso !== null && usIso !== euIso;

  let note;
  if(first > 12) note = 'The first component is greater than 12, so this can only be DD' + sep + 'MM' + sep + 'YYYY (EU/ISO) ordering.';
  else if(second > 12) note = 'The second component is greater than 12, so this can only be MM' + sep + 'DD' + sep + 'YYYY (US) ordering.';
  else if(usIso === euIso) note = 'Day and month are the same value, so both orderings produce the same date.';
  else note = 'Both orderings are valid calendar dates - confirm the source locale/vendor documentation before choosing one.';

  return {
    applicable: true,
    ambiguous: bothValid,
    input: trimmed,
    yearAssumed,
    usInterpretation: usIso ? usIso + rest : null,
    euInterpretation: euIso ? euIso + rest : null,
    note
  };
}

const USERNAME_FORMATS = [
  {
        "precedence": 1,
        "name": "SAML Persistent NameID",
        "category": "SAML protocol",
        "example": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
        "template": "URN identifier - value: opaque hash",
        "regex": "^urn:oasis:names:tc:SAML:2\\.0:nameid-format:persistent$",
        "notes": "Matches the Format URN, not the value. Value is opaque; not recoverable from value alone."
  },
  {
        "precedence": 2,
        "name": "SAML Email NameID",
        "category": "SAML protocol",
        "example": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        "template": "URN identifier - value: user@domain.com",
        "regex": "^urn:oasis:names:tc:SAML:1\\.1:nameid-format:emailAddress$",
        "notes": "Value aliases UPN / Email / NAI."
  },
  {
        "precedence": 3,
        "name": "SAML Transient NameID",
        "category": "SAML protocol",
        "example": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
        "template": "URN identifier - value: per-session string",
        "regex": "^urn:oasis:names:tc:SAML:2\\.0:nameid-format:transient$",
        "notes": "Value is ephemeral/opaque; single login session."
  },
  {
        "precedence": 4,
        "name": "SAML Unspecified NameID",
        "category": "SAML protocol",
        "example": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
        "template": "URN identifier - value: varies by claim",
        "regex": "^urn:oasis:names:tc:SAML:1\\.1:nameid-format:unspecified$",
        "notes": "Value unconstrained by definition; cannot be detected from value."
  },
  {
        "precedence": 5,
        "name": "SAML Windows Domain NameID",
        "category": "SAML protocol",
        "example": "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName",
        "template": "URN identifier - value: DOMAIN\\username",
        "regex": "^urn:oasis:names:tc:SAML:1\\.1:nameid-format:WindowsDomainQualifiedName$",
        "notes": "Value aliases down-level NetBIOS."
  },
  {
        "precedence": 6,
        "name": "SAML X509 Subject NameID",
        "category": "SAML protocol",
        "example": "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName",
        "template": "URN identifier - value: CN=...,OU=... DN",
        "regex": "^urn:oasis:names:tc:SAML:1\\.1:nameid-format:X509SubjectName$",
        "notes": "Value aliases LDAP DN."
  },
  {
        "precedence": 7,
        "name": "SAML Kerberos NameID",
        "category": "SAML protocol",
        "example": "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos",
        "template": "URN identifier - value: username@REALM",
        "regex": "^urn:oasis:names:tc:SAML:2\\.0:nameid-format:kerberos$",
        "notes": "Value aliases Kerberos user principal."
  },
  {
        "precedence": 8,
        "name": "AWS IAM ARN",
        "category": "Cloud IAM (AWS)",
        "example": "arn:aws:iam::123456789012:user/jsmith",
        "template": "arn:aws:iam::account-id:user/username",
        "regex": "^arn:aws:iam::\\d{12}:user\\/[\\w+=,.@\\/-]+$",
        "notes": "Unique arn:aws:iam:: prefix; no collisions."
  },
  {
        "precedence": 9,
        "name": "AWS STS assumed-role ARN",
        "category": "Cloud IAM (AWS)",
        "example": "arn:aws:sts::123456789012:assumed-role/Role/session",
        "template": "arn:aws:sts::account-id:assumed-role/role/session",
        "regex": "^arn:aws:sts::\\d{12}:assumed-role\\/[\\w+=,.@-]+\\/[\\w+=,.@-]+$",
        "notes": "Sibling of IAM ARN; sts + assumed-role."
  },
  {
        "precedence": 10,
        "name": "WebFinger acct URI",
        "category": "Internet / messaging",
        "example": "acct:jsmith@example.com",
        "template": "acct:username@domain",
        "regex": "^acct:[^@\\s]+@[^@\\s]+\\.[^@\\s]+$",
        "notes": "RFC 7565; acct: scheme."
  },
  {
        "precedence": 11,
        "name": "Tel URI",
        "category": "Consumer / phone",
        "example": "tel:+15551234567",
        "template": "tel:+E.164number",
        "regex": "^tel:\\+[1-9]\\d{1,14}$",
        "notes": "RFC 3966; tel: scheme."
  },
  {
        "precedence": 12,
        "name": "SIP URI",
        "category": "Internet / messaging",
        "example": "sip:jsmith@company.com",
        "template": "sip:username@domain.com",
        "regex": "^sips?:[^@\\s]+@[^@\\s\\/]+\\.[^@\\s\\/]+$",
        "notes": "sip: / sips: scheme."
  },
  {
        "precedence": 13,
        "name": "AWS access key ID",
        "category": "Cloud IAM (AWS)",
        "example": "AKIAIOSFODNN7EXAMPLE",
        "template": "AKIA/ASIA + 16 chars",
        "regex": "^(AKIA|ASIA)[0-9A-Z]{16}$",
        "notes": "Credential, not a name. Case-sensitive prefix. Often pasted into programmatic login."
  },
  {
        "precedence": 14,
        "name": "Security Identifier (SID)",
        "category": "Windows / AD",
        "example": "S-1-5-21-3623811015-3361044348-30300820-1013",
        "template": "S-1-5-21-x-x-x-x",
        "regex": "^S-1-\\d+(?:-\\d+)+$",
        "notes": "For user/computer accounts tighten to ^S-1-5-21(?:-\\d+){4}$."
  },
  {
        "precedence": 15,
        "name": "Object ID (GUID)",
        "category": "Entra / Azure AD",
        "example": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
        "template": "8-4-4-4-12 hex digits",
        "regex": "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
        "notes": "Case-agnostic on its own. Also covers on-prem objectGUID."
  },
  {
        "precedence": 16,
        "name": "B2B guest (external)",
        "category": "Entra / Azure AD",
        "example": "jsmith_partner.com#EXT#@company.onmicrosoft.com",
        "template": "user_extdomain.com#EXT#@tenant.onmicrosoft.com",
        "regex": "^[^@\\s]+#EXT#@[^@\\s]+\\.onmicrosoft\\.com$",
        "notes": "#EXT#@ marker. MUST test before generic UPN (which would swallow it)."
  },
  {
        "precedence": 17,
        "name": "GCP service account",
        "category": "Cloud IAM (GCP)",
        "example": "bot@my-project.iam.gserviceaccount.com",
        "template": "name@project.iam.gserviceaccount.com",
        "regex": "^[^@\\s]+@[^@\\s]+\\.iam\\.gserviceaccount\\.com$",
        "notes": ".gserviceaccount.com suffix. Test before generic UPN."
  },
  {
        "precedence": 18,
        "name": "Local Windows account",
        "category": "Windows / AD",
        "example": ".\\Administrator",
        "template": ".\\username",
        "regex": "^\\.\\\\[^\\\\\\/@\\s]+$",
        "notes": "Literal .\\ = this machine. NOTE: MACHINE\\user is NOT this \u2014 identical to NetBIOS."
  },
  {
        "precedence": 19,
        "name": "MySQL account",
        "category": "Database",
        "example": "'jsmith'@'localhost'",
        "template": "'username'@'host'",
        "regex": "^'[^']*'@'[^']*'$",
        "notes": "Identity tied to connecting host. Quotes make it distinctive."
  },
  {
        "precedence": 20,
        "name": "LDAP Distinguished Name (DN)",
        "category": "Directory (LDAP)",
        "example": "cn=jsmith,ou=People,dc=company,dc=com",
        "template": "cn=username,ou=group,dc=domain,dc=com",
        "regex": "^(?:[A-Za-z][\\w-]*=[^,]+)(?:,\\s*[A-Za-z][\\w-]*=[^,]+)+$",
        "notes": "key=value,... structure. Also the value form of X509SubjectName."
  },
  {
        "precedence": 21,
        "name": "Kerberos service principal",
        "category": "Kerberos",
        "example": "host/web.company.com@COMPANY.COM",
        "template": "service/instance@REALM",
        "regex": "^[^\\/@\\s]+\\/[^\\/@\\s]+@[^\\/@\\s]+$",
        "notes": "Forward-slash before @ separates it from user principal."
  },
  {
        "precedence": 22,
        "name": "Fediverse / Mastodon handle",
        "category": "Social / Fediverse",
        "example": "@jsmith@mastodon.social",
        "template": "@username@server",
        "regex": "^@[^@\\s]+@[^@\\s]+\\.[^@\\s]+$",
        "notes": "Two @ signs. Test before Matrix and bare handle."
  },
  {
        "precedence": 23,
        "name": "Matrix ID (MXID)",
        "category": "Social / Fediverse",
        "example": "@jsmith:matrix.org",
        "template": "@username:server",
        "regex": "^@[^@:\\s]+:[^@:\\s]+\\.[^@:\\s]+$",
        "notes": "Leading @ plus colon-separated server."
  },
  {
        "precedence": 24,
        "name": "XMPP / Jabber ID (JID)",
        "category": "Internet / messaging",
        "example": "jsmith@company.com/laptop",
        "template": "username@domain.com/resource",
        "regex": "^[^@\\/\\s]+@[^@\\/\\s]+\\.[^@\\/\\s]+\\/[^@\\s]+$",
        "notes": "Trailing /resource distinguishes it from UPN. Resource-less JID = plain UPN."
  },
  {
        "precedence": 25,
        "name": "Bare @-handle",
        "category": "Social / Fediverse",
        "example": "@jsmith",
        "template": "@username",
        "regex": "^@[A-Za-z0-9._-]+$",
        "notes": "Leading @, no domain, no colon."
  },
  {
        "precedence": 26,
        "name": "E.164 phone number",
        "category": "Consumer / phone",
        "example": "+15551234567",
        "template": "+[country][number]",
        "regex": "^\\+[1-9]\\d{1,14}$",
        "notes": "Leading +, up to 15 digits."
  },
  {
        "precedence": 27,
        "name": "On-Premises UPN",
        "category": "Windows / AD",
        "example": "jsmith@company.local",
        "template": "username@domain.local",
        "regex": "^[^@\\s\\\\\\/]+@[^@\\s\\\\\\/]+\\.(?:local|corp|internal|lan|intranet)$",
        "notes": "Internal-TLD heuristic \u2014 tune the TLD list. Otherwise identical to UPN/Email/NAI."
  },
  {
        "precedence": 28,
        "name": "Down-level logon name (FQDN variant)",
        "category": "Windows / AD",
        "example": "company.com\\jsmith",
        "template": "domain.com\\username",
        "regex": "^[^\\\\\\/@\\s]*\\.[^\\\\\\/@\\s]*\\\\[^\\\\\\/@\\s]+$",
        "notes": "Backslash with a dotted left side."
  },
  {
        "precedence": 29,
        "name": "Down-level logon name (NetBIOS)",
        "category": "Windows / AD",
        "example": "COMPANY\\jsmith",
        "template": "domain\\username",
        "regex": "^[^\\\\\\/@\\s.]+\\\\[^\\\\\\/@\\s]+$",
        "notes": "Backslash, no-dot left side (short NetBIOS name)."
  },
  {
        "precedence": 30,
        "name": "NAI (legacy prefixed)",
        "category": "Network auth",
        "example": "company.com\\jsmith",
        "template": "realm\\username (or realm/username)",
        "regex": "^[^\\\\\\/@\\s]+\\\\[^\\\\\\/@\\s]+$",
        "notes": "Same X\\Y shape as rows 28-29; broad backslash pattern that overlaps both."
  },
  {
        "precedence": 31,
        "name": "Kerberos user principal",
        "category": "Kerberos",
        "example": "jsmith@COMPANY.COM",
        "template": "username@REALM",
        "regex": "^[^@\\s\\\\\\/]+@[A-Z0-9.-]+\\.[A-Z]{2,}$",
        "notes": "Uppercase-realm heuristic only. Lowercase realm falls through to UPN."
  },
  {
        "precedence": 32,
        "name": "User Principal Name (UPN)",
        "category": "Entra / Azure AD",
        "example": "jsmith@company.com",
        "template": "username@domain.com",
        "regex": "^[^@\\s\\\\\\/]+@[^@\\s\\\\\\/]+\\.[^@\\s\\\\\\/]+$",
        "notes": "Identical regex to Email and NAI \u2014 unresolvable by pattern alone."
  },
  {
        "precedence": 33,
        "name": "Email address",
        "category": "Internet / messaging",
        "example": "jsmith@company.com",
        "template": "local-part@domain.com",
        "regex": "^[^@\\s\\\\\\/]+@[^@\\s\\\\\\/]+\\.[^@\\s\\\\\\/]+$",
        "notes": "Alias of UPN / NAI."
  },
  {
        "precedence": 34,
        "name": "Network Access Identifier (NAI)",
        "category": "Network auth",
        "example": "jsmith@company.com",
        "template": "username@realm",
        "regex": "^[^@\\s\\\\\\/]+@[^@\\s\\\\\\/]+\\.[^@\\s\\\\\\/]+$",
        "notes": "RFC 7542 (RADIUS/EAP/802.1X). Alias of UPN / Email."
  },
  {
        "precedence": 35,
        "name": "Numeric UID / employee ID",
        "category": "Generic / opaque",
        "example": "1001",
        "template": "digits",
        "regex": "^\\d+$",
        "notes": "Subset of SAMAccountName; test before it."
  },
  {
        "precedence": 36,
        "name": "Entra ImmutableID / sourceAnchor",
        "category": "Entra / Azure AD",
        "example": "qODJ8f2hK0mQ1pR3sT5uVw==",
        "template": "base64 of on-prem objectGUID",
        "regex": "^[A-Za-z0-9+/]{22}==$",
        "notes": "Used by Entra Connect. == suffix keeps it out of the SAMAccountName fallback."
  },
  {
        "precedence": 37,
        "name": "SAMAccountName (bare)",
        "category": "Windows / AD",
        "example": "jsmith",
        "template": "username",
        "regex": "^[A-Za-z0-9._-]+$",
        "notes": "Fallback \u2014 matches many bare tokens. Keep numeric UID and GUID above it."
  }
];


const $ = (sel, root=document) => root.querySelector(sel);
const $$ = (sel, root=document) => Array.from(root.querySelectorAll(sel));
const esc = value => String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));

function runRegexTest(pattern, flags, text){
  const cleanFlags = Array.from(new Set(String(flags || '').replace(/[^a-z]/gi,'').toLowerCase().split(''))).join('');
  const finalFlags = cleanFlags.includes('g') ? cleanFlags : cleanFlags + 'g';
  let re;
  try {
    re = new RegExp(pattern, finalFlags);
  } catch(e) {
    return {valid:false, error:e.message, matches:[], truncated:false};
  }
  const input = String(text || '');
  const MAX_MATCHES = 500;
  const matches = [];
  let m, guard = 0;
  while((m = re.exec(input)) !== null && matches.length < MAX_MATCHES){
    matches.push({
      index: m.index,
      match: m[0],
      groups: m.slice(1),
      namedGroups: m.groups ? {...m.groups} : null
    });
    if(m[0].length === 0) re.lastIndex++;
    guard++;
    if(guard > 5000) break;
  }
  return {valid:true, error:null, matches, truncated: matches.length >= MAX_MATCHES};
}

function buildHighlightedText(text, matches){
  const str = String(text || '');
  if(!matches || !matches.length) return esc(str);
  let out = '', last = 0;
  for(const m of matches){
    if(m.index < last) continue;
    out += esc(str.slice(last, m.index));
    out += `<mark>${esc(m.match)}</mark>`;
    last = m.index + m.match.length;
  }
  out += esc(str.slice(last));
  return out;
}

function stripTimeFormatComment(formatText) {
  let text = String(formatText || '').trim();
  if(!text) return '';
  text = text.replace(/\s*\(([^)]*)\)\s*$/g, (match, inner) => /^%[:A-Za-z0-9-]+$/.test(String(inner || '').trim()) ? match.trimEnd() : '');
  if(/^%/.test(text) && /\s+-\s+/.test(text)) text = text.split(/\s+-\s+/)[0].trim();
  if(/^%/.test(text) && /\s+\+\s+ms$/i.test(text)) text = text.replace(/\s+\+\s+ms$/i, '%Q');
  return text.trim();
}

function normaliseTimeFormat(formatText) {
  return stripTimeFormatComment(formatText)
    .replace(/\s+/g, ' ')
    .replace(/%3N|%6N|%9N/g, '%Q')
    .replace(/%N/g, '%Q')
    .trim();
}

function timeFormatAlternates(formatText) {
  const raw = String(formatText || '').trim();
  const values = new Set();
  const add = v => { if(v) values.add(normaliseTimeFormat(v)); };
  add(raw);
  add(stripTimeFormatComment(raw));
  if(raw.includes('%f')) add(raw.replace(/%f/g, '%Q'));
  if(raw.includes('%Q')) add(raw.replace(/%Q/g, '%3N'));
  if(raw.includes('%N')) add(raw.replace(/%N/g, '%Q'));
  if(raw.includes('%z')) add(raw.replace(/%z/g, '%:z'));
  if(raw.includes('%:z')) add(raw.replace(/%:z/g, '%z'));
  if(raw.includes('%3N')) add(raw.replace(/%3N/g, '%Q'));
  if(raw.includes('%6N')) add(raw.replace(/%6N/g, '%Q'));
  if(raw.includes('%9N')) add(raw.replace(/%9N/g, '%Q'));
  return Array.from(values).filter(Boolean);
}

function findTimeFormatReferenceMatches(formatText) {
  const inputAlts = timeFormatAlternates(formatText);
  const inputSet = new Set(inputAlts);
  const exact = [];
  const compatible = [];
  TIME_FORMATS.forEach(row => {
    const rowAlts = timeFormatAlternates(row[2]);
    if(rowAlts.some(v => inputSet.has(v))) exact.push(row);
    else if(rowAlts.some(v => inputAlts.some(i => v === i || v.replace(/Z$/, '%z') === i || i.replace(/Z$/, '%z') === v))) compatible.push(row);
  });
  return {exact, compatible};
}

function exampleFromSplunkTimeFormat(formatText) {
  let out = stripTimeFormatComment(formatText);
  if(!out || /custom|conversion|required|RFC 3339|micros|epoch|since/i.test(out)) return '';
  const literals = [];
  out = out.replace(/%%/g, () => {
    literals.push('%');
    return `__LIT${literals.length - 1}__`;
  });
  const replacements = [
    ['%:z','+10:00'], ['%3N','123'], ['%6N','123456'], ['%9N','123456789'], ['%Q','123'], ['%N','123'], ['%f','123456'],
    ['%Y','2026'], ['%G','2026'], ['%y','26'], ['%m','07'], ['%B','July'], ['%b','Jul'], ['%d','09'], ['%e',' 9'], ['%-d','9'], ['%j','190'],
    ['%V','28'], ['%u','4'], ['%A','Thursday'], ['%a','Thu'], ['%H','14'], ['%I','02'], ['%-I','2'], ['%M','30'], ['%S','45'],
    ['%p','PM'], ['%z','+1000'], ['%Z','UTC'], ['%s','1773040800']
  ];
  replacements.forEach(([token,value]) => { out = out.split(token).join(value); });
  out = out.replace(/__LIT(\d+)__/g, (_,i) => literals[Number(i)] || '%');
  return out;
}

function analyseTimeFormatTokens(formatText) {
  const fmt = stripTimeFormatComment(formatText);
  const norm = normaliseTimeFormat(fmt);
  const has = token => norm.includes(token);
  const hasYear = /%Y|%y|%G/.test(norm);
  const hasDate = hasYear && /%m|%b|%B|%j|%V/.test(norm) && /%d|%e|%j|%u/.test(norm);
  const hasTime = /%H|%I/.test(norm) && has('%M') && has('%S');
  const hasFraction = /%Q|%N|%3N|%6N|%9N|%f/.test(fmt);
  const hasOffset = /%:z|%z/.test(norm);
  const hasZoneToken = has('%Z');
  const hasLiteralZoneText = /\b(?:GMT|UTC)\b/.test(norm);
  const hasLiteralZ = /(^|[^%])Z($|[^A-Za-z])/.test(norm);
  const hasZoneName = hasZoneToken || hasLiteralZoneText;
  const hasTimezone = hasOffset || hasZoneToken || hasLiteralZoneText || hasLiteralZ || has('%s');
  let precision = hasFraction ? 'Sub-second / millisecond capable' : has('%s') ? 'Seconds unless combined with fractional token' : hasTime ? 'Seconds only' : 'No full time component';
  if(/%3N/.test(fmt)) precision = 'Milliseconds (%3N)';
  if(/%6N|%f/.test(fmt)) precision = 'Microseconds';
  if(/%9N/.test(fmt)) precision = 'Nanoseconds';
  if(/%Q/.test(fmt)) precision = 'Fractional seconds using Splunk %Q';
  let timezone = hasOffset ? 'Numeric UTC offset' : hasZoneToken ? 'Timezone name / abbreviation' : (hasLiteralZ || hasLiteralZoneText) ? 'UTC literal Z / GMT / UTC' : has('%s') ? 'Epoch is UTC-based' : 'No timezone in format';
  let risk = 'Medium';
  const notes = [];
  if(!hasDate && !has('%s')) notes.push('No complete calendar date was identified.');
  if(!hasTime && !has('%s')) notes.push('No complete time-of-day was identified.');
  if(!hasTimezone) notes.push('No timezone or UTC offset token is present; document source timezone or set TZ handling separately.');
  if(has('%Z')) notes.push('Timezone abbreviations such as AEST, PST, or CET can be ambiguous; numeric offsets are safer.');
  if(!hasFraction) notes.push('No fractional-second token is present, so the format is likely seconds precision only.');
  if(hasDate && hasTime && hasTimezone && hasFraction) risk = has('%Z') && !hasOffset ? 'Medium' : 'Low';
  if(!hasDate || !hasTime || !hasTimezone) risk = 'High';
  if(has('%s')) risk = hasFraction ? 'Low' : 'Medium';
  return {fmt, norm, hasDate, hasTime, hasFraction, hasOffset, hasZoneName, hasLiteralZ, hasTimezone, precision, timezone, risk, notes};
}

function classifySplunkTimeFormat(formatText, matches) {
  const info = analyseTimeFormatTokens(formatText);
  const norm = info.norm;
  let standard = 'Custom / vendor-specific datetime format';
  let category = 'Custom parser / source-specific';
  let description = 'No exact reference pattern matched. The result is inferred from the tokens in the Splunk TIME_FORMAT string.';
  if(matches.exact.length) {
    const best = bestTimeFormatReference(matches.exact);
    standard = best[0];
    category = 'Exact reference match';
    description = best[3] || 'Matched the timestamp reference table.';
  } else if(/^%Y-%m-%dT%H:%M:%S(?:\.%Q)?(?:Z|%z|%:z)$/.test(norm)) {
    standard = 'ISO 8601 / RFC 3339';
    category = 'Inferred standard';
    description = 'Calendar date, T separator, time-of-day, and UTC/offset token align with ISO 8601 / RFC 3339 style timestamps.';
  } else if(/^%Y%m%dT%H%M%S(?:\.%Q)?(?:Z|%z|%:z)$/.test(norm)) {
    standard = 'ISO 8601 Basic / compact';
    category = 'Inferred standard';
    description = 'Compact ISO-style timestamp without date and time delimiters.';
  } else if(/^%a, %d %b %Y %H:%M:%S (?:%z|GMT|UTC)$/.test(norm) || /^%a, %d %b %y %H:%M:%S %z$/.test(norm)) {
    standard = 'RFC 5322 / RFC 2822 / RFC 822 internet message date';
    category = 'Inferred standard';
    description = 'Weekday, day, month name, year, time, and offset are typical internet message date components.';
  } else if(/^%b %e?\s*%H:%M:%S$/.test(norm) || /^%b %d %H:%M:%S(?:\.%Q)?$/.test(norm)) {
    standard = 'RFC 3164 / BSD syslog-style timestamp';
    category = 'Inferred standard';
    description = 'Month name, day, and time without year or timezone matches legacy syslog-style timestamps.';
  } else if(/^%d\/%b\/%Y:%H:%M:%S(?:\.%Q)?(?: %z)?$/.test(norm)) {
    standard = 'Apache / Nginx Common Log Format style';
    category = 'Inferred standard';
    description = 'Day/month/year with colon-separated time is typical of web server access logs.';
  } else if(norm === '%s' || norm === '%s%Q' || norm === '%s.%Q') {
    standard = 'Unix epoch';
    category = 'Inferred standard';
    description = 'Epoch seconds with optional fractional or millisecond component.';
  } else if(/^%Y-%m-%d %H:%M:%S(?:\.%Q)?(?: ?%z| ?%:z)?$/.test(norm)) {
    standard = info.hasTimezone ? 'RFC 3339 / SQL timestamp with offset' : 'SQL / W3C / local timestamp without timezone';
    category = 'Inferred standard';
    description = info.hasTimezone ? 'Space-separated date/time with explicit offset.' : 'Space-separated date/time without timezone. Common in SQL, W3C, IIS, and application logs.';
  } else if(/^%m\/%d\/%Y %I:%M:%S %p$/.test(norm)) {
    standard = 'US locale 12-hour timestamp';
    category = 'Inferred locale format';
    description = 'US month/day/year ordering with 12-hour clock and AM/PM.';
  } else if(/^%d\/%m\/%Y %H:%M:%S$/.test(norm)) {
    standard = 'European / DMY locale timestamp';
    category = 'Inferred locale format';
    description = 'Day/month/year ordering with 24-hour time and no timezone.';
  } else if(/^%Y%m%d%H%M%S(?:%Q)?$/.test(norm)) {
    standard = 'Compact sortable timestamp';
    category = 'Inferred compact format';
    description = 'Sortable numeric timestamp using year, month, day, hour, minute, and second.';
  }
  const cls = info.risk === 'Low' ? 'good' : info.risk === 'Medium' ? 'warn' : 'bad';
  const confidence = matches.exact.length ? 'High' : matches.compatible.length ? 'Medium' : (category.startsWith('Inferred') ? 'Medium' : 'Low');
  return {standard, category, description, cls, confidence, info};
}

function bestTimeFormatReference(rows) {
  const score = row => {
    const name = String(row?.[0] || '');
    if(/^ISO 8601 \/ RFC 3339/i.test(name)) return 0;
    if(/^ISO 8601/i.test(name)) return 1;
    if(/^Internet message \/ RFC/i.test(name)) return 1;
    if(/^Unix epoch/i.test(name)) return 1;
    if(/^Syslog/i.test(name)) return 2;
    if(/^Web server/i.test(name)) return 3;
    if(/^Compact/i.test(name)) return 3;
    if(/^Database/i.test(name)) return 4;
    if(/^Human-readable/i.test(name)) return 5;
    if(/^Language \/ framework/i.test(name)) return 6;
    if(/^Vendor/i.test(name)) return 7;
    return 8;
  };
  return [...(rows || [])].sort((a,b) => score(a) - score(b))[0];
}

function reverseLookupTimeFormat(formatText) {
  const raw = String(formatText || '').trim();
  if(!raw) return null;
  const matches = findTimeFormatReferenceMatches(raw);
  const classification = classifySplunkTimeFormat(raw, matches);
  const bestExact = bestTimeFormatReference(matches.exact);
  const bestCompatible = bestTimeFormatReference(matches.compatible);
  const example = bestExact?.[1] || bestCompatible?.[1] || exampleFromSplunkTimeFormat(raw) || 'Example generation unavailable';
  const validation = bestExact?.[4] || (classification.info.notes.length ? classification.info.notes.join(' ') : 'Validate against representative sample events before production use.');
  return { input: raw, example, matches, ...classification, validation };
}

function renderReverseTimeFormatResult(result) {
  const box = $('#reverseTimeFormatResult');
  const list = $('#reverseTimeFormatMatches');
  if(!result) {
    renderDetection(box, null, 'No Splunk TIME_FORMAT analysed yet', 'Paste a format string such as %Y-%m-%dT%H:%M:%S.%QZ and select Lookup TIME_FORMAT.');
    if(list) list.innerHTML = '';
    return;
  }
  renderDetection(box, {
    cls: result.cls,
    title: result.standard,
    confidence: result.confidence + ' confidence',
    meta: [
      ['Value', result.input],
      ['Category', result.category],
      ['Example', result.example],
      ['Precision', result.info.precision],
      ['Timezone', result.info.timezone],
      ['Risk', result.info.risk]
    ],
    description: result.description,
    notes: `Validation: ${result.validation}`
  }, '', '');
  if(list) {
    const exactRows = result.matches.exact.slice(0,8);
    const compatibleRows = result.matches.compatible.slice(0,8);
    const sections = [];
    if(exactRows.length) {
      sections.push(`<div class="item"><strong>Exact reference matches (${exactRows.length})</strong>${exactRows.map(row => `<div class="small"><code>${esc(row[2])}</code> - ${esc(row[0])} - example <code>${esc(row[1])}</code></div>`).join('')}</div>`);
    }
    if(!exactRows.length && compatibleRows.length) {
      sections.push(`<div class="item"><strong>Compatible reference matches (${compatibleRows.length})</strong>${compatibleRows.map(row => `<div class="small"><code>${esc(row[2])}</code> - ${esc(row[0])} - example <code>${esc(row[1])}</code></div>`).join('')}</div>`);
    }
    if(!sections.length) {
      sections.push('<div class="item small">No exact reference row matched. The standard was inferred from the TIME_FORMAT tokens.</div>');
    }
    list.innerHTML = sections.join('');
  }
}

function detectReverseTimeFormat() {
  const value = $('#sampleSplunkTimeFormat')?.value.trim() || '';
  if(!value) { renderValidationWarning($('#reverseTimeFormatResult'), 'Paste a Splunk TIME_FORMAT string first.'); return; }
  renderReverseTimeFormatResult(reverseLookupTimeFormat(value));
}

function renderEpochToDateResult(result) {
  const box = $('#epochToDateResult');
  if(!result) {
    renderDetection(box, null, 'No epoch value converted yet', 'Enter an epoch value and select Convert to date/time.');
    return;
  }
  if(!result.valid) {
    renderValidationWarning(box, result.error);
    return;
  }
  renderDetection(box, {
    cls: 'good',
    title: result.iso,
    confidence: `${result.unit} precision`,
    meta: [
      ['Day of week (UTC)', result.dayOfWeek],
      ['Unix seconds', String(result.unixSeconds)],
      ['Unix milliseconds', String(result.unixMillis)],
      ['Splunk TIME_FORMAT', result.splunkTimeFormat]
    ]
  }, '', '');
}

function convertEpochToDate() {
  const value = $('#epochInput').value;
  const unit = $('#epochUnit').value;
  if(!String(value || '').trim()) { renderValidationWarning($('#epochToDateResult'), 'Enter an epoch value first.'); return; }
  renderEpochToDateResult(epochToDate(value, unit));
}

function renderDateToEpochResult(result) {
  const box = $('#dateToEpochResult');
  if(!result) {
    renderDetection(box, null, 'No date/time converted yet', 'Enter a date/time value and select Convert to epoch.');
    return;
  }
  if(!result.valid) {
    renderValidationWarning(box, result.error);
    return;
  }
  renderDetection(box, {
    cls: 'good',
    title: `${result.unixSeconds} sec / ${result.unixMillis} ms`,
    confidence: result.dayOfWeek,
    meta: [
      ['ISO 8601 (UTC)', result.iso],
      ['Unix microseconds', String(result.unixMicros)],
      ['Unix nanoseconds', String(result.unixNanos)]
    ],
    notes: result.timezoneNote
  }, '', '');
}

function convertDateToEpoch() {
  const value = $('#dateTimeInput').value;
  if(!String(value || '').trim()) { renderValidationWarning($('#dateToEpochResult'), 'Enter a date/time value first.'); return; }
  renderDateToEpochResult(dateToEpoch(value));
}

function renderValidationWarning(box, message) {
  box.className = 'detectBox warn';
  box.innerHTML = `<div class="detectTitle">${esc(message)}</div>`;
}

function renderDetection(box, data, emptyTitle, emptyNote) {
  if(!data) {
    box.className = 'detectBox info';
    box.innerHTML = `<div class="detectTitle">${esc(emptyTitle)}</div><div class="detectNotes">${esc(emptyNote)}</div>`;
    return;
  }
  box.className = 'detectBox ' + (data.cls || 'info');
  const pillClass = data.cls === 'bad' ? 'bad' : data.cls === 'good' ? 'good' : data.cls === 'warn' ? 'warn' : 'info';
  const meta = (data.meta || []).map(([k,v]) => `<span>${esc(k)}: <code>${esc(v)}</code></span>`).join('');
  box.innerHTML = `
    <div class="detectTitle">${esc(data.title)} <span class="pill ${pillClass}">${esc(data.confidence || 'Detected')}</span></div>
    ${meta ? `<div class="detectMeta">${meta}</div>` : ''}
    ${data.description ? `<div class="detectNotes">${esc(data.description)}</div>` : ''}
    ${data.notes ? `<div class="detectNotes">${esc(data.notes)}</div>` : ''}
  `;
}

function renderLogFormatResult(formatName, parseStatus, extracted, truncation) {
  const guidance = logFormatGuidance(formatName, parseStatus, extracted.length);
  const notes = [guidance.notes?.join(' ') || ''];
  if(truncation && truncation.looksTruncated) notes.push(`Possible truncation: ${truncation.reasons.join(' ')}`);
  renderDetection($('#logFormatResult'), {
    cls: truncation && truncation.looksTruncated && guidance.cls === 'good' ? 'warn' : guidance.cls,
    title: guidance.formatName,
    confidence: guidance.confidence + ' confidence',
    meta: [
      ['Splunk handling', guidance.splunk],
      ['Structure', guidance.structure],
      ['Schema', guidance.schema]
    ],
    description: `SIEM status: ${guidance.siemStatus}. Validation: ${guidance.validation}.`,
    notes: notes.filter(Boolean).join(' ')
  }, 'No log format detected yet', 'Paste a raw event and select Detect log format.');
}

function renderTimestampResult(target, detection) {
  renderDetection(target, detection ? {
    cls: detection.cls,
    title: detection.formatName,
    confidence: detection.confidence + ' confidence',
    meta: [
      ['Example', detection.example || detection.input],
      ['Splunk', detection.timeFormat],
      ['Precision', detection.precision],
      ['Timezone', detection.timezone]
    ],
    description: detection.description || '',
    notes: `UTC status: ${detection.utcStatus}. Normalisation: ${detection.normalisation}.${detection.notes?.length ? ' ' + detection.notes.join(' ') : ''}`
  } : null, 'No timestamp detected yet', 'Paste one timestamp and select Detect timestamp.');
}

function renderPropsConfSuggestion(detection) {
  const box = $('#propsConfSuggestion');
  if(!box) return;
  if(!detection || !detection.input) {
    box.innerHTML = `<div class="detectTitle">props.conf suggestion</div>
      <div class="detectNotes">Detect a timestamp to generate the three timestamp parsing settings.</div>
      <pre>MAX_TIMESTAMP_LOOKAHEAD =
TIME_FORMAT =
TIME_PREFIX =</pre>`;
    return;
  }
  const sample = String(detection.input || '').trim();
  const maxLookahead = sample.length;
  const timeFormat = detection.timeFormat || '';
  const timePrefix = detection.timePrefix || '';
  box.innerHTML = `<div class="detectTitle">props.conf suggestion</div>
    <pre>MAX_TIMESTAMP_LOOKAHEAD = ${esc(maxLookahead)}
TIME_FORMAT = ${esc(timeFormat)}
TIME_PREFIX = ${esc(timePrefix)}</pre>`;
}

function renderLineBreakPropsSuggestion(detection) {
  const box = $('#lineBreakPropsSuggestion');
  if(!box) return;
  if(!detection) {
    box.innerHTML = `<div class="detectTitle">props.conf line breaking suggestion</div>
      <div class="detectNotes">Detect line breaks to generate event boundary settings.</div>
      <pre>SHOULD_LINEMERGE =
LINE_BREAKER =</pre>`;
    return;
  }
  box.innerHTML = `<div class="detectTitle">props.conf line breaking suggestion</div>
    <pre>SHOULD_LINEMERGE = ${esc(detection.shouldLineMerge || '')}
LINE_BREAKER = ${esc(detection.lineBreaker || '')}</pre>`;
}

function detectTimestampInput(value) {
  const raw = String(value || '').trim();
  if(!raw) return null;
  const direct = detectDateTimeFormat(raw);
  if(direct && direct.formatName !== 'Unknown or unsupported timestamp format') {
    return {...direct, originalInput: raw, timePrefix: ''};
  }
  const candidates = findTimestampCandidates(raw, {});
  if(!candidates.length) return direct;
  const preferred = candidates
    .map(c => ({...c, index: raw.indexOf(c.value)}))
    .filter(c => c.index >= 0)
    .sort((a,b) => a.index - b.index)[0] || candidates[0];
  const prefixIndex = raw.indexOf(preferred.value);
  const timePrefix = prefixIndex >= 0 ? raw.slice(0, prefixIndex) : '';
  return {
    ...preferred.detection,
    input: preferred.value,
    example: preferred.value,
    originalInput: raw,
    timePrefix
  };
}

const WEEKDAYS = ['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'];

function epochToDate(value, unit='auto'){
  const trimmed = String(value ?? '').trim();
  if(!trimmed) return {valid:false, error:'Enter an epoch value.'};
  if(!/^-?\d+(\.\d+)?$/.test(trimmed)) return {valid:false, error:'Epoch value must be numeric (digits only, with an optional decimal fraction).'};

  const isFloat = trimmed.includes('.');
  const digitCount = trimmed.replace(/^-/,'').split('.')[0].length;
  let resolvedUnit = unit;
  if(unit === 'auto'){
    if(isFloat || digitCount <= 10) resolvedUnit = 'seconds';
    else if(digitCount <= 13) resolvedUnit = 'milliseconds';
    else if(digitCount <= 16) resolvedUnit = 'microseconds';
    else resolvedUnit = 'nanoseconds';
  }

  const num = Number(trimmed);
  if(!Number.isFinite(num)) return {valid:false, error:'Epoch value is out of range.'};

  const msPerUnit = {seconds:1000, milliseconds:1, microseconds:1/1000, nanoseconds:1/1e6};
  if(!msPerUnit[resolvedUnit]) return {valid:false, error:`Unknown unit: ${resolvedUnit}.`};
  const ms = num * msPerUnit[resolvedUnit];

  const date = new Date(ms);
  if(Number.isNaN(date.getTime())) return {valid:false, error:'Epoch value is out of the representable date range.'};

  const splunkTimeFormat = resolvedUnit === 'seconds' ? '%s'
    : resolvedUnit === 'milliseconds' ? '%s%Q'
    : `Custom conversion required (${resolvedUnit})`;

  return {
    valid:true,
    unit: resolvedUnit,
    ms,
    iso: date.toISOString(),
    unixSeconds: Math.floor(ms/1000),
    unixMillis: Math.round(ms),
    dayOfWeek: WEEKDAYS[date.getUTCDay()],
    splunkTimeFormat
  };
}

function dateToEpoch(value){
  const trimmed = String(value || '').trim();
  if(!trimmed) return {valid:false, error:'Enter a date/time value.'};

  const hasZoneMarker = /(Z|UTC|GMT)$/i.test(trimmed) || /[+-]\d{2}:?\d{2}$/.test(trimmed);
  const isoLike = /^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/.test(trimmed);
  let date, timezoneNote;

  if(hasZoneMarker){
    date = new Date(trimmed);
    timezoneNote = 'Explicit timezone/offset detected and used.';
  } else if(isoLike){
    date = new Date(trimmed.replace(' ','T') + 'Z');
    timezoneNote = 'No timezone specified; interpreted as UTC.';
  } else {
    date = new Date(trimmed);
    timezoneNote = 'No timezone specified and the format is not ISO-like; interpreted using the local system timezone, which may be inaccurate. Prefer an ISO 8601 value.';
  }

  if(Number.isNaN(date.getTime())) return {valid:false, error:'Could not parse this as a date/time. Try an ISO 8601 value such as 2026-07-09T14:30:45Z.'};

  const ms = date.getTime();
  return {
    valid:true,
    timezoneNote,
    iso: date.toISOString(),
    unixSeconds: Math.floor(ms/1000),
    unixMillis: ms,
    unixMicros: ms*1000,
    unixNanos: ms*1e6,
    dayOfWeek: WEEKDAYS[date.getUTCDay()]
  };
}

function escapeLineBreakerLiteral(value) {
  return String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\s+/g, '\\s*');
}

function timestampLineStartInfo(line) {
  const trimmed = String(line || '').trimStart();
  if(!trimmed) return null;
  const candidates = findTimestampCandidates(trimmed, {});
  const usable = candidates.map(c => ({...c, index: trimmed.indexOf(c.value)}))
    .filter(c => {
      if(c.index < 0 || c.index > 40) return false;
      const before = trimmed.slice(0, c.index);
      return before === '' || /^[A-Za-z_][\w.-]{0,40}\s*[:=]\s*["']?$/.test(before) || /^[\["']$/.test(before);
    })
    .sort((a,b) => a.index - b.index)[0];
  if(!usable) return null;
  const prefix = trimmed.slice(0, usable.index);
  return {prefix, value:usable.value, detection:usable.detection};
}

function lineBreakerForTimestamp(info) {
  const name = String(info?.detection?.formatName || '');
  const prefix = info?.prefix || '';
  if(prefix) {
    return `([\\r\\n]+)(?=\\s*${escapeLineBreakerLiteral(prefix)})`;
  }
  if(/RFC 3164|systemd journal|systemd \(short|asctime|Python asctime/i.test(name)) {
    return '([\\r\\n]+)(?=\\s*[A-Z][a-z]{2}\\s+\\d{1,2}\\s+\\d{2}:\\d{2}:\\d{2})';
  }
  if(/Apache Common|Nginx access|HAProxy/i.test(name)) {
    return '([\\r\\n]+)(?=\\s*\\d{1,2}/[A-Z][a-z]{2}/\\d{4}:\\d{2}:\\d{2}:\\d{2})';
  }
  if(/RFC 5322|RFC 1123|RFC 822|RFC 850|JavaScript toUTCString|RFC-ish/i.test(name)) {
    return '([\\r\\n]+)(?=\\s*[A-Z][a-z]{2},?\\s+)';
  }
  if(/Unix epoch/.test(name)) {
    return '([\\r\\n]+)(?=\\s*\\d{10,19}(?:\\.\\d+)?)';
  }
  if(/Compact/.test(name)) {
    return '([\\r\\n]+)(?=\\s*\\d{8,17})';
  }
  return '([\\r\\n]+)(?=\\s*\\d{4}[-/]\\d{2}[-/]\\d{2})';
}

function detectLineBreakFormat(value) {
  const raw = String(value || '').replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  if(!raw.trim()) return null;
  const lines = raw.split('\n');
  const nonEmpty = lines.map((text, index) => ({text, index})).filter(row => row.text.trim());
  const blankLines = lines.length - nonEmpty.length;
  const stackContinuations = nonEmpty.filter(row => /^\s+(?:at\s|File\s"|\.{3}|\w+Error:|Caused by:)/.test(row.text) || /^\s*(?:at\s|Caused by:|Traceback\b)/.test(row.text)).length;
  const make = data => ({
    shouldLineMerge:'false',
    lineCount:lines.length,
    nonEmptyLines:nonEmpty.length,
    blankLines,
    stackContinuations,
    ...data
  });
  if(lines.length <= 1) {
    return make({
      formatName:'Single-line event sample',
      cls:'info',
      confidence:'High',
      structure:'Single-line',
      anchor:'No line break observed',
      lineBreaker:'',
      description:'The sample contains one physical line, so no event boundary pattern can be proven from the sample.',
      notes:'Use a larger sample with at least two events if this source can produce multiple records.'
    });
  }
  const jsonLines = nonEmpty.length > 1 && nonEmpty.every(row => {
    const text = row.text.trim();
    if(!/^[\[{]/.test(text)) return false;
    try { JSON.parse(text); return true; } catch(e) { return false; }
  });
  if(jsonLines) {
    return make({
      formatName:'Newline-delimited JSON',
      cls:'good',
      confidence:'High',
      structure:'One JSON document per line',
      anchor:'Line starts with JSON object or array',
      lineBreaker:'([\\r\\n]+)(?=\\s*[\\{\\[])',
      description:'Each non-empty line parses as its own JSON payload.',
      notes:'This is a strong fit for event breaking before each JSON payload.'
    });
  }
  const timestampStarts = nonEmpty.map(row => ({...row, ts:timestampLineStartInfo(row.text)})).filter(row => row.ts);
  if(timestampStarts.length >= 2) {
    const continuationLines = nonEmpty.length - timestampStarts.length;
    const info = timestampStarts[0].ts;
    return make({
      formatName: continuationLines ? 'Timestamp-started multiline events' : 'Timestamp-started line events',
      cls: continuationLines ? 'warn' : 'good',
      confidence: timestampStarts.length / nonEmpty.length >= 0.5 ? 'High' : 'Medium',
      structure: continuationLines ? 'Multiline events with timestamp anchors' : 'One event per timestamp-started line',
      anchor: info.prefix ? `Prefix plus timestamp: ${info.prefix}` : `Timestamp: ${info.detection.formatName}`,
      lineBreaker: lineBreakerForTimestamp(info),
      eventStartLines: timestampStarts.length,
      continuationLines,
      description: continuationLines ? 'Some lines appear to continue the previous event, so the timestamp at the start of a later line is the likely next-event boundary.' : 'Most event boundaries appear to start with a timestamp.',
      notes: stackContinuations ? 'Stack-trace style continuation lines were detected.' : ''
    });
  }
  if(nonEmpty.filter(row => /^<\d+>/.test(row.text.trim())).length >= 2) {
    return make({
      formatName:'Syslog priority-started events',
      cls:'good',
      confidence:'High',
      structure:'Syslog-like line events',
      anchor:'Line starts with syslog priority',
      lineBreaker:'([\\r\\n]+)(?=<\\d+>)',
      description:'Multiple lines start with a syslog priority marker.',
      notes:'This covers RFC 3164 and RFC 5424 style messages that retain the PRI prefix.'
    });
  }
  if(nonEmpty.filter(row => /^(?:CEF|LEEF):/.test(row.text.trim())).length >= 2) {
    return make({
      formatName:'CEF/LEEF line events',
      cls:'good',
      confidence:'High',
      structure:'One CEF/LEEF event per line',
      anchor:'Line starts with CEF: or LEEF:',
      lineBreaker:'([\\r\\n]+)(?=(?:CEF|LEEF):)',
      description:'Multiple lines start with a common SIEM event header.',
      notes:'If the product prefixes CEF/LEEF with syslog, prefer the syslog or timestamp anchor.'
    });
  }
  const xmlStarts = nonEmpty.filter(row => /^\s*(?:<\?xml|<[A-Za-z][\w:.-]*(?:\s|>))/.test(row.text)).length;
  if(xmlStarts >= 2) {
    return make({
      formatName:'XML-ish event starts',
      cls:'warn',
      confidence:'Medium',
      structure:'XML-like boundaries',
      anchor:'Line starts with XML declaration or tag',
      lineBreaker:'([\\r\\n]+)(?=\\s*(?:<\\?xml|<[A-Za-z][\\w:.-]*(?:\\s|>)))',
      description:'Multiple lines look like the start of XML fragments or documents.',
      notes:'Confirm this does not split inside a multiline XML event.'
    });
  }
  if(/\n\s*\n/.test(raw)) {
    return make({
      formatName:'Blank-line-separated events',
      cls:'warn',
      confidence:'Medium',
      structure:'Paragraph-style records',
      anchor:'One or more blank lines',
      lineBreaker:'([\\r\\n]+){2,}',
      description:'The sample contains blank lines that may separate records.',
      notes:'Use only if blank lines are reliable event separators for this source.'
    });
  }
  if(stackContinuations) {
    return make({
      formatName:'Multiline sample without repeated start anchor',
      cls:'bad',
      confidence:'Low',
      structure:'Stack-trace-like continuation',
      anchor:'No repeatable next-event anchor found',
      lineBreaker:'',
      description:'Continuation lines are present, but the sample does not include enough repeated event starts to build a safe line breaker.',
      notes:'Add at least two complete events so the detector can identify the next-event boundary.'
    });
  }
  return make({
    formatName:'Newline-delimited records without stable anchor',
    cls:'warn',
    confidence:'Medium',
    structure:'One physical line per possible event',
    anchor:'Plain newline',
    lineBreaker:'([\\r\\n]+)',
    description:'The sample has multiple non-empty lines but no stronger event-start pattern was found.',
    notes:'This is safe only when each physical line is always a complete event.'
  });
}

const STACK_TRACE_SIGNATURES = [
  {id:'java', name:'Java', startsWith:/^(Exception in thread |Caused by: |(?:[a-z][\w$]*\.)+[A-Z][\w$]*(?:Exception|Error)[:\s])/, continuation:/^\s*(at\s+[\w.$<>]+\(.*\)|\.\.\.\s*\d+\s+more|Caused by:)/, breakExclude:'Caused by:'},
  {id:'python', name:'Python', startsWith:/^Traceback \(most recent call last\):/, continuation:/^(\s*File "|\s+\S|\w+(?:Error|Exception|Warning):)/, breakExclude:'\\w+(?:Error|Exception|Warning):'},
  {id:'dotnet', name:'.NET / C#', startsWith:/^[\w$]+\.[\w$.]*Exception:/, continuation:/^(\s*at\s+[\w.<>`]+\(.*\)|--- End of inner exception)/, breakExclude:'--- End of inner exception'},
  {id:'node', name:'Node.js / JavaScript', startsWith:/^(TypeError|ReferenceError|SyntaxError|RangeError|Error):/, continuation:/^\s*at\s+.*\(.*:\d+:\d+\)/, breakExclude:null},
  {id:'go', name:'Go', startsWith:/^panic:/, continuation:/^(goroutine \d+ \[|\s*[\w./]+\.go:\d+)/, breakExclude:'goroutine \\d+ '}
];

function detectStackTrace(raw){
  const lines = String(raw || '').split(/\r?\n/);
  const nonEmpty = lines.filter(l => l.trim().length);
  if(!nonEmpty.length) return {detected:false};
  const startIndex = lines.findIndex(l => l.trim().length);
  const firstLine = lines[startIndex];

  const matched = STACK_TRACE_SIGNATURES.find(sig => sig.startsWith.test(firstLine));
  if(!matched) return {detected:false};

  const headerLine = firstLine.trim();
  let continuationLineCount = 0;
  for(let i = startIndex + 1; i < lines.length; i++){
    if(matched.continuation.test(lines[i])) continuationLineCount++;
  }

  const summaryLine = matched.id === 'python' ? (nonEmpty[nonEmpty.length - 1] || '') : headerLine;
  let exceptionType = null, exceptionMessage = null;
  const colonMatch = summaryLine.match(/^([\w.$]+(?:Exception|Error|Warning))\s*:\s*(.*)$/);
  if(colonMatch){ exceptionType = colonMatch[1]; exceptionMessage = colonMatch[2]; }

  const lineBreaker = '([\\r\\n]+)(?=\\S)' + (matched.breakExclude ? `(?!${matched.breakExclude})` : '');

  return {
    detected:true,
    language: matched.name,
    languageId: matched.id,
    headerLine,
    exceptionType,
    exceptionMessage,
    continuationLineCount,
    totalNonEmptyLines: nonEmpty.length,
    shouldLineMerge:'false',
    lineBreaker,
    notes:`Detected a ${matched.name} stack trace with ${continuationLineCount} continuation line(s). Use LINE_BREAKER = ${lineBreaker} so the exception header and its continuation lines stay attached to one event. Validate against a larger real sample before deploying.`
  };
}

function renderLineBreakResult(target, detection) {
  renderDetection(target, detection ? {
    cls:detection.cls,
    title:detection.formatName,
    confidence:detection.confidence + ' confidence',
    meta:[
      ['Structure', detection.structure],
      ['Event start anchor', detection.anchor],
      ['Lines', `${detection.nonEmptyLines} non-empty / ${detection.lineCount} total`],
      ['Continuation lines', detection.continuationLines ?? detection.stackContinuations ?? 0],
      ['SHOULD_LINEMERGE', detection.shouldLineMerge],
      ['LINE_BREAKER', detection.lineBreaker || 'Not enough evidence']
    ],
    description:detection.description || '',
    notes:detection.notes || ''
  } : null, 'No line break detected yet', 'Paste one or more events and select Detect line breaks.');
}

function detectUsernameFormat(value) {
  const input = String(value || '').trim();
  if(!input) return null;
  const matches = USERNAME_FORMATS.filter(row => {
    try { return new RegExp(row.regex).test(input); }
    catch(e) { return false; }
  });
  if(!matches.length) {
    return {
      input,
      formatName: 'Unknown or unsupported username format',
      category: 'Unknown',
      template: 'Custom parser required',
      regex: 'No known pattern matched',
      confidence: 'Low',
      cls: 'bad',
      notes: 'No username format pattern matched. Check whether this is an opaque vendor identifier, a display name, a truncated value, or a source-specific principal format.',
      alternatives: []
    };
  }
  const primary = matches[0];
  const ambiguous = matches.slice(1);
  const genericFallback = /SAMAccountName|UPN|Email address|Network Access Identifier|Numeric UID/.test(primary.name);
  return {
    input,
    formatName: primary.name,
    category: primary.category,
    template: primary.template,
    regex: primary.regex,
    confidence: ambiguous.length ? 'Medium' : genericFallback ? 'Medium' : 'High',
    cls: ambiguous.length || genericFallback ? 'warn' : 'good',
    notes: primary.notes,
    precedence: primary.precedence,
    alternatives: ambiguous
  };
}

function usernameExtractionGuidance(detection) {
  const name = String(detection?.formatName || '');
  const na = {domainIncluded:'No', domainComponent:'None', splunkRegex:'N/A', note:'No reliable domain/user split is present in this format.'};
  if(!detection || /Unknown/.test(name)) return na;
  const byName = [
    [/SAML .*NameID/, {domainIncluded:'No', domainComponent:'None in the Format URN', splunkRegex:'N/A', note:'This detects the SAML NameID Format URN, not the NameID value. Split the value separately based on the actual claim format.'}],
    [/AWS IAM ARN/, {domainIncluded:'No', domainComponent:'AWS account ID namespace', splunkRegex:'^arn:aws:iam::(?<account_id>\\d{12}):user/(?<user>[\\w+=,.@\\/-]+)$', note:'No domain is present, but the AWS account ID can be extracted as the identity namespace.'}],
    [/AWS STS assumed-role ARN/, {domainIncluded:'No', domainComponent:'AWS account ID and role namespace', splunkRegex:'^arn:aws:sts::(?<account_id>\\d{12}):assumed-role/(?<role>[\\w+=,.@-]+)/(?<user>[\\w+=,.@-]+)$', note:'No domain is present; the session name is captured as user and account_id/role provide the namespace.'}],
    [/WebFinger acct URI/, {domainIncluded:'Yes', domainComponent:'Domain after @', splunkRegex:'^acct:(?<user>[^@\\s]+)@(?<domain>[^@\\s]+\\.[^@\\s]+)$', note:''}],
    [/Tel URI|E\.164 phone number|AWS access key ID|Security Identifier|Object ID|Numeric UID|ImmutableID|SAMAccountName|Bare @-handle/, na],
    [/SIP URI/, {domainIncluded:'Yes', domainComponent:'Domain after @', splunkRegex:'^sips?:(?<user>[^@\\s]+)@(?<domain>[^@\\s\\/]+\\.[^@\\s\\/]+)$', note:''}],
    [/B2B guest/, {domainIncluded:'Yes', domainComponent:'Tenant domain after #EXT#@; original external domain is encoded in the user portion', splunkRegex:'^(?<user>[^@\\s]+)#EXT#@(?<domain>[^@\\s]+\\.onmicrosoft\\.com)$', note:'The captured user may contain the external source domain encoded into the local-part.'}],
    [/GCP service account/, {domainIncluded:'Yes', domainComponent:'Service-account domain after @', splunkRegex:'^(?<user>[^@\\s]+)@(?<domain>[^@\\s]+\\.iam\\.gserviceaccount\\.com)$', note:''}],
    [/Local Windows account/, {domainIncluded:'Yes', domainComponent:'Local machine marker "."', splunkRegex:'^(?<domain>\\.)\\\\(?<user>[^\\\\\\/@\\s]+)$', note:'The domain capture is the local-machine marker, not an AD domain.'}],
    [/MySQL account/, {domainIncluded:'Yes', domainComponent:'Host component after @', splunkRegex:"^'(?<user>[^']*)'@'(?<domain>[^']*)'$", note:'MySQL uses a connecting host component; treat it as host/domain context, not necessarily an identity domain.'}],
    [/LDAP Distinguished Name/, {domainIncluded:'Yes', domainComponent:'DN suffix, usually OU/DC components', splunkRegex:'^(?:cn|uid)=(?<user>[^,]+),(?<domain>.+)$', note:'The domain capture is the remaining DN path. Further parsing may be needed to join dc= parts into a DNS domain.'}],
    [/Kerberos service principal/, {domainIncluded:'Yes', domainComponent:'Realm after @', splunkRegex:'^(?<user>[^\\/@\\s]+\\/[^\\/@\\s]+)@(?<domain>[^\\/@\\s]+)$', note:'The user capture is the service/instance principal.'}],
    [/Fediverse/, {domainIncluded:'Yes', domainComponent:'Server domain after second @', splunkRegex:'^@(?<user>[^@\\s]+)@(?<domain>[^@\\s]+\\.[^@\\s]+)$', note:''}],
    [/Matrix ID/, {domainIncluded:'Yes', domainComponent:'Homeserver after colon', splunkRegex:'^@(?<user>[^@:\\s]+):(?<domain>[^@:\\s]+\\.[^@:\\s]+)$', note:''}],
    [/XMPP/, {domainIncluded:'Yes', domainComponent:'Domain after @ before /resource', splunkRegex:'^(?<user>[^@\\/\\s]+)@(?<domain>[^@\\/\\s]+\\.[^@\\/\\s]+)\\/(?<resource>[^@\\s]+)$', note:'Resource is captured separately because it is not part of the username.'}],
    [/On-Premises UPN|User Principal Name|Email address|Network Access Identifier/, {domainIncluded:'Yes', domainComponent:'Domain or realm after @', splunkRegex:'^(?<user>[^@\\s\\\\\\/]+)@(?<domain>[^@\\s\\\\\\/]+\\.[^@\\s\\\\\\/]+)$', note:'UPN, email, and NAI are pattern-equivalent; the detector returns the first match by precedence.'}],
    [/Down-level logon name \(FQDN variant\)/, {domainIncluded:'Yes', domainComponent:'Domain before backslash', splunkRegex:'^(?<domain>[^\\\\\\/@\\s]*\\.[^\\\\\\/@\\s]*)\\\\(?<user>[^\\\\\\/@\\s]+)$', note:''}],
    [/Down-level logon name \(NetBIOS\)|NAI \(legacy prefixed\)/, {domainIncluded:'Yes', domainComponent:'Domain or realm before backslash', splunkRegex:'^(?<domain>[^\\\\\\/@\\s]+)\\\\(?<user>[^\\\\\\/@\\s]+)$', note:''}],
    [/Kerberos user principal/, {domainIncluded:'Yes', domainComponent:'Realm after @', splunkRegex:'^(?<user>[^@\\s\\\\\\/]+)@(?<domain>[A-Z0-9.-]+\\.[A-Z]{2,})$', note:'Uppercase realm is a heuristic; lowercase realms may look like normal UPN/email values.'}]
  ];
  const found = byName.find(([re]) => re.test(name));
  return found ? found[1] : na;
}

const IPV4_REGEX = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const IPV6_REGEX = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|::(ffff(:0{1,4})?:)?((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9]))$/;

function classifyIpv4Category(octets){
  const [a,b] = octets;
  if(a === 10) return 'Private (RFC 1918)';
  if(a === 172 && b >= 16 && b <= 31) return 'Private (RFC 1918)';
  if(a === 192 && b === 168) return 'Private (RFC 1918)';
  if(a === 127) return 'Loopback';
  if(a === 169 && b === 254) return 'Link-local (APIPA)';
  if(a === 100 && b >= 64 && b <= 127) return 'Carrier-grade NAT (RFC 6598)';
  if(a >= 224 && a <= 239) return 'Multicast';
  if(a === 255 && octets[1] === 255 && octets[2] === 255 && octets[3] === 255) return 'Broadcast';
  if(a === 0) return 'Unspecified / "this network" (RFC 791)';
  return 'Public / globally routable (unless otherwise reserved)';
}

function classifyIpv6Category(addr){
  const lower = addr.toLowerCase();
  if(lower === '::1') return 'Loopback';
  if(lower === '::') return 'Unspecified';
  if(/^fe[89ab][0-9a-f]:/.test(lower)) return 'Link-local (fe80::/10)';
  if(/^f[cd][0-9a-f]{2}:/.test(lower)) return 'Unique local (fc00::/7)';
  if(/^ff/.test(lower)) return 'Multicast (ff00::/8)';
  if(/^::ffff:/.test(lower)) return 'IPv4-mapped IPv6';
  return 'Global / public (unless otherwise reserved)';
}

function classifyIpAddress(value){
  const trimmed = String(value || '').trim();
  if(!trimmed) return {valid:false, error:'Enter an IP address.'};
  const slashIndex = trimmed.indexOf('/');
  const addrPart = slashIndex >= 0 ? trimmed.slice(0, slashIndex) : trimmed;
  const prefixPart = slashIndex >= 0 ? trimmed.slice(slashIndex + 1) : undefined;
  if(slashIndex >= 0 && !prefixPart) return {valid:false, error:'CIDR prefix is missing after "/".'};

  const v4Match = addrPart.match(IPV4_REGEX);
  if(v4Match){
    const octets = v4Match.slice(1,5).map(Number);
    if(octets.some(o => o > 255)) return {valid:false, error:'IPv4 octets must be between 0 and 255.'};
    let cidr = null;
    if(prefixPart !== undefined){
      if(!/^\d{1,2}$/.test(prefixPart) || Number(prefixPart) > 32) return {valid:false, error:'IPv4 CIDR prefix must be between 0 and 32.'};
      cidr = Number(prefixPart);
    }
    return {
      valid:true, version:'IPv4', address:addrPart, cidr, isCidr: cidr !== null,
      category: classifyIpv4Category(octets),
      normalised: cidr !== null ? `${addrPart}/${cidr}` : addrPart
    };
  }

  if(IPV6_REGEX.test(addrPart)){
    let cidr = null;
    if(prefixPart !== undefined){
      if(!/^\d{1,3}$/.test(prefixPart) || Number(prefixPart) > 128) return {valid:false, error:'IPv6 CIDR prefix must be between 0 and 128.'};
      cidr = Number(prefixPart);
    }
    return {
      valid:true, version:'IPv6', address:addrPart, cidr, isCidr: cidr !== null,
      category: classifyIpv6Category(addrPart),
      normalised: cidr !== null ? `${addrPart}/${cidr}` : addrPart
    };
  }

  return {valid:false, error:'Not a recognised IPv4 or IPv6 address.'};
}

function findIpCandidates(raw, values={}){
  const candidates = [];
  const ipKey = /(^|[._-])(ip|ips|src_ip|source_ip|srcaddr|src_addr|dst_ip|dest_ip|dst_addr|dest_addr|dstaddr|client_ip|remote_addr|remote_ip|host|hostname|dvc|address|addr)($|[._-])/i;
  const add = (value, key='sample') => {
    if(value === null || value === undefined || value === '') return;
    const text = String(value).trim();
    if(!text || text.length > 60) return;
    const detection = classifyIpAddress(text);
    if(detection.valid) candidates.push({key, value:text, detection});
  };
  Object.entries(values || {}).forEach(([key,value]) => {
    if(ipKey.test(key)) add(value, key);
  });
  const sample = String(raw || '').slice(0,8000);
  const rawPatterns = [
    /\b(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?\b/g,
    /\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}(?:\/\d{1,3})?\b/g
  ];
  rawPatterns.forEach(re => {
    (sample.match(re) || []).forEach(v => add(v, 'raw text'));
  });
  return candidates.filter((c, idx, arr) => arr.findIndex(x => x.value === c.value) === idx);
}

function renderUsernameResult(target, detection) {
  const ambiguity = detection?.alternatives?.length
    ? ` Also matched: ${detection.alternatives.map(x => x.name).join(', ')}. Returning the first match by spreadsheet precedence.`
    : '';
  const split = usernameExtractionGuidance(detection);
  renderDetection(target, detection ? {
    cls: detection.cls,
    title: detection.formatName,
    confidence: detection.confidence + ' confidence',
    meta: [
      ['Value', detection.input],
      ['Category', detection.category],
      ['Domain included', split.domainIncluded],
      ['Domain component', split.domainComponent],
      ['Regex', detection.regex],
      ['Splunk named regex', split.splunkRegex],
      ['Template', detection.template],
      ['Precedence', detection.precedence || 'N/A']
    ],
    description: '',
    notes: `${detection.notes || ''}${split.note ? ' ' + split.note : ''}${ambiguity}`
  } : null, 'No username detected yet', 'Paste one username, principal, account ID, or SAML NameID Format URN and select Detect username.');
}

function renderIpResult(target, detection) {
  if(!detection){
    renderDetection(target, null, 'No IP address detected yet', 'Paste an IPv4 or IPv6 address and select Detect IP address.');
    return;
  }
  if(!detection.valid){
    renderValidationWarning(target, detection.error);
    return;
  }
  renderDetection(target, {
    cls: 'good',
    title: detection.normalised,
    confidence: detection.version,
    meta: [
      ['Category', detection.category],
      ['CIDR notation', detection.isCidr ? 'Yes' : 'No']
    ]
  }, '', '');
}

function detectStandaloneIp() {
  const value = $('#sampleIpAddress').value.trim();
  if(!value) { renderValidationWarning($('#ipResult'), 'Paste an IP address first.'); return; }
  renderIpResult($('#ipResult'), classifyIpAddress(value));
}

function renderRawIpFindings(raw, values) {
  const candidates = findIpCandidates(raw, values);
  if(!candidates.length) {
    renderDetection($('#rawIpResult'), {
      cls:'warn', title:'No IP address found in raw event', confidence:'Not detected',
      notes:'No IPv4/IPv6-like value matched the detector patterns.'
    }, '', '');
    $('#ipCandidates').innerHTML = '';
    return;
  }
  const preferred = candidates.find(c => /^src|source/i.test(c.key)) || candidates[0];
  renderIpResult($('#rawIpResult'), preferred.detection);
  $('#ipCandidates').innerHTML = candidates.slice(0,20).map(c => `
    <div class="item">
      <strong>${esc(c.key)}: <code>${esc(c.value)}</code></strong>
      <span class="small">${esc(c.detection.version)} | ${esc(c.detection.category)}</span>
    </div>
  `).join('');
  if(!$('#sampleIpAddress').value) $('#sampleIpAddress').value = preferred.value;
}

function extractWindowsEventXmlFields(raw){
  const values = {};
  const simpleField = tag => {
    const m = raw.match(new RegExp(`<${tag}\\b[^>]*>([^<]*)</${tag}>`, 'i'));
    if(m && m[1].trim()) values[tag] = m[1].trim();
  };
  ['EventID','Channel','Computer','Level','Task','Keywords','EventRecordID'].forEach(simpleField);
  const providerMatch = raw.match(/<Provider\b[^>]*\bName=["']([^"']+)["']/i);
  if(providerMatch) values['Provider.Name'] = providerMatch[1];
  const timeMatch = raw.match(/<TimeCreated\b[^>]*\bSystemTime=["']([^"']+)["']/i);
  if(timeMatch) values['TimeCreated.SystemTime'] = timeMatch[1];
  const userIdMatch = raw.match(/<Security\b[^>]*\bUserID=["']([^"']+)["']/i);
  if(userIdMatch) values['Security.UserID'] = userIdMatch[1];
  const dataRe = /<Data\s+Name=["']([^"']+)["'][^>]*>([^<]*)<\/Data>/gi;
  let m;
  while((m = dataRe.exec(raw))){
    if(m[2].trim()) values[m[1]] = m[2].trim();
  }
  return values;
}

function extractGenericXmlFields(raw){
  const values = {};
  const leafRe = /<([A-Za-z_][\w:.-]*)(?:\s[^>]*)?>([^<]*)<\/\1>/g;
  let m;
  while((m = leafRe.exec(raw))){
    const text = m[2].trim();
    if(text) values[m[1]] = text;
  }
  const attrRe = /\s([A-Za-z_][\w:-]*)=["']([^"']*)["']/g;
  while((m = attrRe.exec(raw))){
    if(/^xmlns/i.test(m[1]) || m[1] in values) continue;
    values[`@${m[1]}`] = m[2];
  }
  return values;
}

function detectRawFormat(raw) {
  let detected = '', extracted = [], values = {}, parseStatus = 'ok';
  const first = raw.split(/\r?\n/)[0] || '';
  try {
    values = flattenObject(JSON.parse(raw));
    extracted = Object.keys(values).sort();
    detected = 'Structured JSON';
  } catch(e) {
    if(/^\s*[\[{]/.test(raw)) parseStatus = 'malformed';
    const trimmed = raw.trim();
    const looksLikeXml = /^<\?xml/i.test(trimmed) || /^<[A-Za-z]/.test(trimmed);
    const isWindowsEventXml = looksLikeXml && (
      /xmlns=["']http:\/\/schemas\.microsoft\.com\/win\/2004\/08\/events\/event["']/i.test(raw) ||
      (/<EventID\b/i.test(raw) && /<Provider\b/i.test(raw))
    );

    if(/^<\d+>1\s+\d{4}-\d{2}-\d{2}T/.test(first)) detected = 'RFC 5424 structured syslog';
    else if(/^<\d+>/.test(first) && /\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}/.test(first)) detected = 'RFC 3164 syslog';
    else if(first.includes('CEF:')) detected = 'Common Event Format (CEF)';
    else if(isWindowsEventXml) detected = 'Windows Event XML';
    else if(looksLikeXml) detected = 'XML log';
    else if(/\w+=\S+/.test(first)) detected = 'Key-value formatted logs';
    else if(first.includes('\t')) detected = 'Tab-separated values (TSV)';
    else if(first.includes(',') && first.split(',').length > 2) detected = 'Comma-separated values (CSV)';
    else detected = parseStatus === 'malformed' ? 'Malformed structured payload' : 'Unstructured or unknown';

    if(detected === 'Windows Event XML'){
      values = extractWindowsEventXmlFields(raw);
      extracted = Object.keys(values).sort();
    } else if(detected === 'XML log'){
      values = extractGenericXmlFields(raw);
      extracted = Object.keys(values).sort();
    } else {
      values = {...parseKeyValues(raw), ...extractCefFields(raw)};
      extracted = Array.from(new Set([
        ...Object.keys(values),
        ...((raw.match(/(?:^|[\s,{])([A-Za-z_][\w.-]{1,80})(?:=|:)/g) || []).map(x => x.replace(/^[\s,{]+/,'').replace(/[=:]$/,'')))
      ])).sort();
    }
  }
  return { detected, extracted, values, parseStatus };
}

function slug(value){
  return String(value || '').trim().toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-+|-+$/g,'');
}

function suggestSourcetypeName(detected, values={}){
  const vendor = slug(values.deviceVendor || values.vendor || values.Vendor);
  const product = slug(values.deviceProduct || values.product || values.Product || values.application);
  if(detected === 'Common Event Format (CEF)') return vendor && product ? `${vendor}:${product}:cef` : 'vendor:product:cef';
  if(detected === 'Structured JSON') return vendor && product ? `${vendor}:${product}:json` : (product ? `${product}:json` : 'custom:json');
  if(detected === 'RFC 5424 structured syslog') return vendor ? `${vendor}:syslog` : 'syslog:rfc5424';
  if(detected === 'RFC 3164 syslog') return vendor ? `${vendor}:syslog` : 'syslog:rfc3164';
  if(detected === 'Key-value formatted logs') return vendor && product ? `${vendor}:${product}` : 'custom:kv';
  if(detected === 'Comma-separated values (CSV)') return 'custom:csv';
  if(detected === 'Tab-separated values (TSV)') return 'custom:tsv';
  if(detected === 'Windows Event XML') return 'xmlwineventlog';
  if(detected === 'XML log') return 'custom:xml';
  if(detected === 'Malformed structured payload') return 'custom:unverified';
  if(detected === 'Unstructured or unknown') return 'custom:unstructured';
  return 'custom:unknown';
}

function suggestFieldExtraction(detected, raw, values={}, extracted=[]){
  const base = (title, cls, propsConf, notes=[]) => ({title, cls, propsConf, notes});

  if(!detected){
    return base('Analyse a raw event to generate a suggestion', 'info', '', []);
  }
  if(detected === 'Structured JSON'){
    return base('Structured JSON - no manual extraction required', 'good',
      'INDEXED_EXTRACTIONS = json\nKV_MODE = none',
      ['JSON fields are extracted automatically at index time. KV_MODE = none avoids redundant automatic key-value extraction on top of the JSON parser.']);
  }
  if(detected === 'Common Event Format (CEF)'){
    const header = 'EXTRACT-cef_header = ^CEF:(?<cef_version>\\d+)\\|(?<device_vendor>[^|]*)\\|(?<device_product>[^|]*)\\|(?<device_version>[^|]*)\\|(?<signature_id>[^|]*)\\|(?<name>[^|]*)\\|(?<severity>[^|]*)\\|';
    return base('CEF header extraction + auto KV for extension fields', 'good',
      `${header}\nKV_MODE = auto`,
      ['The pipe-delimited CEF header is extracted explicitly; key=value extension fields after the header are handled by KV_MODE = auto. Confirm pipe characters escaped as \\| inside extension values are unescaped correctly downstream.']);
  }
  if(detected === 'Key-value formatted logs'){
    const sampleKey = normKey(extracted[0] || 'user') || 'user';
    return base('Key-value pairs - automatic KV extraction', 'warn',
      'KV_MODE = auto',
      [`KV_MODE = auto covers most key=value pairs, including quoted values. For high-volume sourcetypes, replace it with explicit EXTRACT statements per required field for better search performance, for example: EXTRACT-${sampleKey} = ${sampleKey}=(?<${sampleKey}>"[^"]*"|\\S+)`,
       'Disable KV_MODE = auto once explicit EXTRACT statements cover every required field, to avoid double extraction.']);
  }
  if(detected === 'Comma-separated values (CSV)'){
    const first = String(raw || '').split(/\r?\n/)[0] || '';
    const columnCount = Math.max(1, first.split(',').length);
    const fieldNames = Array.from({length: columnCount}, (_, i) => `field${i+1}`).join(',');
    return base(`Comma-separated values - ${columnCount} column(s) detected`, 'warn',
      `INDEXED_EXTRACTIONS = csv\nFIELD_NAMES = ${fieldNames}\nFIELD_DELIMITER = ,`,
      ['Replace the generated field1..fieldN names with the real column names from the source. Confirm quoted fields containing commas are handled and that the column count is stable across all events for this sourcetype.']);
  }
  if(detected === 'Tab-separated values (TSV)'){
    const first = String(raw || '').split(/\r?\n/)[0] || '';
    const columnCount = Math.max(1, first.split('\t').length);
    const fieldNames = Array.from({length: columnCount}, (_, i) => `field${i+1}`).join(',');
    return base(`Tab-separated values - ${columnCount} column(s) detected`, 'warn',
      `INDEXED_EXTRACTIONS = csv\nFIELD_NAMES = ${fieldNames}\nFIELD_DELIMITER = \\t`,
      ['Replace the generated field1..fieldN names with the real column names from the source and confirm the column count is stable across all events.']);
  }
  if(detected === 'RFC 5424 structured syslog'){
    return base('RFC 5424 header extraction', 'good',
      'EXTRACT-syslog5424_header = ^<(?<pri>\\d+)>(?<syslog_version>\\d+)\\s+(?<syslog_timestamp>\\S+)\\s+(?<hostname>\\S+)\\s+(?<app_name>\\S+)\\s+(?<procid>\\S+)\\s+(?<msgid>\\S+)\\s+',
      ['Extracts the fixed-position PRI, version, timestamp, host, app, procid, and msgid header fields. Structured-data and the free-text message payload need vendor-specific extraction after the header.']);
  }
  if(detected === 'RFC 3164 syslog'){
    return base('RFC 3164 header extraction', 'warn',
      'EXTRACT-syslog3164_header = ^<(?<pri>\\d+)>(?<syslog_timestamp>[A-Za-z]{3}\\s+\\d{1,2}\\s+\\d{2}:\\d{2}:\\d{2})\\s+(?<hostname>\\S+)\\s+(?<tag>[\\w./-]+)(?:\\[(?<pid>\\d+)\\])?:\\s*',
      ['Legacy syslog headers vary by vendor. Verify the tag/pid pattern against real samples and confirm year/timezone inference for the timestamp separately.']);
  }
  if(detected === 'Windows Event XML' || detected === 'XML log'){
    return base('XML - structured field extraction', 'warn',
      'KV_MODE = xml',
      ['KV_MODE = xml extracts attributes and element text as fields automatically. For Windows Event XML, confirm EventID, Computer, and EventData/Data name-value pairs are extracted as expected; add explicit EXTRACT/REPORT transforms for anything KV_MODE = xml misses.']);
  }
  return base(`${detected} - no built-in extraction template`, 'bad', '',
    ['Document the field layout from real samples and write explicit EXTRACT/REPORT transforms once the schema is confirmed.']);
}

function csvEscape(value){
  const v = String(value ?? '');
  return /[",\n]/.test(v) ? `"${v.replace(/"/g,'""')}"` : v;
}

function buildLookupSkeleton(fieldName, rawValues){
  const field = String(fieldName || '').trim() || 'field';
  const values = String(rawValues || '')
    .split(/\r?\n|,/)
    .map(v => v.trim())
    .filter(Boolean);
  const distinct = [...new Set(values)];
  if(!distinct.length) return {valid:false, error:'Enter at least one sample value, one per line or comma-separated.'};

  const outputField = `${field}_normalized`;
  const csv = [`${csvEscape(field)},${csvEscape(outputField)}`, ...distinct.map(v => `${csvEscape(v)},`)].join('\n') + '\n';
  const lookupName = `${field}_lookup`;
  const transformsConf = `[${lookupName}]\nfilename = ${lookupName}.csv`;
  const propsConf = `LOOKUP-${field} = ${lookupName} ${field} OUTPUT ${outputField}`;

  return {valid:true, fieldName:field, outputField, distinctValueCount:distinct.length, csv, lookupName, transformsConf, propsConf};
}

function buildCimFieldAliases(extracted=[]){
  const matches = REQUIRED_FIELDS
    .map(row => ({row, hits: findFields(extracted, row.names, row.id)}))
    .filter(x => x.hits.length);
  const lines = matches.map(({row, hits}) => `FIELDALIAS-${row.id} = ${hits[0]} AS ${row.id}`);
  return {matches, lines};
}

function combineFieldExtractionWithCim(fieldExtraction, cimAliases){
  if(!cimAliases || !cimAliases.lines.length) return fieldExtraction;
  const propsConf = [fieldExtraction.propsConf, ...cimAliases.lines].filter(Boolean).join('\n');
  const notes = [
    ...(fieldExtraction.notes || []),
    `${cimAliases.lines.length} CIM field alias suggestion(s) added based on matched required-field categories (${cimAliases.matches.map(m => m.row.category).join(', ')}).`
  ];
  return {...fieldExtraction, propsConf, notes};
}

function detectTruncationRisk(raw){
  const trimmed = String(raw || '').trim();
  if(!trimmed) return {looksTruncated:false, reasons:[]};
  const reasons = [];
  const countChar = ch => (trimmed.split(ch).length - 1);

  if(/^[\[{]/.test(trimmed)){
    const openBraces = countChar('{'), closeBraces = countChar('}');
    const openBrackets = countChar('['), closeBrackets = countChar(']');
    const quoteCount = (trimmed.match(/(?<!\\)"/g) || []).length;
    if(openBraces !== closeBraces) reasons.push(`Unbalanced curly braces (${openBraces} "{" vs ${closeBraces} "}").`);
    if(openBrackets !== closeBrackets) reasons.push(`Unbalanced square brackets (${openBrackets} "[" vs ${closeBrackets} "]").`);
    if(quoteCount % 2 !== 0) reasons.push(`Odd number of unescaped double quotes (${quoteCount}), suggesting a truncated string value.`);
    if(!/[\]}]$/.test(trimmed)) reasons.push('Sample does not end with a closing "}" or "]".');
  }
  if(/[,:]\s*$/.test(trimmed)) reasons.push('Sample ends with a trailing comma or colon, suggesting the event was cut off mid-field.');

  return {looksTruncated: reasons.length > 0, reasons};
}

const INVISIBLE_CHAR_NAMES = {
  ' ': 'non-breaking space (U+00A0)',
  '​': 'zero-width space (U+200B)',
  '‌': 'zero-width non-joiner (U+200C)',
  '‍': 'zero-width joiner (U+200D)',
  '﻿': 'byte order mark / zero-width no-break space (U+FEFF)',
  ' ': 'line separator (U+2028)',
  ' ': 'paragraph separator (U+2029)'
};

function detectEncodingIssues(raw){
  const text = String(raw ?? '');
  const issues = [];
  if(!text) return {hasIssues:false, issues};

  if(text.charCodeAt(0) === 0xFEFF){
    issues.push({cls:'warn', message:'Sample starts with a UTF-8/UTF-16 byte order mark (BOM). Some parsers include the BOM in the first extracted field unless it is stripped.'});
  }

  const replacementCount = (text.match(/�/g) || []).length;
  if(replacementCount > 0){
    issues.push({cls:'bad', message:`${replacementCount} Unicode replacement character(s) (U+FFFD) found, indicating the text was decoded with the wrong character encoding somewhere upstream.`});
  }

  const crlf = (text.match(/\r\n/g) || []).length;
  const bareLf = (text.match(/(?<!\r)\n/g) || []).length;
  const bareCr = (text.match(/\r(?!\n)/g) || []).length;
  const lineEndingKinds = [crlf > 0 && 'CRLF', bareLf > 0 && 'LF', bareCr > 0 && 'bare CR'].filter(Boolean);
  if(lineEndingKinds.length > 1){
    issues.push({cls:'warn', message:`Mixed line endings detected (${lineEndingKinds.join(', ')}: ${crlf} CRLF, ${bareLf} LF, ${bareCr} CR). LINE_BREAKER patterns anchored on one style may miss events using another.`});
  }

  const controlChars = [...text].filter(ch => {
    const code = ch.codePointAt(0);
    return (code < 32 && ch !== '\t' && ch !== '\n' && ch !== '\r') || (code >= 127 && code <= 159);
  });
  if(controlChars.length){
    const codes = [...new Set(controlChars.map(ch => 'U+' + ch.codePointAt(0).toString(16).toUpperCase().padStart(4,'0')))];
    issues.push({cls:'bad', message:`${controlChars.length} non-printable control character(s) found (${codes.slice(0,6).join(', ')}${codes.length > 6 ? ', ...' : ''}). These often break regex-based field extraction.`});
  }

  Object.entries(INVISIBLE_CHAR_NAMES).forEach(([ch, name]) => {
    const searchText = ch === '﻿' ? text.slice(1) : text;
    const count = searchText.split(ch).length - 1;
    if(count > 0) issues.push({cls:'warn', message:`${count} occurrence(s) of ${name} found. These are invisible in most editors and can silently break exact-match regex or delimiter parsing.`});
  });

  return {hasIssues: issues.length > 0, issues};
}

function buildPropsConfBundle(state={}){
  const sourcetype = state.sourcetypeName || 'custom:sourcetype';
  const lines = [`[${sourcetype}]`];
  const ts = state.timestampProps || {};
  if(ts.maxLookahead) lines.push(`MAX_TIMESTAMP_LOOKAHEAD = ${ts.maxLookahead}`);
  if(ts.timeFormat) lines.push(`TIME_FORMAT = ${ts.timeFormat}`);
  if(ts.timePrefix) lines.push(`TIME_PREFIX = ${ts.timePrefix}`);
  const lb = state.lineBreakProps || {};
  if(lb.shouldLineMerge) lines.push(`SHOULD_LINEMERGE = ${lb.shouldLineMerge}`);
  if(lb.lineBreaker) lines.push(`LINE_BREAKER = ${lb.lineBreaker}`);
  const extraction = state.fieldExtraction || {};
  if(extraction.propsConf) lines.push(...extraction.propsConf.split('\n').filter(Boolean));
  return lines.join('\n') + '\n';
}

function buildRawEventReport(raw){
  const trimmed = String(raw || '').trim();
  if(!trimmed) return null;

  const result = detectRawFormat(trimmed);
  const guidance = logFormatGuidance(result.detected, result.parseStatus, result.extracted.length);
  const truncation = detectTruncationRisk(trimmed);

  const timestampCandidates = findTimestampCandidates(trimmed, result.values);
  const preferredTimestamp = timestampCandidates.find(c => /event|created|occurred|timecreated|utctime|timestamp/i.test(c.key) && !/@timestamp|_time|index|ingest|received/i.test(c.key)) || timestampCandidates[0] || null;

  const usernameCandidates = findUsernameCandidates(trimmed, result.values);
  const preferredUsername = usernameCandidates.find(c => /user|principal|upn|account|identity|nameid/i.test(c.key)) || usernameCandidates[0] || null;

  const ipCandidates = findIpCandidates(trimmed, result.values);
  const preferredIp = ipCandidates.find(c => /^src|source/i.test(c.key)) || ipCandidates[0] || null;

  const lineBreak = detectLineBreakFormat(trimmed);
  const sourcetypeName = suggestSourcetypeName(result.detected, result.values);
  const cimAliases = buildCimFieldAliases(result.extracted);
  const fieldExtraction = combineFieldExtractionWithCim(suggestFieldExtraction(result.detected, trimmed, result.values, result.extracted), cimAliases);
  const categoryMatches = REQUIRED_FIELDS
    .map(row => ({row, hits: findFields(result.extracted, row.names, row.id)}))
    .filter(x => x.hits.length)
    .map(x => ({category: x.row.category, fields: x.hits}));

  return {
    raw: trimmed,
    generatedAt: new Date().toISOString(),
    logFormat: {detected: result.detected, parseStatus: result.parseStatus, guidance},
    truncation,
    sourcetypeName,
    timestamp: preferredTimestamp ? {value: preferredTimestamp.value, ...preferredTimestamp.detection} : null,
    username: preferredUsername ? {value: preferredUsername.value, ...preferredUsername.detection} : null,
    ip: preferredIp ? {value: preferredIp.value, ...preferredIp.detection} : null,
    lineBreak,
    extractedFields: result.extracted,
    categoryMatches,
    fieldExtraction
  };
}

function buildAnalysisReportMarkdown(report){
  if(!report) return '';
  const lines = [];
  lines.push('# LENS Analysis Report');
  lines.push('');
  lines.push(`Generated: ${report.generatedAt}`);
  lines.push('');
  lines.push('## Raw Event Sample');
  lines.push('```');
  lines.push(report.raw);
  lines.push('```');
  lines.push('');
  lines.push('## Log Format');
  lines.push(`- Detected format: ${report.logFormat.detected || 'Unknown'}`);
  lines.push(`- Confidence: ${report.logFormat.guidance.confidence}`);
  lines.push(`- Suggested sourcetype: \`${report.sourcetypeName}\``);
  lines.push(`- Splunk handling: ${report.logFormat.guidance.splunk}`);
  lines.push(`- Validation: ${report.logFormat.guidance.validation}`);
  if(report.truncation.looksTruncated){
    lines.push(`- **Possible truncation detected**: ${report.truncation.reasons.join(' ')}`);
  }
  lines.push('');
  lines.push('## Timestamp');
  if(report.timestamp){
    lines.push(`- Value: \`${report.timestamp.value}\``);
    lines.push(`- Format: ${report.timestamp.formatName}`);
    lines.push(`- Splunk TIME_FORMAT: \`${report.timestamp.timeFormat}\``);
    lines.push(`- Timezone: ${report.timestamp.timezone} (${report.timestamp.utcStatus})`);
  } else {
    lines.push('- No timestamp detected.');
  }
  lines.push('');
  lines.push('## Username / Principal');
  if(report.username){
    lines.push(`- Value: \`${report.username.value}\``);
    lines.push(`- Format: ${report.username.formatName} (${report.username.category})`);
  } else {
    lines.push('- No username detected.');
  }
  lines.push('');
  lines.push('## IP / Network Address');
  if(report.ip){
    lines.push(`- Value: \`${report.ip.value}\``);
    lines.push(`- Version: ${report.ip.version} | Category: ${report.ip.category}`);
  } else {
    lines.push('- No IP address detected.');
  }
  lines.push('');
  lines.push('## Line Breaking');
  lines.push(`- SHOULD_LINEMERGE: ${report.lineBreak.shouldLineMerge}`);
  lines.push(`- LINE_BREAKER: \`${report.lineBreak.lineBreaker || ''}\``);
  lines.push('');
  lines.push('## Extracted Fields');
  lines.push(report.extractedFields.length ? report.extractedFields.map(f => `\`${f}\``).join(', ') : '_None extracted._');
  lines.push('');
  lines.push('## Likely SIEM / CIM Categories');
  if(report.categoryMatches.length){
    report.categoryMatches.forEach(m => lines.push(`- **${m.category}**: ${m.fields.join(', ')}`));
  } else {
    lines.push('_No category matches._');
  }
  lines.push('');
  lines.push('## Suggested props.conf');
  lines.push('```');
  lines.push(`[${report.sourcetypeName}]`);
  if(report.timestamp && report.timestamp.timeFormat) lines.push(`TIME_FORMAT = ${report.timestamp.timeFormat}`);
  lines.push(`SHOULD_LINEMERGE = ${report.lineBreak.shouldLineMerge}`);
  if(report.lineBreak.lineBreaker) lines.push(`LINE_BREAKER = ${report.lineBreak.lineBreaker}`);
  if(report.fieldExtraction.propsConf) lines.push(report.fieldExtraction.propsConf);
  lines.push('```');
  return lines.join('\n') + '\n';
}

const TIME_FORMAT_TOKEN_REGEX = {
  '%:z': '[+-]\\d{2}:\\d{2}',
  '%Y': '\\d{4}', '%y': '\\d{2}',
  '%m': '(?:0[1-9]|1[0-2])', '%d': '(?:0[1-9]|[12]\\d|3[01])', '%e': '\\s?\\d{1,2}',
  '%H': '(?:[01]\\d|2[0-3])', '%I': '(?:0[1-9]|1[0-2])', '%M': '[0-5]\\d', '%S': '(?:[0-5]\\d|60)',
  '%j': '\\d{1,3}', '%p': '[AaPp][Mm]',
  '%Q': '\\d+', '%f': '\\d{1,9}', '%N': '\\d{1,9}',
  '%z': '[+-]\\d{4}', '%Z': '[A-Za-z]+',
  '%a': '[A-Za-z]{3}', '%A': '[A-Za-z]+', '%b': '[A-Za-z]{3}', '%B': '[A-Za-z]+',
  '%s': '\\d+', '%n': '\\s', '%t': '\\s', '%%': '%',
  '%G': '\\d{4}', '%V': '\\d{2}', '%u': '\\d', '%g': '\\d{2}'
};

function escapeRegexChar(ch){
  return /[.*+?^${}()|[\]\\]/.test(ch) ? '\\' + ch : ch;
}

function timeFormatToRegex(formatText){
  const text = String(formatText || '');
  const tokens = Object.keys(TIME_FORMAT_TOKEN_REGEX).sort((a,b) => b.length - a.length);
  let pattern = '', i = 0;
  const unsupported = [];
  while(i < text.length){
    if(text[i] === '%'){
      const tok = tokens.find(t => text.startsWith(t, i));
      if(tok){
        pattern += TIME_FORMAT_TOKEN_REGEX[tok];
        i += tok.length;
        continue;
      }
      unsupported.push(text.slice(i, i+2));
      pattern += escapeRegexChar('%');
      i += 1;
      continue;
    }
    pattern += escapeRegexChar(text[i]);
    i += 1;
  }
  return {pattern, unsupported};
}

function validateTimeFormatAgainstSample(sample, timeFormat, timePrefix, maxLookahead){
  if(!timeFormat) return {checked:false};
  const {pattern, unsupported} = timeFormatToRegex(timeFormat);
  const text = String(sample || '');
  let regex;
  try {
    regex = new RegExp((timePrefix ? String(timePrefix) : '') + '(' + pattern + ')');
  } catch(e) {
    return {checked:true, valid:false, unsupported, error:`TIME_PREFIX or TIME_FORMAT produced an invalid regular expression: ${e.message}`};
  }
  const match = text.match(regex);
  if(!match){
    return {checked:true, valid:false, unsupported, error: timePrefix ? 'TIME_PREFIX + TIME_FORMAT did not match anywhere in the sample.' : 'TIME_FORMAT did not match anywhere in the sample.'};
  }
  const matchedValue = match[1];
  const endIndex = match.index + match[0].length;
  const withinLookahead = maxLookahead ? endIndex <= Number(maxLookahead) : null;
  const warnings = [];
  if(unsupported.length) warnings.push(`Unrecognised TIME_FORMAT token(s): ${unsupported.join(', ')} (treated as literal text).`);
  if(withinLookahead === false) warnings.push(`Match ends at position ${endIndex}, beyond MAX_TIMESTAMP_LOOKAHEAD = ${maxLookahead}.`);
  return {checked:true, valid:true, matchedValue, matchIndex:match.index, endIndex, withinLookahead, unsupported, warning: warnings.join(' ')};
}

function parsePropsConfText(text){
  const settings = {};
  let stanza = null;
  String(text || '').split(/\r?\n/).forEach(line => {
    const trimmed = line.trim();
    if(!trimmed || trimmed.startsWith('#')) return;
    const stanzaMatch = trimmed.match(/^\[(.+)\]$/);
    if(stanzaMatch){ stanza = stanzaMatch[1]; return; }
    const kvMatch = trimmed.match(/^([^=]+?)\s*=\s*(.*)$/);
    if(kvMatch) settings[kvMatch[1].trim()] = kvMatch[2];
  });
  return {stanza, settings};
}

function diffPropsConf(textA, textB){
  const a = parsePropsConfText(textA).settings;
  const b = parsePropsConfText(textB).settings;
  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
  const added = [], removed = [], changed = [], unchanged = [];
  keys.forEach(key => {
    const inA = Object.prototype.hasOwnProperty.call(a, key);
    const inB = Object.prototype.hasOwnProperty.call(b, key);
    if(inA && !inB) removed.push({key, before:a[key]});
    else if(!inA && inB) added.push({key, after:b[key]});
    else if(a[key] !== b[key]) changed.push({key, before:a[key], after:b[key]});
    else unchanged.push({key, value:a[key]});
  });
  const byKey = (x,y) => x.key.localeCompare(y.key);
  return {
    added: added.sort(byKey),
    removed: removed.sort(byKey),
    changed: changed.sort(byKey),
    unchanged: unchanged.sort(byKey),
    hasDiff: added.length > 0 || removed.length > 0 || changed.length > 0
  };
}

function validatePropsConf(propsText, sampleText){
  const {stanza, settings} = parsePropsConfText(propsText);
  const keys = Object.keys(settings);
  if(!keys.length) return {stanza, checks:[], error:'No recognisable key = value settings found. Paste a props.conf stanza such as TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%QZ'};

  const sample = String(sampleText || '');
  const firstLine = sample.split(/\r?\n/)[0] || sample;
  const checks = [];

  if(settings.TIME_FORMAT){
    const result = validateTimeFormatAgainstSample(firstLine, settings.TIME_FORMAT, settings.TIME_PREFIX, settings.MAX_TIMESTAMP_LOOKAHEAD);
    checks.push({
      key:'TIME_FORMAT',
      cls: result.valid ? (result.warning ? 'warn' : 'good') : 'bad',
      message: result.valid
        ? `Matched \`${result.matchedValue}\` in the sample.${result.warning ? ' ' + result.warning : ''}`
        : (result.error || 'Could not validate against the sample.')
    });
  }

  if(settings.LINE_BREAKER){
    let regex, error;
    try { regex = new RegExp(settings.LINE_BREAKER, 'g'); } catch(e){ error = e.message; }
    if(error){
      checks.push({key:'LINE_BREAKER', cls:'bad', message:`Invalid regular expression: ${error}`});
    } else {
      const boundaryCount = (sample.match(regex) || []).length;
      const eventCount = boundaryCount + 1;
      checks.push({
        key:'LINE_BREAKER',
        cls: boundaryCount > 0 ? 'good' : 'warn',
        message: boundaryCount > 0
          ? `Splits the sample into an estimated ${eventCount} event(s).`
          : 'Did not match anywhere in the sample. Paste a multi-event sample with a real event boundary to confirm.'
      });
    }
  }

  ['EXTRACT-', 'REPORT-'].forEach(prefix => {
    Object.keys(settings).filter(k => k.startsWith(prefix)).forEach(key => {
      if(prefix === 'REPORT-'){
        checks.push({key, cls:'info', message:'REPORT- settings reference a transforms.conf stanza, which this validator cannot check independently.'});
        return;
      }
      let regex, error;
      try { regex = new RegExp(settings[key]); } catch(e){ error = e.message; }
      if(error){ checks.push({key, cls:'bad', message:`Invalid regular expression: ${error}`}); return; }
      const match = sample.match(regex);
      if(!match){ checks.push({key, cls:'warn', message:'Did not match the sample event.'}); return; }
      const named = match.groups ? Object.entries(match.groups).map(([k,v]) => `${k}=${v}`).join(', ') : '';
      checks.push({
        key, cls:'good',
        message: named ? `Matched. Captured fields: ${named}.` : 'Matched, but the pattern has no named capture groups (Splunk EXTRACT requires named groups to produce fields).'
      });
    });
  });

  if(settings.KV_MODE){
    const mode = settings.KV_MODE.trim().toLowerCase();
    const valid = ['none','auto','auto_escaped','multi','json','xml'].includes(mode);
    checks.push({key:'KV_MODE', cls: valid ? 'good' : 'bad', message: valid ? 'Recognised KV_MODE value.' : `Unrecognised KV_MODE value "${settings.KV_MODE}". Expected one of none, auto, auto_escaped, multi, json, xml.`});
  }

  if(settings.INDEXED_EXTRACTIONS){
    const mode = settings.INDEXED_EXTRACTIONS.trim().toLowerCase();
    const valid = ['json','csv','w3c','tsv','psv'].includes(mode);
    checks.push({key:'INDEXED_EXTRACTIONS', cls: valid ? 'good' : 'bad', message: valid ? 'Recognised INDEXED_EXTRACTIONS value.' : `Unrecognised INDEXED_EXTRACTIONS value "${settings.INDEXED_EXTRACTIONS}".`});
  }

  Object.keys(settings).filter(k => k.startsWith('FIELDALIAS-')).forEach(key => {
    const valid = /^\S+\s+AS\s+\S+/i.test(settings[key].trim());
    checks.push({key, cls: valid ? 'good' : 'bad', message: valid ? 'Recognised "<field> AS <alias>" syntax.' : 'Expected syntax: <field> AS <alias> [<field2> AS <alias2> ...].'});
  });

  const knownKeys = new Set(['TIME_FORMAT','TIME_PREFIX','MAX_TIMESTAMP_LOOKAHEAD','LINE_BREAKER','SHOULD_LINEMERGE','KV_MODE','INDEXED_EXTRACTIONS','FIELD_DELIMITER','FIELD_NAMES','FIELD_QUOTE']);
  Object.keys(settings).forEach(key => {
    const known = knownKeys.has(key) || key.startsWith('EXTRACT-') || key.startsWith('REPORT-') || key.startsWith('FIELDALIAS-') || key.startsWith('EVAL-');
    if(!known) checks.push({key, cls:'info', message:'Setting is not validated by this tool.'});
  });

  return {stanza, checks};
}

function checkBatchConsistency(rawText){
  const lines = String(rawText || '').split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  if(!lines.length) return null;

  const events = lines.map((line, i) => {
    const {detected, extracted, values} = detectRawFormat(line);
    const preferred = findTimestampCandidates(line, values)[0] || null;
    return {
      index: i + 1,
      line,
      format: detected,
      fields: extracted,
      timestampFormat: preferred ? preferred.detection.formatName : null,
      timezone: preferred ? preferred.detection.timezone : null,
      utcStatus: preferred ? preferred.detection.utcStatus : null
    };
  });

  const countBy = (arr, keyFn) => {
    const counts = new Map();
    arr.forEach(item => { const k = keyFn(item); if(k === null || k === undefined) return; counts.set(k, (counts.get(k) || 0) + 1); });
    return counts;
  };
  const mode = counts => { let best = null, bestCount = -1; for(const [k,v] of counts) if(v > bestCount){ best = k; bestCount = v; } return best; };

  const formatCounts = countBy(events, e => e.format);
  const dominantFormat = mode(formatCounts);
  const formatDrift = events.filter(e => e.format !== dominantFormat);

  const sameFormatEvents = events.filter(e => e.format === dominantFormat);
  const fieldSets = sameFormatEvents.map(e => new Set(e.fields));
  const fieldPresenceCounts = new Map();
  fieldSets.forEach(set => set.forEach(f => fieldPresenceCounts.set(f, (fieldPresenceCounts.get(f) || 0) + 1)));
  const allFieldsSeen = [...fieldPresenceCounts.keys()].sort();
  const commonFields = allFieldsSeen.filter(f => fieldPresenceCounts.get(f) === sameFormatEvents.length);
  const fieldDrift = sameFormatEvents
    .map((e, i) => ({index: e.index, missing: allFieldsSeen.filter(f => !fieldSets[i].has(f))}))
    .filter(d => d.missing.length);

  const tsFormatCounts = countBy(events, e => e.timestampFormat);
  const dominantTsFormat = mode(tsFormatCounts);
  const tsDrift = events.filter(e => e.timestampFormat && e.timestampFormat !== dominantTsFormat);
  const noTimestamp = events.filter(e => !e.timestampFormat);

  const tzStatusCounts = countBy(events, e => e.utcStatus);
  const tzDrift = events.filter(e => e.utcStatus === 'Timezone missing');

  const problems = formatDrift.length + fieldDrift.length + tsDrift.length + noTimestamp.length;
  const verdict = problems === 0 ? 'good' : ((formatDrift.length || noTimestamp.length === events.length) ? 'bad' : 'warn');

  return {
    totalEvents: events.length, events,
    dominantFormat, formatCounts: [...formatCounts.entries()], formatDrift,
    commonFields, fieldDrift,
    dominantTsFormat, tsFormatCounts: [...tsFormatCounts.entries()], tsDrift, noTimestamp,
    tzStatusCounts: [...tzStatusCounts.entries()], tzDrift,
    verdict
  };
}

function buildSplSearches({sourcetypeName, indexName, fields=[]}={}){
  const index = indexName && indexName.trim() ? indexName.trim() : '<index>';
  const sourcetype = sourcetypeName && sourcetypeName.trim() ? sourcetypeName.trim() : 'custom:sourcetype';
  const topFields = fields.filter(Boolean).slice(0,12);
  const ingestionCheck = `index=${index} sourcetype="${sourcetype}"\n| head 20`;
  const fieldTable = topFields.length
    ? `index=${index} sourcetype="${sourcetype}"\n| table _time, ${topFields.join(', ')}\n| head 20`
    : `index=${index} sourcetype="${sourcetype}"\n| table _time, _raw\n| head 20`;
  const timestampSanity = `index=${index} sourcetype="${sourcetype}"\n| eval index_lag_sec = _indextime - _time\n| stats count avg(index_lag_sec) as avg_lag_sec max(index_lag_sec) as max_lag_sec by sourcetype`;
  return {ingestionCheck, fieldTable, timestampSanity};
}

function buildInputsConfStanza({sourcetypeName, indexName, monitorPath}={}){
  const index = indexName && indexName.trim() ? indexName.trim() : '<index>';
  const sourcetype = sourcetypeName && sourcetypeName.trim() ? sourcetypeName.trim() : 'custom:sourcetype';
  const path = monitorPath && monitorPath.trim() ? monitorPath.trim() : '/path/to/logs/*.log';
  return `[monitor://${path}]\nindex = ${index}\nsourcetype = ${sourcetype}\ndisabled = false`;
}

function estimateEventBytes(raw){
  return typeof TextEncoder !== 'undefined' ? new TextEncoder().encode(String(raw || '')).length : String(raw || '').length;
}

function buildHecPayload({raw, detectedFormat, sourcetypeName, indexName, timestampEpochSeconds}={}){
  let eventValue = raw;
  if(detectedFormat === 'Structured JSON'){
    try { eventValue = JSON.parse(raw); } catch(e) { eventValue = raw; }
  }
  const payload = {event: eventValue, sourcetype: sourcetypeName && sourcetypeName.trim() ? sourcetypeName.trim() : 'custom:sourcetype'};
  if(indexName && indexName.trim()) payload.index = indexName.trim();
  if(Number.isFinite(timestampEpochSeconds)) payload.time = timestampEpochSeconds;
  return JSON.stringify(payload, null, 2);
}

function buildHecCurlCommand(hecJson, {hecUrl, hecToken}={}){
  const url = hecUrl && hecUrl.trim() ? hecUrl.trim() : 'https://<splunk-host>:8088/services/collector/event';
  const token = hecToken && hecToken.trim() ? hecToken.trim() : '<HEC-token>';
  const escapedJson = String(hecJson || '').replace(/'/g, `'\\''`);
  return `curl -k "${url}" \\\n  -H "Authorization: Splunk ${token}" \\\n  -d '${escapedJson}'`;
}

const CIM_FIELD_ALIASES = {
  action: ['action','event.action','result','outcome'],
  app: ['app','application','service'],
  dest: ['dest','dest_ip','dst','dst_ip','destination','target'],
  dest_port: ['dest_port','dport','destination_port'],
  src: ['src','src_ip','source','source_ip'],
  src_port: ['src_port','sport','source_port'],
  user: ['user','username','user_name','account'],
  signature: ['signature','signature_id','rule','rule_name'],
  vendor_product: ['vendor_product','product','vendor'],
  bytes: ['bytes','bytes_total'],
  protocol: ['protocol','proto'],
  transport: ['transport'],
  http_method: ['http_method','method'],
  http_user_agent: ['http_user_agent','user_agent','useragent'],
  status: ['status','status_code','result_code'],
  url: ['url','uri','request_url'],
  file_name: ['file_name','filename'],
  file_path: ['file_path','filepath','path'],
  change_type: ['change_type','changetype'],
  object: ['object','object_name'],
  result: ['result','outcome'],
  process: ['process','command_line','cmdline'],
  process_name: ['process_name','image'],
  process_id: ['process_id','pid'],
  parent_process_name: ['parent_process_name','parentimage']
};

const CIM_DATA_MODELS = [
  {id:'authentication', name:'Authentication', description:'Successful and failed authentication events.', fields:['action','app','dest','src','user','signature','vendor_product']},
  {id:'network_traffic', name:'Network Traffic', description:'Firewall/network traffic allow or deny events.', fields:['action','app','bytes','dest','dest_port','src','src_port','protocol','transport','vendor_product']},
  {id:'web', name:'Web', description:'HTTP/web proxy and web server traffic.', fields:['action','bytes','dest','http_method','http_user_agent','status','url','src','user']},
  {id:'malware', name:'Malware', description:'Anti-virus/EDR malware detection and remediation events.', fields:['action','dest','file_name','file_path','signature','vendor_product']},
  {id:'change', name:'Change', description:'Configuration, account, and endpoint change events.', fields:['action','change_type','dest','object','result','status','user']},
  {id:'endpoint_processes', name:'Endpoint - Processes', description:'Process creation and termination events.', fields:['action','dest','process','process_name','process_id','parent_process_name','user']}
];

function findCimFieldMatches(extracted, field){
  const expected = CIM_FIELD_ALIASES[field] || [field];
  return findFields(extracted, expected.join(','), '');
}

function checkCimCompliance(modelId, extracted=[]){
  const model = CIM_DATA_MODELS.find(m => m.id === modelId);
  if(!model) return null;
  const present = [], missing = [];
  model.fields.forEach(field => {
    const hits = findCimFieldMatches(extracted, field);
    if(hits.length) present.push({field, matched:hits}); else missing.push(field);
  });
  const coverage = model.fields.length ? Math.round((present.length / model.fields.length) * 100) : 0;
  return {model, present, missing, coverage};
}

function estimateIndexVolume({avgEventBytes, eventsPerSecond, eventsPerDay, retentionDays}={}){
  const bytesPerEvent = Number(avgEventBytes);
  if(!Number.isFinite(bytesPerEvent) || bytesPerEvent <= 0) return {valid:false, error:'Enter a positive average event size in bytes.'};

  let dailyEvents;
  if(eventsPerDay !== undefined && eventsPerDay !== null && String(eventsPerDay).trim() !== ''){
    dailyEvents = Number(eventsPerDay);
  } else if(eventsPerSecond !== undefined && eventsPerSecond !== null && String(eventsPerSecond).trim() !== ''){
    dailyEvents = Number(eventsPerSecond) * 86400;
  } else {
    return {valid:false, error:'Enter either events per second or events per day.'};
  }
  if(!Number.isFinite(dailyEvents) || dailyEvents <= 0) return {valid:false, error:'Events per second/day must be a positive number.'};

  const dailyBytes = bytesPerEvent * dailyEvents;
  const GB = 1024 ** 3;
  const retention = Number(retentionDays);
  const hasRetention = Number.isFinite(retention) && retention > 0;

  return {
    valid:true,
    dailyEvents: Math.round(dailyEvents),
    dailyRawGB: dailyBytes / GB,
    monthlyRawGB: (dailyBytes * 30) / GB,
    annualRawGB: (dailyBytes * 365) / GB,
    estimatedOnDiskDailyGB: (dailyBytes * 0.5) / GB,
    retentionDays: hasRetention ? retention : null,
    estimatedRetainedOnDiskGB: hasRetention ? (dailyBytes * 0.5 * retention) / GB : null
  };
}

function renderExtractedFields(extracted) {
  $('#fieldList').innerHTML = extracted.length
    ? extracted.slice(0,80).map(f => `<div class="item"><code>${esc(f)}</code></div>`).join('')
    : '<div class="item small">No fields extracted yet.</div>';
  const matches = REQUIRED_FIELDS.map(row => ({row, hits:findFields(extracted, row.names, row.id)})).filter(x => x.hits.length);
  $('#fieldCategoryList').innerHTML = matches.length
    ? matches.map(x => `<div class="item"><strong>${esc(x.row.category)}</strong><span class="small">${esc(x.hits.slice(0,8).join(', '))}</span></div>`).join('')
    : '<div class="item small">No category matches yet.</div>';
}

function renderRawTimestampFindings(raw, values) {
  const candidates = findTimestampCandidates(raw, values);
  if(!candidates.length) {
    renderDetection($('#rawTimestampResult'), {
      cls:'warn', title:'No timestamp found in raw event', confidence:'Not detected',
      notes:'No timestamp-like value matched the detector patterns. Check whether the sample is truncated, hidden inside escaped text, or uses a vendor-specific format.'
    }, '', '');
    $('#timestampCandidates').innerHTML = '';
    return;
  }
  const preferred = candidates.find(c => /event|created|occurred|timecreated|utctime|timestamp/i.test(c.key) && !/@timestamp|_time|index|ingest|received/i.test(c.key)) || candidates[0];
  renderTimestampResult($('#rawTimestampResult'), preferred.detection);
  $('#timestampCandidates').innerHTML = candidates.slice(0,20).map(c => `
    <div class="item">
      <strong>${esc(c.key)}: <code>${esc(c.value)}</code></strong>
      <span class="small">${esc(c.detection.formatName)} | Splunk <code>${esc(c.detection.timeFormat)}</code> | ${esc(c.detection.precision)} | ${esc(c.detection.timezone)}</span>
    </div>
  `).join('');
  if(!$('#sampleDateTime').value) $('#sampleDateTime').value = preferred.value;
  renderPropsConfSuggestion(preferred.detection);
}

function findUsernameCandidates(raw, values={}) {
  const candidates = [];
  const userKey = /(^|[._-])(user|username|principal|upn|account|identity|actor|subject|targetuser|suser|duser|src_user|dest_user|nameid|arn|sid|assumedrole|assumed_role)($|[._-])/i;
  const add = (value, key='sample') => {
    if(value === null || value === undefined || value === '') return;
    const text = String(value).trim();
    if(!text || text.length > 320) return;
    const detection = detectUsernameFormat(text);
    if(detection && detection.formatName !== 'Unknown or unsupported username format') candidates.push({key, value:text, detection});
  };
  Object.entries(values || {}).forEach(([key,value]) => {
    if(userKey.test(key) || /\\|@|^S-1-|^arn:aws:|^urn:oasis:names:tc:SAML:/i.test(String(value || ''))) add(value, key);
  });
  const sample = String(raw || '').slice(0,8000);
  const rawPatterns = [
    /urn:oasis:names:tc:SAML:[12]\.[01]:nameid-format:[A-Za-z]+/g,
    /arn:aws:(?:iam|sts)::\d{12}:[A-Za-z0-9+=,.@_:\/-]+/g,
    /\bS-1-\d+(?:-\d+)+\b/g,
    /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g,
    /(?:^|[\s"'])\.\\[^\\\/@\s"']+/g,
    /(?:^|[\s"'])[A-Za-z0-9.-]+\\[^\\\/@\s"']+/g,
    /\b[^@\s\\\/"']+@[^@\s\\\/"']+\.[^@\s\\\/"']+\b/g,
    /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    /'[^']*'@'[^']*'/g
  ];
  rawPatterns.forEach(re => {
    (sample.match(re) || []).forEach(v => add(v.trim().replace(/^["']|["']$/g,''), 'raw text'));
  });
  return candidates.filter((c, idx, arr) => arr.findIndex(x => x.value === c.value && x.detection.formatName === c.detection.formatName) === idx);
}

function renderRawUsernameFindings(raw, values) {
  const candidates = findUsernameCandidates(raw, values);
  if(!candidates.length) {
    renderDetection($('#rawUsernameResult'), {
      cls:'warn',
      title:'No username found in raw event',
      confidence:'Not detected',
      notes:'No user-like field or value matched the username format patterns. Check whether identity appears only in free text, display-name form, or a source-specific field.'
    }, '', '');
    $('#usernameCandidates').innerHTML = '';
    return;
  }
  const preferred = candidates.find(c => /user|principal|upn|account|identity|nameid/i.test(c.key)) || candidates[0];
  renderUsernameResult($('#rawUsernameResult'), preferred.detection);
  $('#usernameCandidates').innerHTML = candidates.slice(0,20).map(c => `
    <div class="item">
      <strong>${esc(c.key)}: <code>${esc(c.value)}</code></strong>
      <span class="small">${esc(c.detection.formatName)} | ${esc(c.detection.category)} | ${esc(c.detection.confidence)} confidence</span>
    </div>
  `).join('');
  if(!$('#sampleUsername').value) $('#sampleUsername').value = preferred.value;
}

function renderStackTraceNote(target, raw) {
  if(!target) return;
  const detection = detectStackTrace(raw);
  if(!detection.detected){
    target.hidden = true;
    target.innerHTML = '';
    return;
  }
  target.hidden = false;
  target.innerHTML = `
    <div class="detectTitle">Stack trace detected: ${esc(detection.language)}</div>
    <div class="detectNotes">${esc(detection.notes)}</div>
    <pre>SHOULD_LINEMERGE = ${esc(detection.shouldLineMerge)}
LINE_BREAKER = ${esc(detection.lineBreaker)}</pre>
  `;
}

function renderRawLineBreakFindings(raw) {
  const detection = detectLineBreakFormat(raw);
  renderLineBreakResult($('#rawLineBreakResult'), detection);
  if(!$('#sampleLineBreak').value) $('#sampleLineBreak').value = raw;
  renderLineBreakPropsSuggestion(detection);
  renderStackTraceNote($('#rawStackTraceResult'), raw);
}

let lastAnalysis = null;

function renderFieldExtractionSuggestion(sourcetypeName, suggestion) {
  renderDetection($('#fieldExtractionResult'), {
    cls: suggestion.cls,
    title: suggestion.title,
    meta: [['Suggested sourcetype', sourcetypeName]],
    notes: suggestion.notes.join(' ')
  }, '', '');
  const propsBox = $('#fieldExtractionProps');
  propsBox.innerHTML = suggestion.propsConf
    ? `<div class="detectTitle">Suggested props.conf lines</div><pre>${esc(suggestion.propsConf)}</pre>`
    : `<div class="detectTitle">Suggested props.conf lines</div><div class="detectNotes">No extraction template available for this format yet.</div>`;
}

function downloadPropsConf() {
  if(!lastAnalysis) return;
  const text = buildPropsConfBundle(lastAnalysis);
  const blob = new Blob([text], {type:'text/plain'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'props.conf';
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function downloadReport() {
  const raw = $('#sampleRawEvent').value.trim();
  if(!raw) { renderValidationWarning($('#logFormatResult'), 'Paste a sample raw event first.'); return; }
  const markdown = buildAnalysisReportMarkdown(buildRawEventReport(raw));
  const blob = new Blob([markdown], {type:'text/markdown'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'lens-analysis-report.md';
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function renderEncodingResult(raw) {
  const box = $('#encodingResult');
  const list = $('#encodingIssueList');
  const result = detectEncodingIssues(raw);
  if(!result.hasIssues){
    renderDetection(box, {cls:'good', title:'No encoding issues detected', confidence:'Clean sample'}, '', '');
    list.innerHTML = '';
    return;
  }
  const badCount = result.issues.filter(i => i.cls === 'bad').length;
  renderDetection(box, {
    cls: badCount ? 'bad' : 'warn',
    title: `${result.issues.length} encoding issue(s) found`,
    confidence: badCount ? `${badCount} likely to break parsing` : 'Worth reviewing'
  }, '', '');
  list.innerHTML = result.issues.map(i => `<div class="item"><span class="pill ${i.cls}">${esc(i.cls)}</span> <span class="small">${esc(i.message)}</span></div>`).join('');
}

function analyseRawEvent() {
  const raw = $('#sampleRawEvent').value.trim();
  if(!raw) { renderValidationWarning($('#logFormatResult'), 'Paste a sample raw event first.'); return; }
  const result = detectRawFormat(raw);
  const truncation = detectTruncationRisk(raw);
  renderLogFormatResult(result.detected, result.parseStatus, result.extracted, truncation);
  renderExtractedFields(result.extracted);
  renderRawTimestampFindings(raw, result.values);
  renderRawUsernameFindings(raw, result.values);
  renderRawIpFindings(raw, result.values);
  renderRawLineBreakFindings(raw);
  renderEncodingResult(raw);

  const sourcetypeName = suggestSourcetypeName(result.detected, result.values);
  const cimAliases = buildCimFieldAliases(result.extracted);
  const fieldExtraction = combineFieldExtractionWithCim(suggestFieldExtraction(result.detected, raw, result.values, result.extracted), cimAliases);
  renderFieldExtractionSuggestion(sourcetypeName, fieldExtraction);

  const timestampCandidate = findTimestampCandidates(raw, result.values)[0] || null;
  let timestampProps = null;
  if(timestampCandidate) {
    const firstLine = raw.split(/\r?\n/)[0] || raw;
    const idx = firstLine.indexOf(timestampCandidate.value);
    timestampProps = {
      maxLookahead: idx >= 0 ? idx + timestampCandidate.value.length : timestampCandidate.value.length,
      timeFormat: timestampCandidate.detection.timeFormat || '',
      timePrefix: idx > 0 ? firstLine.slice(0, idx) : ''
    };
  }
  const lineBreakDetection = detectLineBreakFormat(raw);

  lastAnalysis = {
    raw,
    detectedFormat: result.detected,
    extractedFields: result.extracted,
    timestampEpochSeconds: (() => {
      if(!timestampCandidate) return null;
      const converted = dateToEpoch(timestampCandidate.value);
      return converted.valid ? converted.unixSeconds : null;
    })(),
    sourcetypeName,
    fieldExtraction,
    timestampProps,
    lineBreakProps: {
      shouldLineMerge: lineBreakDetection.shouldLineMerge || '',
      lineBreaker: lineBreakDetection.lineBreaker || ''
    }
  };
  const downloadBtn = $('#downloadPropsBtn');
  if(downloadBtn) downloadBtn.disabled = false;
  const downloadReportBtn = $('#downloadReportBtn');
  if(downloadReportBtn) downloadReportBtn.disabled = false;
}

function detectStandaloneTimestamp() {
  const value = $('#sampleDateTime').value.trim();
  if(!value) { renderValidationWarning($('#timestampResult'), 'Paste a timestamp first.'); return; }
  const detection = detectTimestampInput(value);
  renderTimestampResult($('#timestampResult'), detection);
  renderPropsConfSuggestion(detection);
}

function detectStandaloneUsername() {
  const value = $('#sampleUsername').value.trim();
  if(!value) { renderValidationWarning($('#usernameResult'), 'Paste a username first.'); return; }
  renderUsernameResult($('#usernameResult'), detectUsernameFormat(value));
}

function detectStandaloneLineBreak() {
  const value = $('#sampleLineBreak').value;
  if(!value.trim()) { renderValidationWarning($('#lineBreakResult'), 'Paste sample events first.'); return; }
  const detection = detectLineBreakFormat(value);
  renderLineBreakResult($('#lineBreakResult'), detection);
  renderLineBreakPropsSuggestion(detection);
  renderStackTraceNote($('#stackTraceResult'), value);
}

function renderBatchConsistency(result) {
  const box = $('#batchConsistencyResult');
  const details = $('#batchConsistencyDetails');
  if(!result) {
    renderDetection(box, null, 'No batch analysed yet', 'Paste multiple events, one per line, and select Check consistency.');
    details.innerHTML = '';
    return;
  }
  const formatSummary = result.formatCounts.map(([f,c]) => `${f} (${c})`).join(', ');
  const tsSummary = result.tsFormatCounts.length ? result.tsFormatCounts.map(([f,c]) => `${f} (${c})`).join(', ') : 'No timestamps detected';
  const notes = [
    result.formatDrift.length ? `${result.formatDrift.length} event(s) do not match the dominant format: line ${result.formatDrift.map(e=>e.index).join(', ')}.` : '',
    result.fieldDrift.length ? `${result.fieldDrift.length} event(s) are missing fields present in other same-format events: ${result.fieldDrift.map(d=>`line ${d.index} (missing ${d.missing.join(', ')})`).join('; ')}.` : '',
    result.noTimestamp.length ? `${result.noTimestamp.length} event(s) have no detected timestamp: line ${result.noTimestamp.map(e=>e.index).join(', ')}.` : '',
    result.tsDrift.length ? `${result.tsDrift.length} event(s) use a different timestamp format than the majority: line ${result.tsDrift.map(e=>e.index).join(', ')}.` : '',
    result.tzDrift.length ? `${result.tzDrift.length} event(s) have a timestamp with no timezone context: line ${result.tzDrift.map(e=>e.index).join(', ')}.` : ''
  ].filter(Boolean);
  renderDetection(box, {
    cls: result.verdict,
    title: result.verdict === 'good' ? `${result.totalEvents} events are consistent` : `${result.totalEvents} events analysed - drift detected`,
    confidence: `${result.totalEvents} event(s)`,
    meta: [
      ['Dominant format', result.dominantFormat],
      ['Format breakdown', formatSummary],
      ['Timestamp formats', tsSummary]
    ],
    notes: notes.length ? notes.join(' ') : 'No drift detected across the pasted events.'
  }, '', '');
  details.innerHTML = result.events.map(e => `
    <div class="item">
      <strong>Line ${esc(e.index)}: ${esc(e.format)}</strong>
      <span class="small">Fields: ${esc(e.fields.join(', ') || 'none')}</span>
      <span class="small">Timestamp: ${esc(e.timestampFormat || 'not detected')}${e.timezone ? ' | ' + esc(e.timezone) : ''}</span>
    </div>
  `).join('');
}

function checkBatchConsistencyHandler() {
  const value = $('#batchEventsInput').value;
  if(!value.trim()) { renderValidationWarning($('#batchConsistencyResult'), 'Paste two or more sample events, one per line, first.'); return; }
  renderBatchConsistency(checkBatchConsistency(value));
}

function renderRegexTest(result) {
  const box = $('#regexTestResult');
  if(!result) {
    renderDetection(box, null, 'No regex tested yet', 'Enter a pattern and test string and select Test regex.');
    $('#regexMatches').innerHTML = '';
    $('#regexHighlighted').innerHTML = '';
    return;
  }
  if(!result.valid) {
    renderValidationWarning(box, `Invalid regular expression: ${result.error}`);
    $('#regexMatches').innerHTML = '';
    $('#regexHighlighted').innerHTML = '';
    return;
  }
  renderDetection(box, {
    cls: result.matches.length ? 'good' : 'warn',
    title: result.matches.length ? `${result.matches.length} match${result.matches.length === 1 ? '' : 'es'} found` : 'No matches found',
    notes: result.truncated ? 'Match list truncated at 500 matches.' : ''
  }, '', '');
  $('#regexMatches').innerHTML = result.matches.length
    ? result.matches.slice(0,50).map((m,i) => {
        const groupsText = m.groups.length ? m.groups.map((g,gi) => `$${gi+1}=${g ?? ''}`).join(', ') : '';
        const namedText = m.namedGroups ? Object.entries(m.namedGroups).map(([k,v]) => `${k}=${v ?? ''}`).join(', ') : '';
        const extra = [groupsText, namedText].filter(Boolean).join(' | ');
        return `<div class="item"><strong>Match ${i+1} @ ${m.index}: <code>${esc(m.match)}</code></strong>${extra ? `<span class="small">${esc(extra)}</span>` : ''}</div>`;
      }).join('')
    : '<div class="item small">No matches found.</div>';
  $('#regexHighlighted').innerHTML = buildHighlightedText($('#regexTestString').value, result.matches);
}

function runRegexTestHandler() {
  const pattern = $('#regexPattern').value;
  const flags = $('#regexFlags').value;
  const text = $('#regexTestString').value;
  if(!pattern) { renderValidationWarning($('#regexTestResult'), 'Enter a regex pattern first.'); return; }
  renderRegexTest(runRegexTest(pattern, flags, text));
}

function renderPropsValidatorResult(result) {
  const box = $('#propsValidatorResult');
  const list = $('#propsValidatorChecks');
  if(!result) {
    renderDetection(box, null, 'No stanza validated yet', 'Paste a props.conf stanza and a sample event and select Validate.');
    list.innerHTML = '';
    return;
  }
  if(result.error) {
    renderValidationWarning(box, result.error);
    list.innerHTML = '';
    return;
  }
  const badCount = result.checks.filter(c => c.cls === 'bad').length;
  const warnCount = result.checks.filter(c => c.cls === 'warn').length;
  renderDetection(box, {
    cls: badCount ? 'bad' : (warnCount ? 'warn' : 'good'),
    title: `${result.checks.length} setting(s) checked`,
    confidence: badCount ? `${badCount} failing` : (warnCount ? `${warnCount} warning(s)` : 'All checks passed'),
    meta: result.stanza ? [['Stanza', result.stanza]] : []
  }, '', '');
  list.innerHTML = result.checks.map(c => `
    <div class="item">
      <strong><code>${esc(c.key)}</code> <span class="pill ${c.cls}">${esc(c.cls)}</span></strong>
      <span class="small">${esc(c.message)}</span>
    </div>
  `).join('');
}

function validatePropsConfHandler() {
  const propsText = $('#propsConfInput').value;
  const sample = $('#propsConfSample').value;
  if(!propsText.trim()) { renderValidationWarning($('#propsValidatorResult'), 'Paste a props.conf stanza first.'); return; }
  renderPropsValidatorResult(validatePropsConf(propsText, sample));
}

function renderPropsDiff(diff) {
  const box = $('#propsDiffResult');
  const list = $('#propsDiffList');
  if(!diff) {
    renderDetection(box, null, 'No comparison run yet', 'Paste a before and after stanza and select Compare.');
    list.innerHTML = '';
    return;
  }
  renderDetection(box, {
    cls: diff.hasDiff ? 'warn' : 'good',
    title: diff.hasDiff ? `${diff.added.length} added, ${diff.removed.length} removed, ${diff.changed.length} changed` : 'No differences found',
    confidence: `${diff.unchanged.length} setting(s) unchanged`
  }, '', '');
  list.innerHTML = [
    ...diff.added.map(d => `<div class="item"><strong><code>${esc(d.key)}</code> <span class="pill good">added</span></strong><span class="small">${esc(d.after)}</span></div>`),
    ...diff.removed.map(d => `<div class="item"><strong><code>${esc(d.key)}</code> <span class="pill bad">removed</span></strong><span class="small">${esc(d.before)}</span></div>`),
    ...diff.changed.map(d => `<div class="item"><strong><code>${esc(d.key)}</code> <span class="pill warn">changed</span></strong><span class="small">${esc(d.before)} &rarr; ${esc(d.after)}</span></div>`)
  ].join('');
}

function diffPropsConfHandler() {
  const before = $('#propsDiffBefore').value;
  const after = $('#propsDiffAfter').value;
  if(!before.trim() && !after.trim()) { renderValidationWarning($('#propsDiffResult'), 'Paste a before and after stanza first.'); return; }
  renderPropsDiff(diffPropsConf(before, after));
}

function renderDateDisambiguatorResult(result) {
  const box = $('#dateDisambiguatorResult');
  if(!result || !result.applicable) {
    renderDetection(box, null, 'No date disambiguated yet', 'Enter a slash/dot/dash-delimited date and select Disambiguate.');
    return;
  }
  renderDetection(box, {
    cls: result.ambiguous ? 'warn' : 'good',
    title: result.ambiguous ? 'Ambiguous - both orderings are valid' : 'Unambiguous',
    confidence: result.yearAssumed ? '2-digit year expanded' : '',
    meta: [
      ['US ordering (MM/DD/YYYY)', result.usInterpretation || 'Not a valid date'],
      ['EU/ISO ordering (DD/MM/YYYY)', result.euInterpretation || 'Not a valid date']
    ],
    notes: result.note
  }, '', '');
}

function disambiguateDateHandler() {
  const value = $('#ambiguousDateInput').value;
  if(!value.trim()) { renderValidationWarning($('#dateDisambiguatorResult'), 'Enter a date value first.'); return; }
  const result = disambiguateDate(value);
  if(!result.applicable) { renderValidationWarning($('#dateDisambiguatorResult'), 'This does not look like a slash/dot/dash-delimited date (e.g. 03/04/2026).'); return; }
  renderDateDisambiguatorResult(result);
}

let lastLookupSkeleton = null;

function renderLookupResult(result) {
  const box = $('#lookupResult');
  const downloadBtn = $('#downloadLookupBtn');
  if(!result) {
    box.innerHTML = `<div class="detectTitle">Lookup skeleton</div><div class="detectNotes">Enter a field name and sample values, then select Generate lookup skeleton.</div>`;
    if(downloadBtn) downloadBtn.disabled = true;
    return;
  }
  if(!result.valid) {
    box.className = 'propsBox';
    box.innerHTML = `<div class="detectTitle">Lookup skeleton</div><div class="detectNotes">${esc(result.error)}</div>`;
    if(downloadBtn) downloadBtn.disabled = true;
    return;
  }
  box.innerHTML = `
    <div class="detectTitle">${esc(result.distinctValueCount)} distinct value(s) &rarr; ${esc(result.lookupName)}.csv</div>
    <pre>${esc(result.csv)}</pre>
    <div class="detectTitle">transforms.conf</div>
    <pre>${esc(result.transformsConf)}</pre>
    <div class="detectTitle">props.conf</div>
    <pre>${esc(result.propsConf)}</pre>
  `;
  if(downloadBtn) downloadBtn.disabled = false;
}

function generateLookupHandler() {
  const fieldName = $('#lookupFieldName').value;
  const values = $('#lookupValues').value;
  const result = buildLookupSkeleton(fieldName, values);
  lastLookupSkeleton = result.valid ? result : null;
  renderLookupResult(result);
}

function downloadLookupCsv() {
  if(!lastLookupSkeleton) return;
  const blob = new Blob([lastLookupSkeleton.csv], {type:'text/csv'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${lastLookupSkeleton.lookupName}.csv`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function renderSplResult(searches) {
  const box = $('#splResult');
  if(!searches) {
    box.innerHTML = `<div class="detectTitle">No searches generated yet</div><div class="detectNotes">Enter an index/sourcetype (or use the last raw event analysis) and select Generate searches.</div>`;
    return;
  }
  box.innerHTML = `
    <div class="detectTitle">Ingestion check</div>
    <pre>${esc(searches.ingestionCheck)}</pre>
    <div class="detectTitle">Field extraction table</div>
    <pre>${esc(searches.fieldTable)}</pre>
    <div class="detectTitle">Timestamp / index-time lag sanity check</div>
    <pre>${esc(searches.timestampSanity)}</pre>
  `;
}

function generateSplHandler() {
  const indexName = $('#splIndex').value;
  const sourcetypeName = $('#splSourcetype').value;
  const fields = lastAnalysis && lastAnalysis.extractedFields ? lastAnalysis.extractedFields : [];
  renderSplResult(buildSplSearches({indexName, sourcetypeName, fields}));
}

function useLastAnalysisForSpl() {
  if(!lastAnalysis) {
    $('#splResult').innerHTML = `<div class="detectTitle">No searches generated yet</div><div class="detectNotes">Analyse a raw event above first, then select Use last raw event analysis.</div>`;
    return;
  }
  $('#splSourcetype').value = lastAnalysis.sourcetypeName || '';
  generateSplHandler();
}

function renderInputsConfResult(stanza) {
  const box = $('#inputsConfResult');
  box.innerHTML = stanza
    ? `<div class="detectTitle">inputs.conf</div><pre>${esc(stanza)}</pre>`
    : `<div class="detectTitle">inputs.conf</div><div class="detectNotes">Enter an index/sourcetype/path and select Generate inputs.conf.</div>`;
}

function generateInputsConfHandler() {
  const indexName = $('#inputsIndex').value;
  const sourcetypeName = $('#inputsSourcetype').value;
  const monitorPath = $('#inputsMonitorPath').value;
  renderInputsConfResult(buildInputsConfStanza({indexName, sourcetypeName, monitorPath}));
}

function useLastAnalysisForInputs() {
  if(!lastAnalysis) return;
  $('#inputsSourcetype').value = lastAnalysis.sourcetypeName || '';
  generateInputsConfHandler();
}

function renderHecResult(payload, curlCommand) {
  const box = $('#hecResult');
  box.innerHTML = payload
    ? `<div class="detectTitle">HEC event payload</div><pre>${esc(payload)}</pre><div class="detectTitle">curl command</div><pre>${esc(curlCommand)}</pre>`
    : `<div class="detectTitle">HEC payload</div><div class="detectNotes">Paste a raw event above and select Generate HEC payload.</div>`;
}

function generateHecHandler() {
  const raw = $('#sampleRawEvent').value.trim();
  if(!raw) { renderValidationWarning($('#hecResult'), 'Paste a sample raw event first.'); return; }
  const result = detectRawFormat(raw);
  const sourcetypeName = $('#inputsSourcetype').value || suggestSourcetypeName(result.detected, result.values);
  const indexName = $('#inputsIndex').value;
  const timestampCandidate = findTimestampCandidates(raw, result.values)[0] || null;
  let timestampEpochSeconds = null;
  if(timestampCandidate){
    const converted = dateToEpoch(timestampCandidate.value);
    if(converted.valid) timestampEpochSeconds = converted.unixSeconds;
  }
  const payload = buildHecPayload({raw, detectedFormat: result.detected, sourcetypeName, indexName, timestampEpochSeconds});
  const curlCommand = buildHecCurlCommand(payload, {hecUrl: $('#hecUrl').value, hecToken: $('#hecToken').value});
  renderHecResult(payload, curlCommand);
}

function renderCimResult(result) {
  const box = $('#cimResult');
  const list = $('#cimFieldList');
  if(!result) {
    renderDetection(box, null, 'No compliance check run yet', 'Analyse a raw event above, choose a data model, and select Check compliance.');
    list.innerHTML = '';
    return;
  }
  renderDetection(box, {
    cls: result.coverage >= 80 ? 'good' : (result.coverage >= 40 ? 'warn' : 'bad'),
    title: `${result.model.name}: ${result.coverage}% core field coverage`,
    confidence: `${result.present.length} of ${result.model.fields.length} core fields present`,
    meta: [['Model', result.model.description]]
  }, '', '');
  list.innerHTML = [
    ...result.present.map(p => `<div class="item"><strong>${esc(p.field)} <span class="pill good">present</span></strong><span class="small">Matched: ${esc(p.matched.join(', '))}</span></div>`),
    ...result.missing.map(f => `<div class="item"><strong>${esc(f)} <span class="pill warn">missing</span></strong></div>`)
  ].join('');
}

function checkCimComplianceHandler() {
  const raw = $('#sampleRawEvent').value.trim();
  if(!raw) { renderValidationWarning($('#cimResult'), 'Paste and analyse a raw event first.'); return; }
  const modelId = $('#cimModelSelect').value;
  const {extracted} = detectRawFormat(raw);
  renderCimResult(checkCimCompliance(modelId, extracted));
}

function renderVolumeResult(result) {
  const box = $('#volumeResult');
  if(!result) {
    renderDetection(box, null, 'No estimate generated yet', 'Enter an average event size and events per second/day, then select Estimate.');
    return;
  }
  if(!result.valid) {
    renderValidationWarning(box, result.error);
    return;
  }
  const gb = n => n.toFixed(2);
  renderDetection(box, {
    cls: 'good',
    title: `${gb(result.dailyRawGB)} GB/day raw (license-relevant)`,
    confidence: `${result.dailyEvents.toLocaleString()} events/day`,
    meta: [
      ['Monthly raw', `${gb(result.monthlyRawGB)} GB`],
      ['Annual raw', `${gb(result.annualRawGB)} GB`],
      ['Est. on-disk/day', `${gb(result.estimatedOnDiskDailyGB)} GB`],
      ...(result.estimatedRetainedOnDiskGB !== null ? [['Est. on-disk retained', `${gb(result.estimatedRetainedOnDiskGB)} GB over ${result.retentionDays}d`]] : [])
    ],
    notes: 'On-disk figures are a rough 50% rule-of-thumb estimate; actual compression varies by data type. License usage is based on raw daily volume above, not on-disk size.'
  }, '', '');
}

function estimateVolumeHandler() {
  const avgEventBytes = $('#volAvgBytes').value;
  const eventsPerSecond = $('#volEventsPerSecond').value;
  const eventsPerDay = $('#volEventsPerDay').value;
  const retentionDays = $('#volRetentionDays').value;
  renderVolumeResult(estimateIndexVolume({avgEventBytes, eventsPerSecond, eventsPerDay, retentionDays}));
}

function useSampleEventSizeHandler() {
  const raw = $('#sampleRawEvent').value;
  if(!raw.trim()) { renderValidationWarning($('#volumeResult'), 'Paste a sample raw event first.'); return; }
  $('#volAvgBytes').value = String(estimateEventBytes(raw));
}

function copyResults() {
  const logTitle = $('#logFormatResult .detectTitle')?.innerText || '';
  const tsTitle = $('#timestampResult .detectTitle')?.innerText || '';
  const rawTsTitle = $('#rawTimestampResult .detectTitle')?.innerText || '';
  const usernameTitle = $('#usernameResult .detectTitle')?.innerText || '';
  const rawUsernameTitle = $('#rawUsernameResult .detectTitle')?.innerText || '';
  const lineBreakTitle = $('#lineBreakResult .detectTitle')?.innerText || '';
  const reverseTimeFormatTitle = $('#reverseTimeFormatResult .detectTitle')?.innerText || '';
  const rawLineBreakTitle = $('#rawLineBreakResult .detectTitle')?.innerText || '';
  const text = `Log format: ${logTitle}\nStandalone timestamp: ${tsTitle}\nSplunk TIME_FORMAT reverse lookup: ${reverseTimeFormatTitle}\nStandalone username: ${usernameTitle}\nStandalone line break: ${lineBreakTitle}\nRaw event timestamp: ${rawTsTitle}\nRaw event username: ${rawUsernameTitle}\nRaw event line break: ${rawLineBreakTitle}`;
  const status = $('#copyStatus');
  const setStatus = message => { if(status) status.textContent = message; };
  navigator.clipboard?.writeText(text)
    .then(() => setStatus('Results copied to clipboard.'))
    .catch(() => { setStatus('Clipboard unavailable - copy the text below.'); prompt('Copy results:', text); });
}

function resetRawEventOutputs() {
  renderDetection($('#logFormatResult'), null, 'No log format detected yet', 'Paste a raw event and select Detect log format.');
  renderDetection($('#rawTimestampResult'), null, 'No raw event analysed yet', 'The raw event detector will list timestamp candidates here.');
  renderDetection($('#rawUsernameResult'), null, 'No raw event analysed yet', 'The raw event detector will list username candidates here.');
  renderDetection($('#rawIpResult'), null, 'No raw event analysed yet', 'The raw event detector will list IP address candidates here.');
  renderDetection($('#rawLineBreakResult'), null, 'No raw event analysed yet', 'The raw event detector will summarise line break structure here.');
  $('#timestampCandidates').innerHTML = '';
  $('#usernameCandidates').innerHTML = '';
  $('#ipCandidates').innerHTML = '';
  renderExtractedFields([]);
  renderFieldExtractionSuggestion('custom:sourcetype', {title:'No raw event analysed yet', cls:'info', propsConf:'', notes:['Analyse a raw event to generate an extraction suggestion.']});
  renderDetection($('#encodingResult'), null, 'No raw event analysed yet', 'The raw event detector will report encoding issues here.');
  $('#encodingIssueList').innerHTML = '';
  renderStackTraceNote($('#rawStackTraceResult'), '');
  lastAnalysis = null;
  const downloadBtn = $('#downloadPropsBtn');
  if(downloadBtn) downloadBtn.disabled = true;
  const downloadReportBtn = $('#downloadReportBtn');
  if(downloadReportBtn) downloadReportBtn.disabled = true;
}

function resetAll() {
  $('#sampleRawEvent').value = '';
  $('#sampleDateTime').value = '';
  $('#sampleUsername').value = '';
  $('#sampleIpAddress').value = '';
  $('#sampleLineBreak').value = '';
  $('#sampleSplunkTimeFormat').value = '';
  $('#batchEventsInput').value = '';
  $('#regexPattern').value = '';
  $('#regexFlags').value = '';
  $('#regexTestString').value = '';
  $('#epochInput').value = '';
  $('#epochUnit').value = 'auto';
  $('#dateTimeInput').value = '';
  $('#propsConfInput').value = '';
  $('#propsConfSample').value = '';
  $('#splIndex').value = '';
  $('#splSourcetype').value = '';
  $('#inputsIndex').value = '';
  $('#inputsSourcetype').value = '';
  $('#inputsMonitorPath').value = '';
  $('#hecUrl').value = '';
  $('#hecToken').value = '';
  $('#volAvgBytes').value = '';
  $('#volEventsPerSecond').value = '';
  $('#volEventsPerDay').value = '';
  $('#volRetentionDays').value = '';
  $('#propsDiffBefore').value = '';
  $('#propsDiffAfter').value = '';
  $('#ambiguousDateInput').value = '';
  $('#lookupFieldName').value = '';
  $('#lookupValues').value = '';
  renderDetection($('#timestampResult'), null, 'No timestamp detected yet', 'Paste one timestamp and select Detect timestamp.');
  renderPropsConfSuggestion(null);
  renderReverseTimeFormatResult(null);
  renderDetection($('#usernameResult'), null, 'No username detected yet', 'Paste one username, principal, account ID, or SAML NameID Format URN and select Detect username.');
  renderIpResult($('#ipResult'), null);
  renderLineBreakResult($('#lineBreakResult'), null);
  renderLineBreakPropsSuggestion(null);
  renderStackTraceNote($('#stackTraceResult'), '');
  renderBatchConsistency(null);
  renderRegexTest(null);
  renderEpochToDateResult(null);
  renderDateToEpochResult(null);
  renderDateDisambiguatorResult(null);
  renderPropsValidatorResult(null);
  renderPropsDiff(null);
  renderSplResult(null);
  renderInputsConfResult(null);
  renderHecResult(null, null);
  renderCimResult(null);
  renderVolumeResult(null);
  lastLookupSkeleton = null;
  renderLookupResult(null);
  resetRawEventOutputs();
}

function init() {
  $('#timeRefTable tbody').innerHTML = TIME_FORMATS.map(row => `<tr>${row.map(c => `<td>${esc(c)}</td>`).join('')}</tr>`).join('');
  $('#formatCount').textContent = String(TIME_FORMATS.length);
  $('#usernameRefTable tbody').innerHTML = USERNAME_FORMATS.map(row => `<tr><td>${esc(row.precedence)}</td><td>${esc(row.name)}</td><td>${esc(row.category)}</td><td><code>${esc(row.example)}</code></td><td>${esc(row.template)}</td><td><code>${esc(row.regex)}</code></td><td>${esc(row.notes)}</td></tr>`).join('');
  $('#usernameFormatCount').textContent = String(USERNAME_FORMATS.length);
  $('#cimModelSelect').innerHTML = CIM_DATA_MODELS.map(m => `<option value="${esc(m.id)}">${esc(m.name)}</option>`).join('');
  $('#analyzeBtn').addEventListener('click', analyseRawEvent);
  $('#detectTimestampBtn').addEventListener('click', detectStandaloneTimestamp);
  $('#reverseTimeFormatBtn').addEventListener('click', detectReverseTimeFormat);
  $('#detectUsernameBtn').addEventListener('click', detectStandaloneUsername);
  $('#detectIpBtn').addEventListener('click', detectStandaloneIp);
  $('#detectLineBreakBtn').addEventListener('click', detectStandaloneLineBreak);
  $('#downloadPropsBtn').addEventListener('click', downloadPropsConf);
  $('#downloadReportBtn').addEventListener('click', downloadReport);
  $('#checkBatchBtn').addEventListener('click', checkBatchConsistencyHandler);
  $('#clearBatchBtn').addEventListener('click', () => {
    $('#batchEventsInput').value = '';
    renderBatchConsistency(null);
  });
  $('#testRegexBtn').addEventListener('click', runRegexTestHandler);
  $('#clearRegexBtn').addEventListener('click', () => {
    $('#regexPattern').value = '';
    $('#regexFlags').value = '';
    $('#regexTestString').value = '';
    renderRegexTest(null);
  });
  $('#convertEpochBtn').addEventListener('click', convertEpochToDate);
  $('#epochNowBtn').addEventListener('click', () => {
    $('#epochInput').value = String(Date.now());
    $('#epochUnit').value = 'milliseconds';
    convertEpochToDate();
  });
  $('#clearEpochBtn').addEventListener('click', () => {
    $('#epochInput').value = '';
    $('#epochUnit').value = 'auto';
    renderEpochToDateResult(null);
  });
  $('#convertDateBtn').addEventListener('click', convertDateToEpoch);
  $('#dateNowBtn').addEventListener('click', () => {
    $('#dateTimeInput').value = new Date().toISOString();
    convertDateToEpoch();
  });
  $('#clearDateBtn').addEventListener('click', () => {
    $('#dateTimeInput').value = '';
    renderDateToEpochResult(null);
  });
  $('#epochInput').addEventListener('keydown', e => { if(e.key === 'Enter') convertEpochToDate(); });
  $('#dateTimeInput').addEventListener('keydown', e => { if(e.key === 'Enter') convertDateToEpoch(); });
  $('#clearRawBtn').addEventListener('click', () => {
    $('#sampleRawEvent').value='';
    resetRawEventOutputs();
  });
  $('#clearTimestampBtn').addEventListener('click', () => {
    $('#sampleDateTime').value='';
    renderDetection($('#timestampResult'), null, 'No timestamp detected yet', 'Paste one timestamp and select Detect timestamp.');
    renderPropsConfSuggestion(null);
  });
  $('#clearReverseTimeFormatBtn').addEventListener('click', () => {
    $('#sampleSplunkTimeFormat').value='';
    renderReverseTimeFormatResult(null);
  });
  $('#clearUsernameBtn').addEventListener('click', () => {
    $('#sampleUsername').value='';
    renderDetection($('#usernameResult'), null, 'No username detected yet', 'Paste one username, principal, account ID, or SAML NameID Format URN and select Detect username.');
  });
  $('#clearIpBtn').addEventListener('click', () => {
    $('#sampleIpAddress').value='';
    renderIpResult($('#ipResult'), null);
  });
  $('#sampleIpAddress').addEventListener('keydown', e => { if(e.key === 'Enter') detectStandaloneIp(); });
  $('#clearLineBreakBtn').addEventListener('click', () => {
    $('#sampleLineBreak').value='';
    renderLineBreakResult($('#lineBreakResult'), null);
    renderLineBreakPropsSuggestion(null);
  });
  $('#copyBtn').addEventListener('click', copyResults);
  $('#resetBtn').addEventListener('click', resetAll);
  $('#loadExampleBtn').addEventListener('click', () => {
    $('#sampleRawEvent').value = [
      'timestamp=2026-07-09T14:30:45.123+10:00 level=error user=COMPANY\\jsmith action=user_login result=failure',
      '    at auth.validate(auth.js:42)',
      '    at login.submit(login.js:18)',
      'timestamp=2026-07-09T14:31:02.901+10:00 level=info user=jsmith@company.com action=user_logout result=success'
    ].join('\n');
    analyseRawEvent();
  });
  $('#sampleDateTime').addEventListener('keydown', e => { if(e.key === 'Enter') detectStandaloneTimestamp(); });
  $('#sampleSplunkTimeFormat').addEventListener('keydown', e => { if(e.key === 'Enter') detectReverseTimeFormat(); });
  $('#sampleUsername').addEventListener('keydown', e => { if(e.key === 'Enter') detectStandaloneUsername(); });
  $('#validatePropsBtn').addEventListener('click', validatePropsConfHandler);
  $('#clearPropsValidatorBtn').addEventListener('click', () => {
    $('#propsConfInput').value = '';
    $('#propsConfSample').value = '';
    renderPropsValidatorResult(null);
  });
  $('#generateSplBtn').addEventListener('click', generateSplHandler);
  $('#splUseAnalysisBtn').addEventListener('click', useLastAnalysisForSpl);
  $('#clearSplBtn').addEventListener('click', () => {
    $('#splIndex').value = '';
    $('#splSourcetype').value = '';
    renderSplResult(null);
  });
  $('#generateInputsBtn').addEventListener('click', generateInputsConfHandler);
  $('#inputsUseAnalysisBtn').addEventListener('click', useLastAnalysisForInputs);
  $('#generateHecBtn').addEventListener('click', generateHecHandler);
  $('#checkCimBtn').addEventListener('click', checkCimComplianceHandler);
  $('#estimateVolumeBtn').addEventListener('click', estimateVolumeHandler);
  $('#volUseSampleBtn').addEventListener('click', useSampleEventSizeHandler);
  $('#clearVolumeBtn').addEventListener('click', () => {
    $('#volAvgBytes').value = '';
    $('#volEventsPerSecond').value = '';
    $('#volEventsPerDay').value = '';
    $('#volRetentionDays').value = '';
    renderVolumeResult(null);
  });
  $('#diffPropsBtn').addEventListener('click', diffPropsConfHandler);
  $('#clearPropsDiffBtn').addEventListener('click', () => {
    $('#propsDiffBefore').value = '';
    $('#propsDiffAfter').value = '';
    renderPropsDiff(null);
  });
  $('#disambiguateDateBtn').addEventListener('click', disambiguateDateHandler);
  $('#clearDateDisambiguatorBtn').addEventListener('click', () => {
    $('#ambiguousDateInput').value = '';
    renderDateDisambiguatorResult(null);
  });
  $('#ambiguousDateInput').addEventListener('keydown', e => { if(e.key === 'Enter') disambiguateDateHandler(); });
  $('#generateLookupBtn').addEventListener('click', generateLookupHandler);
  $('#downloadLookupBtn').addEventListener('click', downloadLookupCsv);
  $('#clearLookupBtn').addEventListener('click', () => {
    $('#lookupFieldName').value = '';
    $('#lookupValues').value = '';
    lastLookupSkeleton = null;
    renderLookupResult(null);
  });
  initThemeToggle();
}

function initThemeToggle() {
  const btn = $('#themeToggleBtn');
  if(!btn) return;
  const root = document.documentElement;
  const apply = theme => {
    root.setAttribute('data-theme', theme);
    btn.textContent = theme === 'light' ? 'Dark mode' : 'Light mode';
    btn.setAttribute('aria-pressed', theme === 'light' ? 'true' : 'false');
  };
  const prefersLight = typeof window.matchMedia === 'function' && window.matchMedia('(prefers-color-scheme: light)').matches;
  apply(prefersLight ? 'light' : 'dark');
  btn.addEventListener('click', () => {
    const current = root.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
    apply(current === 'light' ? 'dark' : 'light');
  });
}

if(typeof document !== 'undefined') {
  init();
}

if(typeof module !== 'undefined' && module.exports) {
  module.exports = {
    TIME_FORMATS,
    USERNAME_FORMATS,
    REQUIRED_FIELDS,
    flattenObject,
    normKey,
    findFields,
    parseKeyValues,
    extractCefFields,
    normaliseLogFormatName,
    logFormatGuidance,
    findTimestampCandidates,
    detectDateTimeFormat,
    reverseLookupTimeFormat,
    detectTimestampInput,
    escapeLineBreakerLiteral,
    detectLineBreakFormat,
    detectUsernameFormat,
    findUsernameCandidates,
    detectRawFormat,
    extractWindowsEventXmlFields,
    extractGenericXmlFields,
    slug,
    suggestSourcetypeName,
    suggestFieldExtraction,
    buildPropsConfBundle,
    checkBatchConsistency,
    runRegexTest,
    buildHighlightedText,
    epochToDate,
    dateToEpoch,
    classifyIpAddress,
    findIpCandidates,
    buildCimFieldAliases,
    combineFieldExtractionWithCim,
    detectTruncationRisk,
    buildRawEventReport,
    buildAnalysisReportMarkdown,
    timeFormatToRegex,
    validateTimeFormatAgainstSample,
    parsePropsConfText,
    validatePropsConf,
    buildSplSearches,
    buildInputsConfStanza,
    estimateEventBytes,
    buildHecPayload,
    buildHecCurlCommand,
    CIM_DATA_MODELS,
    findCimFieldMatches,
    checkCimCompliance,
    estimateIndexVolume,
    detectEncodingIssues,
    detectStackTrace,
    diffPropsConf,
    disambiguateDate,
    csvEscape,
    buildLookupSkeleton
  };
}
