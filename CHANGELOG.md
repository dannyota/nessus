# Changelog

## v0.1.0

First release. Read-only Go SDK for Nessus self-hosted scanner.

### Core

- API key authentication (`X-ApiKeys: accessKey=xxx;secretKey=yyy`)
- Functional options: `WithAPIKeys`, `WithInsecureTLS`, `WithTimeout`, `WithTransport`, `WithHTTPClient`, `WithUserAgent`
- Sentinel errors: `ErrAuth`, `ErrNotFound`, `ErrPermission`, `APIError`
- Severity constants: `SeverityInfo`, `SeverityLow`, `SeverityMedium`, `SeverityHigh`, `SeverityCritical`
- `SeverityName(level)` helper for display
- Zero external dependencies (stdlib only)

### Resource Methods (10 total)

**Individual API calls:**
- `ListScans()` — all scans with status, folder, timestamps
- `GetScan(id)` — scan details including host list
- `GetScanHistory(scanID)` — historical scan runs (history IDs, status, date)
- `GetHostDetails(scanID, hostID)` — vulnerability list per host
- `GetPluginOutput(scanID, hostID, pluginID)` — finding details: synopsis, description, solution, CVSS, CVE, output text

**Bulk export (recommended for ingestion):**
- `ExportScan(scanID, opts...)` — request Nessus XML export, optional `WithHistoryID(id)`
- `ExportStatus(token)` — poll export readiness
- `DownloadExport(token)` — download raw export bytes
- `ExportAndWait(scanID, opts...)` — export + poll + download + parse in one call

### XML Parser

- `ParseNessusXML(data)` — parse `.nessus` XML into typed `ExportResult` with hosts and findings
- `WithMinSeverity(level)` — filter findings during parsing
- Each `Finding` includes: plugin ID/name/family, severity, port, synopsis, description, solution, evidence output, CVSS/CVSS3 scores, CVE/BID/XREF references, see also links
- Each `ExportHost` includes: IP, FQDN, hostname, NetBIOS name, OS, MAC, start/end timestamps
