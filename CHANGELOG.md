# Changelog

## v0.1.0 (unreleased)

First release. Read-only Go SDK for Nessus self-hosted scanner.

### Core

- API key authentication (`X-ApiKeys: accessKey=xxx;secretKey=yyy`)
- Functional options: `WithAPIKeys`, `WithInsecureTLS`, `WithTimeout`, `WithTransport`, `WithHTTPClient`, `WithUserAgent`
- Sentinel errors: `ErrAuth`, `ErrNotFound`, `ErrPermission`, `APIError`
- Zero external dependencies (stdlib only)

### Resource Methods (10 total)

**Individual API calls:**
- `ListScans()` — all scans with status, folder, timestamps
- `GetScan(id)` — scan details including host list
- `GetScanHistory(scanID)` — historical scan runs (history IDs, status, date)
- `GetHostDetails(scanID, hostID)` — host info with vulnerability summary per severity
- `GetPluginOutput(scanID, hostID, pluginID)` — finding details: synopsis, description, solution, CVSS, CVE, output text

**Bulk export (recommended for ingestion):**
- `ExportScan(scanID, opts...)` — request Nessus XML export, optional `WithHistoryID(id)`
- `ExportStatus(token)` — poll export readiness
- `DownloadExport(token)` — download raw export bytes
- `ExportAndWait(scanID, opts...)` — export + poll + download + parse in one call

### XML Parser

- `ParseNessusXML(data)` — parse `.nessus` XML into typed `ExportResult` with hosts and findings
- Each `Finding` includes: plugin ID/name/family, severity, port, synopsis, description, solution, evidence output, CVSS/CVSS3 scores, CVE/BID/XREF references
