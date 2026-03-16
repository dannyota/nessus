# Changelog

## v0.1.1

### New Features

- **Agent ID extraction** — `ExtractAgentID(host)` for export results, `ParseAgentID(output)` for REST API results. Extracts Nessus Agent UUID from plugin 110230/100574 output
- **Streaming XML parser** — `ParseNessusXMLFromReader(r)` streams XML token-by-token, one host at a time. Suitable for large exports
- **Export progress callback** — `WithOnProgress(fn)` reports phase transitions (`exporting`, `polling`, `downloading`, `parsing`) during `ExportAndWait`. Useful for Temporal heartbeats
- **Severity constants** — `SeverityInfo` through `SeverityCritical` + `SeverityName()` helper
- **MinSeverity filter** — `WithMinSeverity(level)` to skip low-severity findings during parsing
- **Host properties** — `ExportHost` now includes `NetBIOSName`, `StartTimestamp`, `EndTimestamp`
- **SeeAlso as `[]string`** — split into individual URLs in both `Finding` and `PluginInfo`

### Bug Fixes

- `Scan.StartTime`/`EndTime` were never populated in `ListScans`
- Handle `starttime`/`endtime` as flexible type (string or int)
- Guard against zero file-ID in export response
- Check context cancellation before each poll iteration

### Security

- Validate export token in `ExportStatus`/`DownloadExport` to prevent path traversal
- `WithInsecureTLS` doc warns about MITM risk

### Code Quality

- GoDoc comments on exported functions
- Error prefix consistency (`nessus:` on all errors)
- Plugin ID constants: `PluginIDNessusAgent`, `PluginIDNessusAgentLegacy`

## v0.1.0

First release. Read-only Go SDK for Nessus self-hosted scanner.

### Core

- API key authentication (`X-ApiKeys: accessKey=xxx;secretKey=yyy`)
- Functional options: `WithAPIKeys`, `WithInsecureTLS`, `WithTimeout`, `WithTransport`, `WithHTTPClient`, `WithUserAgent`
- Sentinel errors: `ErrAuth`, `ErrNotFound`, `ErrPermission`, `APIError`
- Zero external dependencies (stdlib only)

### Resource Methods

- `ListScans()`, `GetScan(id)`, `GetScanHistory(scanID)`
- `GetHostDetails(scanID, hostID)`, `GetPluginOutput(scanID, hostID, pluginID)`
- `ExportScan(scanID, opts...)`, `ExportStatus(token)`, `DownloadExport(token)`
- `ExportAndWait(scanID, opts...)` — export + poll + download + parse

### XML Parser

- `ParseNessusXML(data)` — parse `.nessus` XML into typed `ExportResult`
