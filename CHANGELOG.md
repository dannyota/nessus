# Changelog

## v0.1.0 (unreleased)

First release. Read-only Go SDK for Nessus self-hosted scanner.

### Core

- API key authentication (`X-ApiKeys: accessKey=xxx;secretKey=yyy`)
- Functional options: `WithAPIKeys`, `WithInsecureTLS`, `WithTimeout`, `WithTransport`, `WithHTTPClient`, `WithUserAgent`
- Sentinel errors: `ErrAuth`, `ErrNotFound`, `APIError`
- Zero external dependencies (stdlib only)

### Resource Methods (4 total)

- `ListScans()` — all scans with status, folder, timestamps
- `GetScan(id)` — scan details including host list
- `GetHostDetails(scanID, hostID)` — host info with vulnerability summary per severity
- `GetPluginOutput(scanID, hostID, pluginID)` — finding details: synopsis, description, solution, CVSS, CVE, output text
