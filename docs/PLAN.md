# Plan

Development roadmap for nessus.

## 🏗️ Phase 1: Core Client — ✅ Done

| Component | Description | Status |
|-----------|-------------|:------:|
| HTTP client | TLS configuration, base URL | ✅ |
| API key auth | `X-ApiKeys` header on every request | ✅ |
| Functional options | `WithAPIKeys`, `WithInsecureTLS`, `WithTimeout`, `WithTransport`, `WithHTTPClient`, `WithUserAgent` | ✅ |
| Request helpers | Internal GET and POST with auth and error handling | ✅ |
| Error types | `ErrAuth`, `ErrNotFound`, `ErrPermission`, `APIError` | ✅ |

## 📦 Phase 2: Resource Methods — ✅ Done

| Method | Description | Status |
|--------|-------------|:------:|
| `ListScans()` | All scans with status, folder, timestamps | ✅ |
| `GetScan(id)` | Scan details including host list | ✅ |
| `GetScanHistory(scanID)` | Historical scan runs (history IDs, status, date) | ✅ |
| `GetHostDetails(scanID, hostID)` | Vulnerability list per host | ✅ |
| `GetPluginOutput(scanID, hostID, pluginID)` | Full finding: synopsis, description, solution, CVSS, CVE, output text | ✅ |

## 📤 Phase 3: Bulk Export — ✅ Done

| Method | Description | Status |
|--------|-------------|:------:|
| `ExportScan(scanID, opts...)` | Request Nessus XML export | ✅ |
| `ExportStatus(token)` | Poll export readiness | ✅ |
| `DownloadExport(token)` | Download raw export bytes | ✅ |
| `ExportAndWait(scanID, opts...)` | Export + poll + download + parse | ✅ |
| `ParseNessusXML(data)` | Parse `.nessus` XML into typed result | ✅ |
| `WithHistoryID(id)` | Export specific historical scan run | ✅ |

## ✅ Phase 4: Quality — ✅ Done

| Task | Description | Status |
|------|-------------|:------:|
| Unit tests | httptest-based mock server, table-driven tests | ✅ |
| Smoke test | Live scanner test (`go run smoke.go`) | ✅ |
| GoDoc | Comments on all exported types and methods | ✅ |

## 🔧 Phase 5: Polish — ✅ Done

| Task | Description | Status |
|------|-------------|:------:|
| Host properties | Parse `netbios-name`, `HOST_START_TIMESTAMP`, `HOST_END_TIMESTAMP` into `ExportHost` | ✅ |
| SeeAlso as `[]string` | Change `SeeAlso` from `string` to `[]string` in `Finding` and `PluginInfo` | ✅ |
| MinSeverity filter | `WithMinSeverity(level)` export option to skip info/low findings during parse | ✅ |
| Severity constants | `SeverityInfo` through `SeverityCritical` + `SeverityName()` helper | ✅ |
| Token validation | Validate export token to prevent path traversal | ✅ |
| Test data hygiene | All test fixtures use placeholder data only | ✅ |
| Code review fixes | GoDoc on exported funcs, error prefix consistency, bug fixes | ✅ |

## 🔮 Phase 6: Future

Add as needed when hotpot integration requires them:

| Task | Description |
|------|-------------|
| `ListFolders()` | Scan folder organization |
| `ServerStatus()` | Scanner health check |
| `ServerProperties()` | Scanner version, license info |
| Agent ID extraction | Helper to extract Nessus Agent UUID from plugin 110230 output |
| Streaming XML parser | Memory-efficient parsing for very large exports |
| Export progress callback | Notify caller during poll loop |

## ❌ Non-Goals

| Scope | Reason |
|-------|--------|
| Write operations (create/launch/stop scans) | Read-only SDK |
| Tenable.io (cloud) API | Different API, different auth (Tenable API keys) |
| Nessus Agent API | Separate product |
