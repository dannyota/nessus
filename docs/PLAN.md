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
| `GetHostDetails(scanID, hostID)` | Host info with vulnerability list (plugin_id, severity, count) | ✅ |
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

## 🔮 Phase 5: Future

Candidates — add as needed:

| Resource | Category |
|----------|----------|
| Folders | Organization |
| Server status | System |
| Server properties | System |
| Policies | Configuration |

## ❌ Non-Goals

| Scope | Reason |
|-------|--------|
| Write operations (create/launch/stop scans) | Read-only SDK |
| Tenable.io (cloud) API | Different API, different auth (Tenable API keys) |
| Nessus Agent API | Separate product |
