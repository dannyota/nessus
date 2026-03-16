# Plan

Development roadmap for nessus.

## 🏗️ Phase 1: Core Client — ✅ Done

| Component | Description | Status |
|-----------|-------------|:------:|
| HTTP client | TLS configuration, base URL | ✅ |
| API key auth | `X-ApiKeys` header on every request | ✅ |
| Functional options | `WithAPIKeys`, `WithInsecureTLS`, `WithTimeout`, `WithTransport`, `WithHTTPClient`, `WithUserAgent` | ✅ |
| Request helper | Internal GET with auth and error handling | ✅ |
| Error types | `ErrAuth`, `ErrNotFound`, `ErrPermission`, `APIError` | ✅ |

## 📦 Phase 2: Resource Methods — ✅ Done

| Method | Description | Status |
|--------|-------------|:------:|
| `ListScans()` | All scans with status, folder, timestamps | ✅ |
| `GetScan(id)` | Scan details including host list | ✅ |
| `GetHostDetails(scanID, hostID)` | Host info with vulnerability list (plugin_id, severity, count) | ✅ |
| `GetPluginOutput(scanID, hostID, pluginID)` | Full finding: synopsis, description, solution, CVSS, CVE, output text | ✅ |

## ✅ Phase 3: Quality — ✅ Done

| Task | Description | Status |
|------|-------------|:------:|
| Unit tests | httptest-based mock server, table-driven tests | ✅ |
| Smoke test | Live scanner test (`go run smoke.go`) | ✅ |
| GoDoc | Comments on all exported types and methods | ✅ |

## 🔮 Phase 4: Future

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
| Export (Nessus/CSV/HTML) | Hotpot ingests via API, not file export |
