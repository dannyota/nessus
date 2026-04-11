# Architecture

Go SDK for Nessus self-hosted scanner REST API.

## 🔄 API Protocol

### 🔐 Authentication

Stateless API key auth — no login/logout, no sessions:

| Header | Format |
|--------|--------|
| `X-ApiKeys` | `accessKey={access_key};secretKey={secret_key}` |

Sent on every request. Keys are generated in the Nessus web UI under Settings > My Account > API Keys.

### 📡 Endpoints

All endpoints are under the base URL (e.g. `https://nessus:8834`).

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/scans` | GET | List all scans |
| `/scans/{id}` | GET | Scan details with host list |
| `/scans/{scan_id}/hosts/{host_id}` | GET | Host details with vulnerability list |
| `/scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}` | GET | Plugin output (finding details) |
| `/agents` | GET | List all agents |
| `/agent-groups` | GET | List all agent groups |
| `/scanners` | GET | List all scanners |

### 📦 Response Format

Success:

```json
{
  "scans": [...],
  "folders": [...]
}
```

Error:

```json
{
  "error": "Invalid Credentials"
}
```

| HTTP Status | Meaning | SDK Error |
|-------------|---------|-----------|
| 200 | Success | — |
| 401 | Invalid API keys | `ErrAuth` |
| 404 | Resource not found | `ErrNotFound` |
| 403 | Insufficient permissions | `ErrPermission` |
| Other 4xx/5xx | API error | `APIError` |

### 📋 Content Type

All requests and responses use `application/json`. No pagination — Nessus returns full lists.

## 📂 Package Layout

```
danny.vn/nessus/
├── client.go             # Client, NewClient, Close
├── option.go             # WithAPIKeys, WithInsecureTLS, WithTimeout, etc.
├── request.go            # Internal HTTP GET with auth header
├── errors.go             # ErrAuth, ErrNotFound, ErrPermission, APIError
├── types.go              # All public domain types
│
├── scan.go               # ListScans, GetScan
├── host.go               # GetHostDetails
├── plugin.go             # GetPluginOutput
├── agent_api.go          # ListAgents
├── agent_group_api.go    # ListAgentGroups
├── scanner_api.go        # ListScanners
│
├── testhelper_test.go    # Shared httptest server
├── *_test.go             # Unit tests for all resources
└── smoke.go              # Live scanner smoke test (go run)
```

## 🏛️ Design Decisions

| Decision | Rationale |
|----------|-----------|
| Flat package | Single concern, no sub-packages needed |
| Functional options | Clean constructor, extensible (rate limiting, custom transports) |
| No Login/Logout | Nessus uses stateless API keys, not sessions |
| Read-only | Inventory/audit use case — no scan creation or modification |
| No pagination handling | Nessus self-hosted returns full lists; agents use callback for large-data safety |
| Separate DTOs | API structs stay unexported; public types have clean field names |

## ⚠️ TLS

| Issue | Solution |
|-------|----------|
| Self-signed certs | `WithInsecureTLS()` |

Most self-hosted Nessus scanners use self-signed certificates.
