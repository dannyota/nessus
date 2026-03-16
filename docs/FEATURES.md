# Features

Nessus self-hosted REST API coverage.

## 🔍 Scans

| Resource | SDK Method | API Endpoint | Status |
|----------|-----------|--------------|:------:|
| List scans | `ListScans()` | `GET /scans` | ✅ |
| Scan details | `GetScan(id)` | `GET /scans/{id}` | ✅ |

## 🖥️ Hosts

| Resource | SDK Method | API Endpoint | Status |
|----------|-----------|--------------|:------:|
| Host details | `GetHostDetails(scanID, hostID)` | `GET /scans/{scan_id}/hosts/{host_id}` | ✅ |

## 🛡️ Findings

| Resource | SDK Method | API Endpoint | Status |
|----------|-----------|--------------|:------:|
| Plugin output | `GetPluginOutput(scanID, hostID, pluginID)` | `GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}` | ✅ |

## 🚫 Not in Scope (v0.1.0)

| Resource | API Endpoint | Reason |
|----------|-------------|--------|
| Folders | `GET /folders` | Not needed for ingestion |
| Policies | `GET /policies` | Not needed for ingestion |
| Scanners | `GET /scanners` | Not needed for ingestion |
| Export | `POST /scans/{id}/export` | Not needed for ingestion |
| Server status | `GET /server/status` | Not needed for ingestion |
| Server properties | `GET /server/properties` | Not needed for ingestion |
| Create/launch scans | `POST /scans` | Read-only SDK |

## 📈 Summary

| Category | v0.1.0 | Future | Total |
|----------|:------:|:------:|:-----:|
| Scans | 2 | 0 | 2 |
| Hosts | 1 | 0 | 1 |
| Findings | 1 | 0 | 1 |
| Folders | 0 | 1 | 1 |
| System | 0 | 2 | 2 |
| **Total** | **4** | **3** | **7** |
