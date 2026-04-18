# Features

Nessus self-hosted REST API coverage.

## 🔍 Scans

| Resource | SDK Method | API Endpoint | Status |
|----------|-----------|--------------|:------:|
| List scans | `ListScans()` | `GET /scans` | ✅ |
| Scan details | `GetScan(id)` | `GET /scans/{id}` | ✅ |
| Scan history | `GetScanHistory(scanID)` | `GET /scans/{id}` | ✅ |

## 🖥️ Hosts

| Resource | SDK Method | API Endpoint | Status |
|----------|-----------|--------------|:------:|
| Host details | `GetHostDetails(scanID, hostID)` | `GET /scans/{scan_id}/hosts/{host_id}` | ✅ |

## 🛡️ Findings

| Resource | SDK Method | API Endpoint | Status |
|----------|-----------|--------------|:------:|
| Plugin output | `GetPluginOutput(scanID, hostID, pluginID)` | `GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}` | ✅ |

## 📦 Export (Bulk)

| Resource | SDK Method | API Endpoint | Status |
|----------|-----------|--------------|:------:|
| Request export | `ExportScan(scanID, opts...)` | `POST /scans/{id}/export` | ✅ |
| Check status | `ExportStatus(token)` | `GET /tokens/{token}/status` | ✅ |
| Download | `DownloadExport(token)` | `GET /tokens/{token}/download` | ✅ |
| Export + parse | `ExportAndWait(scanID, opts...)` | All of the above + XML parse | ✅ |

## 📄 XML Parser

| Resource | Function | Description | Status |
|----------|----------|-------------|:------:|
| Parse export | `ParseNessusXML(data)` | Parse `.nessus` XML into typed `ExportResult` | ✅ |

## 🤖 Agents

| Resource | SDK Method | API Endpoint | Status |
|----------|-----------|--------------|:------:|
| List agents | `ListAgents(ctx, fn)` | `GET /agents` | ✅ |
| List agents with pagination/sorting | `ListAgentsWithOptions(ctx, opts, fn)` | `GET /agents?limit=...&offset=...` | ✅ |

## 📂 Agent Groups

| Resource | SDK Method | API Endpoint | Status |
|----------|-----------|--------------|:------:|
| List agent groups | `ListAgentGroups(ctx)` | `GET /agent-groups` | ✅ |

## 📋 Policies

| Resource | SDK Method | API Endpoint | Status |
|----------|-----------|--------------|:------:|
| List policies | `ListPolicies(ctx)` | `GET /policies` | ✅ |

## 🔌 Scanners

| Resource | SDK Method | API Endpoint | Status |
|----------|-----------|--------------|:------:|
| List scanners | `ListScanners(ctx)` | `GET /scanners` | ✅ |

## 🖥️ Server

| Resource | SDK Method | API Endpoint | Status |
|----------|-----------|--------------|:------:|
| Server properties | `ServerProperties(ctx)` | `GET /server/properties` | ✅ |

## 🚫 Not in Scope

| Resource | API Endpoint | Reason |
|----------|-------------|--------|
| Folders | `GET /folders` | Not needed for ingestion |
| Server status | `GET /server/status` | Not needed for ingestion |
| Create/launch scans | `POST /scans` | Read-only SDK |

## 📈 Summary

| Category | Done | Future | Total |
|----------|:----:|:------:|:-----:|
| Scans | 3 | 0 | 3 |
| Hosts | 1 | 0 | 1 |
| Findings | 1 | 0 | 1 |
| Export | 4 | 0 | 4 |
| Parser | 1 | 0 | 1 |
| Agents | 2 | 0 | 2 |
| Agent Groups | 1 | 0 | 1 |
| Policies | 1 | 0 | 1 |
| Scanners | 1 | 0 | 1 |
| Server | 1 | 0 | 1 |
| **Total** | **16** | **0** | **16** |
