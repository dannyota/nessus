# nessus

Unofficial Go SDK for Nessus self-hosted scanner REST API.

> **Self-hosted only.** This SDK targets Nessus Professional/Expert/Essentials
> running on your own infrastructure. It does **not** support Tenable.io
> (cloud), which has a different API.

## 📚 Install

```bash
go get danny.vn/nessus
```

Requires Go 1.24+.

## 🚀 Quick Start

```go
package main

import (
	"context"
	"fmt"
	"log"

	"danny.vn/nessus"
)

func main() {
	client, err := nessus.NewClient("https://nessus.example.com:8834",
		nessus.WithAPIKeys("access-key", "secret-key"),
		nessus.WithInsecureTLS(), // self-signed certs
	)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	scans, err := client.ListScans(ctx)
	if err != nil {
		log.Fatal(err)
	}
	for _, s := range scans {
		fmt.Printf("%s (status: %s)\n", s.Name, s.Status)
	}
}
```

## 🛡️ Supported Resources

Read-only. See [FEATURES.md](docs/FEATURES.md) for details.

| Category | Resources | Count |
|----------|-----------|:-----:|
| Scans | List scans, scan details, history | 3 |
| Hosts | Host details per scan | 1 |
| Findings | Plugin output per host | 1 |
| Export | Export, poll, download, parse | 4 |
| Agents | List agents, paginated listing | 2 |
| Agent Groups | List agent groups | 1 |
| Policies | List scan policies | 1 |
| Scanners | List scanners | 1 |
| Server | Server properties | 1 |

## ✅ Testing

```bash
go test ./...
```

Smoke test against a live Nessus scanner:

```bash
NESSUS_ADDRESS=https://nessus.example.com:8834 \
NESSUS_ACCESS_KEY=your-access-key \
NESSUS_SECRET_KEY=your-secret-key \
go run smoke.go
```

Basic read-only mapping check with raw and SDK output:

```bash
go run ./examples/basic
```

The example reads `.nessus.json` by default and writes local output under
`examples/basic/output/`.

## 📖 Documentation

| Document | Description |
|----------|-------------|
| [ARCHITECTURE](docs/ARCHITECTURE.md) | API protocol, package layout, design decisions |
| [FEATURES](docs/FEATURES.md) | Resource coverage |
| [PLAN](docs/PLAN.md) | Development roadmap |

## 📋 License

MIT — see [LICENSE](LICENSE).
