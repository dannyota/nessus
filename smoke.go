//go:build ignore

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"text/tabwriter"
	"time"

	"danny.vn/nessus"
)

type config struct {
	Address     string `json:"address"`
	AccessKey   string `json:"access_key"`
	SecretKey   string `json:"secret_key"`
	InsecureTLS bool   `json:"insecure_tls"`
}

func loadConfig() config {
	var cfg config

	// Load from .nessus.json if it exists.
	if data, err := os.ReadFile(".nessus.json"); err == nil {
		if err := json.Unmarshal(data, &cfg); err != nil {
			log.Fatalf("invalid .nessus.json: %v", err)
		}
	}

	// Env vars override file values.
	if v := os.Getenv("NESSUS_ADDRESS"); v != "" {
		cfg.Address = v
	}
	if v := os.Getenv("NESSUS_ACCESS_KEY"); v != "" {
		cfg.AccessKey = v
	}
	if v := os.Getenv("NESSUS_SECRET_KEY"); v != "" {
		cfg.SecretKey = v
	}

	if cfg.Address == "" || cfg.AccessKey == "" || cfg.SecretKey == "" {
		fmt.Fprintln(os.Stderr, "Create .nessus.json or set NESSUS_ADDRESS, NESSUS_ACCESS_KEY, NESSUS_SECRET_KEY")
		os.Exit(1)
	}

	return cfg
}

// writeSample writes a JSON sample file to samples/<name>.json.
func writeSample(name string, v any) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: marshal %s sample: %v\n", name, err)
		return
	}
	os.MkdirAll("samples", 0o755)
	path := fmt.Sprintf("samples/%s.json", name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "warning: write %s: %v\n", path, err)
		return
	}
	fmt.Printf("  → %s (%d bytes)\n", path, len(data))
}

func main() {
	cfg := loadConfig()

	var opts []nessus.ClientOption
	opts = append(opts, nessus.WithAPIKeys(cfg.AccessKey, cfg.SecretKey))
	if cfg.InsecureTLS {
		opts = append(opts, nessus.WithInsecureTLS())
	}

	ctx := context.Background()

	client, err := nessus.NewClient(cfg.Address, opts...)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	fmt.Printf("Connecting to %s...\n", cfg.Address)

	// List scans.
	scans, err := client.ListScans(ctx)
	if err != nil {
		log.Fatalf("ListScans: %v", err)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintf(w, "ID\tNAME\tSTATUS\tFOLDER\n")
	for _, s := range scans {
		fmt.Fprintf(w, "%d\t%s\t%s\t%d\n", s.ID, s.Name, s.Status, s.FolderID)
	}
	w.Flush()
	fmt.Println()

	// Use the first (latest) completed scan.
	var exportScanID int
	for _, s := range scans {
		if s.Status == "completed" {
			exportScanID = s.ID
			break
		}
	}
	if exportScanID == 0 {
		fmt.Println("No completed scans found.")
		return
	}

	// --- Scan History ---
	fmt.Printf("=== Scan History (scan %d) ===\n", exportScanID)
	history, err := client.GetScanHistory(ctx, exportScanID)
	if err != nil {
		fmt.Printf("  GetScanHistory: %v\n", err)
	} else {
		fmt.Fprintf(w, "HISTORY_ID\tSTATUS\tDATE\n")
		for _, h := range firstN(history, 5) {
			fmt.Fprintf(w, "%d\t%s\t%s\n", h.HistoryID, h.Status, time.Unix(h.CreationDate, 0).Format("2006-01-02 15:04"))
		}
		if len(history) > 5 {
			fmt.Fprintf(w, "... and %d more\n", len(history)-5)
		}
		w.Flush()
		fmt.Println()
		writeSample("scan_history", history)
	}

	// --- Scan Host Detail + OS Detection ---
	detail, err := client.GetScan(ctx, exportScanID)
	if err != nil {
		fmt.Printf("  GetScan: %v\n", err)
	} else if len(detail.Hosts) > 0 {
		firstHost := detail.Hosts[0]
		fmt.Printf("=== Scan Host Detail (host %d) ===\n", firstHost.HostID)
		hd, err := client.GetHostDetails(ctx, exportScanID, firstHost.HostID)
		if err != nil {
			fmt.Printf("  GetHostDetails: %v\n", err)
		} else {
			fmt.Printf("  IP:          %s\n", hd.IP)
			fmt.Printf("  FQDN:        %s\n", hd.FQDN)
			fmt.Printf("  OS:          %s\n", hd.OS)
			fmt.Printf("  OS Family:   %s\n", nessus.OSFamily(hd.OS))
			fmt.Printf("  MAC:         %s\n", hd.MAC)
			fmt.Printf("  NetBIOS:     %s\n", hd.NetBIOSName)
			fmt.Printf("  Vulns:       %d\n", len(hd.Vulnerabilities))
			fmt.Println()
			writeSample("host_detail", hd)
		}
	}

	// --- Export & Parse ---
	fmt.Printf("=== Export & Parse (scan %d) ===\n", exportScanID)
	fmt.Println("Requesting export...")

	start := time.Now()
	result, err := client.ExportAndWait(ctx, exportScanID)
	if err != nil {
		fmt.Printf("  ExportAndWait: %v\n", err)
	} else {
		elapsed := time.Since(start)
		fmt.Printf("  Downloaded and parsed in %s\n", elapsed.Round(time.Millisecond))
		fmt.Printf("  Report: %s\n", result.Name)
		fmt.Printf("  Hosts: %d\n\n", len(result.Hosts))

		// Show host summary.
		fmt.Fprintf(w, "HOST\tIP\tOS\tFAMILY\tFINDINGS\tCRIT\tHIGH\n")
		for _, h := range firstN(result.Hosts, 20) {
			crit, high := 0, 0
			for _, f := range h.Findings {
				if f.Severity == nessus.SeverityCritical {
					crit++
				}
				if f.Severity == nessus.SeverityHigh {
					high++
				}
			}
			osInfo := nessus.ExtractOS(h)
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%d\t%d\n",
				h.Hostname, h.IP, truncate(osInfo.Name, 30), osInfo.Family, len(h.Findings), crit, high)
		}
		w.Flush()
		fmt.Println()

		// Show first critical finding with evidence.
		for _, h := range result.Hosts {
			for _, f := range h.Findings {
				if f.Severity >= nessus.SeverityHigh && f.Output != "" {
					fmt.Printf("=== Example Finding ===\n")
					fmt.Printf("  Host: %s (%s)\n", h.Hostname, h.IP)
					fmt.Printf("  Plugin: %d - %s\n", f.PluginID, f.PluginName)
					fmt.Printf("  Severity: %s, Risk Factor: %s\n", nessus.SeverityName(f.Severity), f.RiskFactor)
					fmt.Printf("  CVSS: %.1f  CVSS3: %.1f\n", f.CVSSBaseScore, f.CVSS3BaseScore)
					if len(f.CVE) > 0 {
						fmt.Printf("  CVEs: %v\n", f.CVE)
					}
					fmt.Printf("  Synopsis: %s\n", f.Synopsis)
					fmt.Printf("  Solution: %s\n", f.Solution)
					fmt.Printf("  Evidence:\n    %s\n", truncate(f.Output, 200))
					fmt.Println()
					writeSample("export_finding", f)
					goto done
				}
			}
		}
	done:

		// Stats.
		totalFindings := 0
		for _, h := range result.Hosts {
			totalFindings += len(h.Findings)
		}
		fmt.Printf("Total: %d hosts, %d findings\n\n", len(result.Hosts), totalFindings)

		writeSample("export_result_hosts", firstN(result.Hosts, 3))
	}

	fmt.Println("Writing samples/...")
	writeSample("scans", scans)

	// --- Raw API capture for new endpoints ---
	fmt.Println("\n=== Raw API Capture ===")
	rawEndpoints := map[string]string{
		"agents":             "/agents",
		"agent_groups":       "/agent-groups",
		"scanners":           "/scanners",
		"server_properties":  "/server/properties",
	}
	for name, path := range rawEndpoints {
		fmt.Printf("  GET %s ... ", path)
		body, err := rawGet(cfg, path)
		if err != nil {
			fmt.Printf("ERROR: %v\n", err)
			continue
		}
		// Pretty-print the JSON.
		var pretty json.RawMessage
		if json.Unmarshal(body, &pretty) == nil {
			formatted, _ := json.MarshalIndent(pretty, "", "  ")
			body = formatted
		}
		os.MkdirAll("samples", 0o755)
		p := fmt.Sprintf("samples/%s.json", name)
		if err := os.WriteFile(p, body, 0o644); err != nil {
			fmt.Printf("write error: %v\n", err)
			continue
		}
		fmt.Printf("OK → %s (%d bytes)\n", p, len(body))
	}
}

// firstN returns the first n items from a slice (or all if fewer).
func firstN[T any](s []T, n int) []T {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// rawGet makes an authenticated GET request and returns the raw response body.
func rawGet(cfg config, path string) ([]byte, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: cfg.InsecureTLS}
	hc := &http.Client{Transport: tr, Timeout: 30 * time.Second}

	req, err := http.NewRequest("GET", cfg.Address+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-ApiKeys", fmt.Sprintf("accessKey=%s;secretKey=%s", cfg.AccessKey, cfg.SecretKey))
	req.Header.Set("Accept", "application/json")

	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body[:min(len(body), 200)]))
	}
	return body, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
