//go:build ignore

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"text/tabwriter"

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

	// Get details + host vulns for the first completed scan.
	for _, s := range scans {
		if s.Status != "completed" {
			continue
		}

		fmt.Printf("Scan %d (%s):\n", s.ID, s.Name)
		detail, err := client.GetScan(ctx, s.ID)
		if err != nil {
			fmt.Printf("  GetScan: %v\n", err)
			continue
		}
		fmt.Printf("  Policy: %s, Scanner: %s, Targets: %s\n", detail.Info.Policy, detail.Info.Scanner, detail.Info.Targets)
		fmt.Printf("  Hosts: %d\n\n", len(detail.Hosts))

		fmt.Fprintf(w, "HOST\tIP\tOS\tCRIT\tHIGH\tMED\tLOW\tINFO\n")
		for _, h := range detail.Hosts {
			fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d\n",
				h.Hostname, h.IP, h.OS, h.Critical, h.High, h.Medium, h.Low, h.Info)
		}
		w.Flush()
		fmt.Println()

		// Get vulns for the first host.
		if len(detail.Hosts) > 0 {
			host := detail.Hosts[0]
			fmt.Printf("Vulnerabilities for %s (%s):\n", host.Hostname, host.IP)

			vulns, err := client.GetHostDetails(ctx, s.ID, host.HostID)
			if err != nil {
				fmt.Printf("  GetHostDetails: %v\n", err)
			} else {
				fmt.Fprintf(w, "PLUGIN\tNAME\tFAMILY\tSEVERITY\tCOUNT\n")
				for _, v := range firstN(vulns, 10) {
					fmt.Fprintf(w, "%d\t%s\t%s\t%d\t%d\n",
						v.PluginID, v.PluginName, v.PluginFamily, v.Severity, v.Count)
				}
				w.Flush()
				fmt.Println()

				// Get plugin output for the first high/critical vuln.
				for _, v := range vulns {
					if v.Severity >= 3 {
						fmt.Printf("Plugin output for %s (plugin %d):\n", v.PluginName, v.PluginID)
						output, err := client.GetPluginOutput(ctx, s.ID, host.HostID, v.PluginID)
						if err != nil {
							fmt.Printf("  GetPluginOutput: %v\n", err)
						} else {
							fmt.Printf("  Synopsis: %s\n", output.Info.Synopsis)
							fmt.Printf("  Risk: %s\n", output.Info.RiskFactor)
							fmt.Printf("  CVSS: %.1f\n", output.Info.CVSSBaseScore)
							fmt.Printf("  CVSS3: %.1f\n", output.Info.CVSS3BaseScore)
							if len(output.Info.CVE) > 0 {
								fmt.Printf("  CVEs: %v\n", output.Info.CVE)
							}
							fmt.Printf("  Solution: %s\n", output.Info.Solution)
							writeSample("plugin_output", output)
						}
						break
					}
				}
			}

			writeSample("host_vulnerabilities", firstN(vulns, 20))
		}

		// Write samples.
		writeSample("scan_detail", detail)
		break // Only process first completed scan.
	}

	// Summary.
	fmt.Println()
	fmt.Fprintf(w, "RESOURCE\tCOUNT\n")
	fmt.Fprintf(w, "Scans\t%d\n", len(scans))
	w.Flush()

	fmt.Println("\nWriting samples/...")
	writeSample("scans", scans)
}

// firstN returns the first n items from a slice (or all if fewer).
func firstN[T any](s []T, n int) []T {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
