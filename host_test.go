package nessus

import (
	"context"
	"testing"
)

func TestGetHostDetails(t *testing.T) {
	client := newTestClient(t, map[string]string{
		"/scans/42/hosts/1": `{
			"info": {
				"host-ip": "192.168.1.10",
				"host-fqdn": "web-01.example.com",
				"operating-system": "Linux 5.15"
			},
			"vulnerabilities": [
				{
					"plugin_id": 12345,
					"plugin_name": "SSL Certificate Expired",
					"plugin_family": "General",
					"severity": 4,
					"count": 1
				},
				{
					"plugin_id": 67890,
					"plugin_name": "SSH Weak Algorithms",
					"plugin_family": "Misc.",
					"severity": 2,
					"count": 3
				}
			]
		}`,
	})

	vulns, err := client.GetHostDetails(context.Background(), 42, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) != 2 {
		t.Fatalf("len = %d, want 2", len(vulns))
	}

	v := vulns[0]
	if v.PluginID != 12345 {
		t.Errorf("PluginID = %d", v.PluginID)
	}
	if v.PluginName != "SSL Certificate Expired" {
		t.Errorf("PluginName = %q", v.PluginName)
	}
	if v.PluginFamily != "General" {
		t.Errorf("PluginFamily = %q", v.PluginFamily)
	}
	if v.Severity != SeverityCritical {
		t.Errorf("Severity = %d, want SeverityCritical", v.Severity)
	}
	if v.Count != 1 {
		t.Errorf("Count = %d", v.Count)
	}

	v2 := vulns[1]
	if v2.Severity != SeverityMedium {
		t.Errorf("Severity = %d, want SeverityMedium", v2.Severity)
	}
}

func TestGetHostDetails_Empty(t *testing.T) {
	client := newTestClient(t, map[string]string{
		"/scans/42/hosts/1": `{
			"info": {"host-ip": "10.0.0.1"},
			"vulnerabilities": []
		}`,
	})

	vulns, err := client.GetHostDetails(context.Background(), 42, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) != 0 {
		t.Fatalf("len = %d, want 0", len(vulns))
	}
}
