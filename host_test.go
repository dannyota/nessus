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
				"hostname": "web-01",
				"operating-system": "Linux 5.15",
				"mac-address": "00:1A:2B:3C:4D:5E",
				"netbios-name": "WEB01"
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

	detail, err := client.GetHostDetails(context.Background(), 42, 1)
	if err != nil {
		t.Fatal(err)
	}

	// Host info.
	if detail.IP != "192.168.1.10" {
		t.Errorf("IP = %q", detail.IP)
	}
	if detail.FQDN != "web-01.example.com" {
		t.Errorf("FQDN = %q", detail.FQDN)
	}
	if detail.Hostname != "web-01" {
		t.Errorf("Hostname = %q", detail.Hostname)
	}
	if detail.OS != "Linux 5.15" {
		t.Errorf("OS = %q", detail.OS)
	}
	if detail.MAC != "00:1A:2B:3C:4D:5E" {
		t.Errorf("MAC = %q", detail.MAC)
	}
	if detail.NetBIOSName != "WEB01" {
		t.Errorf("NetBIOSName = %q", detail.NetBIOSName)
	}

	// Vulnerabilities.
	if len(detail.Vulnerabilities) != 2 {
		t.Fatalf("len = %d, want 2", len(detail.Vulnerabilities))
	}

	v := detail.Vulnerabilities[0]
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

	v2 := detail.Vulnerabilities[1]
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

	detail, err := client.GetHostDetails(context.Background(), 42, 1)
	if err != nil {
		t.Fatal(err)
	}
	if detail.IP != "10.0.0.1" {
		t.Errorf("IP = %q", detail.IP)
	}
	if len(detail.Vulnerabilities) != 0 {
		t.Fatalf("len = %d, want 0", len(detail.Vulnerabilities))
	}
}
