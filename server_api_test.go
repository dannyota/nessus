package nessus

import (
	"context"
	"testing"
)

func TestServerProperties(t *testing.T) {
	client := newTestClient(t, map[string]string{
		"/server/properties": `{
			"nessus_type": "Nessus Manager",
			"server_uuid": "00000000-0000-0000-0000-000000000000aabbccddeeff1234",
			"nessus_ui_version": "10.0.0",
			"platform": "LINUX",
			"plugin_set": "202501010000",
			"expiration": 1735689600,
			"license": {
				"type": "manager",
				"ips": 500,
				"agents": 500,
				"agents_used": 156,
				"scanners": 0,
				"scanners_used": 0
			}
		}`,
	})

	info, err := client.ServerProperties(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if info.NessusType != "Nessus Manager" {
		t.Errorf("NessusType = %q", info.NessusType)
	}
	if info.ServerUUID != "00000000-0000-0000-0000-000000000000aabbccddeeff1234" {
		t.Errorf("ServerUUID = %q", info.ServerUUID)
	}
	if info.Version != "10.0.0" {
		t.Errorf("Version = %q", info.Version)
	}
	if info.Platform != "LINUX" {
		t.Errorf("Platform = %q", info.Platform)
	}
	if info.PluginSet != "202501010000" {
		t.Errorf("PluginSet = %q", info.PluginSet)
	}
	if info.LicenseType != "manager" {
		t.Errorf("LicenseType = %q", info.LicenseType)
	}
	if info.LicenseExpiry != 1735689600 {
		t.Errorf("LicenseExpiry = %d", info.LicenseExpiry)
	}
	if info.LicensedHosts != 500 {
		t.Errorf("LicensedHosts = %d", info.LicensedHosts)
	}
	if info.LicensedAgents != 500 {
		t.Errorf("LicensedAgents = %d", info.LicensedAgents)
	}
	if info.AgentsUsed != 156 {
		t.Errorf("AgentsUsed = %d", info.AgentsUsed)
	}
	if info.LicensedScanners != 0 {
		t.Errorf("LicensedScanners = %d", info.LicensedScanners)
	}
	if info.ScannersUsed != 0 {
		t.Errorf("ScannersUsed = %d", info.ScannersUsed)
	}
}
