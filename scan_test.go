package nessus

import (
	"context"
	"testing"
)

func TestListScans(t *testing.T) {
	client := newTestClient(t, map[string]string{
		"/scans": `{
			"scans": [
				{
					"id": 42,
					"name": "Weekly Scan",
					"status": "completed",
					"folder_id": 3,
					"enabled": true,
					"control": true,
					"last_modification_date": 1700000000,
					"creation_date": 1690000000,
					"user_permissions": 128
				},
				{
					"id": 43,
					"name": "Quick Scan",
					"status": "running",
					"folder_id": 3,
					"enabled": true,
					"control": false,
					"last_modification_date": 1700001000,
					"creation_date": 1690001000,
					"user_permissions": 128
				}
			]
		}`,
	})

	scans, err := client.ListScans(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(scans) != 2 {
		t.Fatalf("len = %d, want 2", len(scans))
	}

	s := scans[0]
	if s.ID != 42 {
		t.Errorf("ID = %d, want 42", s.ID)
	}
	if s.Name != "Weekly Scan" {
		t.Errorf("Name = %q", s.Name)
	}
	if s.Status != "completed" {
		t.Errorf("Status = %q", s.Status)
	}
	if s.FolderID != 3 {
		t.Errorf("FolderID = %d", s.FolderID)
	}
	if !s.Enabled {
		t.Error("Enabled = false")
	}
	if s.LastModified != 1700000000 {
		t.Errorf("LastModified = %d", s.LastModified)
	}
}

func TestListScans_Empty(t *testing.T) {
	client := newTestClient(t, map[string]string{
		"/scans": `{"scans": null}`,
	})

	scans, err := client.ListScans(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(scans) != 0 {
		t.Fatalf("len = %d, want 0", len(scans))
	}
}

func TestGetScan(t *testing.T) {
	client := newTestClient(t, map[string]string{
		"/scans/42": `{
			"info": {
				"name": "Weekly Scan",
				"status": "completed",
				"policy": "Advanced Scan",
				"scanner_name": "Local Scanner",
				"targets": "192.168.1.0/24",
				"scanner_start": 1700000000,
				"scanner_end": 1700003600,
				"hostcount": 2
			},
			"hosts": [
				{
					"host_id": 1,
					"hostname": "web-01",
					"host_ip": "192.168.1.10",
					"operating-system": "Linux 5.15",
					"critical": 2,
					"high": 5,
					"medium": 12,
					"low": 3,
					"info": 45,
					"progress": "100"
				},
				{
					"host_id": 2,
					"hostname": "db-01",
					"host_ip": "192.168.1.20",
					"operating-system": "Ubuntu 22.04",
					"critical": 0,
					"high": 1,
					"medium": 4,
					"low": 2,
					"info": 30,
					"progress": "100"
				}
			]
		}`,
	})

	detail, err := client.GetScan(context.Background(), 42)
	if err != nil {
		t.Fatal(err)
	}

	if detail.Info.Name != "Weekly Scan" {
		t.Errorf("Info.Name = %q", detail.Info.Name)
	}
	if detail.Info.Status != "completed" {
		t.Errorf("Info.Status = %q", detail.Info.Status)
	}
	if detail.Info.Policy != "Advanced Scan" {
		t.Errorf("Info.Policy = %q", detail.Info.Policy)
	}
	if detail.Info.Targets != "192.168.1.0/24" {
		t.Errorf("Info.Targets = %q", detail.Info.Targets)
	}
	if detail.Info.HostCount != 2 {
		t.Errorf("Info.HostCount = %d", detail.Info.HostCount)
	}

	if len(detail.Hosts) != 2 {
		t.Fatalf("len(Hosts) = %d, want 2", len(detail.Hosts))
	}

	h := detail.Hosts[0]
	if h.HostID != 1 {
		t.Errorf("HostID = %d", h.HostID)
	}
	if h.Hostname != "web-01" {
		t.Errorf("Hostname = %q", h.Hostname)
	}
	if h.IP != "192.168.1.10" {
		t.Errorf("IP = %q", h.IP)
	}
	if h.Critical != 2 {
		t.Errorf("Critical = %d", h.Critical)
	}
	if h.High != 5 {
		t.Errorf("High = %d", h.High)
	}
}
