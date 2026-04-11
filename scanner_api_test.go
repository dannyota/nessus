package nessus

import (
	"context"
	"testing"
)

func TestListScanners(t *testing.T) {
	client := newTestClient(t, map[string]string{
		"/scanners": `{
			"scanners": [
				{
					"id": 1,
					"uuid": "00000000-0000-0000-0000-000000000000",
					"name": "Local Scanner",
					"status": "on",
					"type": "local",
					"platform": "LINUX",
					"ui_version": "10.8.3",
					"engine_version": "19.10.3",
					"linked": 1
				}
			]
		}`,
	})

	scanners, err := client.ListScanners(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if len(scanners) != 1 {
		t.Fatalf("len = %d, want 1", len(scanners))
	}

	s := scanners[0]
	if s.ID != 1 {
		t.Errorf("ID = %d", s.ID)
	}
	if s.Name != "Local Scanner" {
		t.Errorf("Name = %q", s.Name)
	}
	if s.Status != "on" {
		t.Errorf("Status = %q", s.Status)
	}
	if s.Type != "local" {
		t.Errorf("Type = %q", s.Type)
	}
	if s.UIVersion != "10.8.3" {
		t.Errorf("UIVersion = %q", s.UIVersion)
	}
	if s.EngineVersion != "19.10.3" {
		t.Errorf("EngineVersion = %q", s.EngineVersion)
	}
	if s.Linked != 1 {
		t.Errorf("Linked = %d", s.Linked)
	}
}
