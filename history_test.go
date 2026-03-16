package nessus

import (
	"context"
	"testing"
)

func TestGetScanHistory(t *testing.T) {
	client := newTestClient(t, map[string]string{
		"/scans/42": `{
			"info": {"name": "Weekly Scan", "status": "completed"},
			"hosts": [],
			"history": [
				{"history_id": 100, "status": "completed", "creation_date": 1700000000},
				{"history_id": 101, "status": "completed", "creation_date": 1700100000},
				{"history_id": 102, "status": "running", "creation_date": 1700200000}
			]
		}`,
	})

	history, err := client.GetScanHistory(context.Background(), 42)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 3 {
		t.Fatalf("len = %d, want 3", len(history))
	}

	if history[0].HistoryID != 100 {
		t.Errorf("HistoryID = %d", history[0].HistoryID)
	}
	if history[0].Status != "completed" {
		t.Errorf("Status = %q", history[0].Status)
	}
	if history[0].CreationDate != 1700000000 {
		t.Errorf("CreationDate = %d", history[0].CreationDate)
	}
	if history[2].Status != "running" {
		t.Errorf("Status = %q", history[2].Status)
	}
}
