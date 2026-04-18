package nessus

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExportScan(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/scans/42/export", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		// Verify auth.
		if r.Header.Get("X-ApiKeys") != "accessKey=test-ak;secretKey=test-sk" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// Verify body.
		var body struct {
			Format string `json:"format"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode body: %v", err)
		}
		if body.Format != "nessus" {
			t.Errorf("format = %q, want nessus", body.Format)
		}

		_, _ = w.Write([]byte(`{"token":"abc-123","file":0}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client, err := NewClient(server.URL, WithAPIKeys("test-ak", "test-sk"))
	if err != nil {
		t.Fatal(err)
	}

	token, err := client.ExportScan(context.Background(), 42)
	if err != nil {
		t.Fatal(err)
	}
	if token != "abc-123" {
		t.Errorf("token = %q, want abc-123", token)
	}
}

func TestExportScanWithHistoryID(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/scans/42/export", func(w http.ResponseWriter, r *http.Request) {
		historyID := r.URL.Query().Get("history_id")
		if historyID != "100" {
			t.Errorf("history_id = %q, want 100", historyID)
		}
		_, _ = w.Write([]byte(`{"token":"def-456","file":0}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client, err := NewClient(server.URL, WithAPIKeys("a", "s"))
	if err != nil {
		t.Fatal(err)
	}

	token, err := client.ExportScan(context.Background(), 42, WithHistoryID(100))
	if err != nil {
		t.Fatal(err)
	}
	if token != "def-456" {
		t.Errorf("token = %q", token)
	}
}

func TestExportStatus(t *testing.T) {
	client := newTestClient(t, map[string]string{
		"/tokens/abc-123/status": `{"status":"ready"}`,
	})

	status, err := client.ExportStatus(context.Background(), "abc-123")
	if err != nil {
		t.Fatal(err)
	}
	if status != "ready" {
		t.Errorf("status = %q, want ready", status)
	}
}

func TestDownloadExport(t *testing.T) {
	xmlData := `<?xml version="1.0"?><NessusClientData_v2><Report name="Test"></Report></NessusClientData_v2>`
	client := newTestClient(t, map[string]string{
		"/tokens/abc-123/download": xmlData,
	})

	data, err := client.DownloadExport(context.Background(), "abc-123")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != xmlData {
		t.Errorf("data = %q", string(data))
	}
}

func TestExportScanFileIDFallback(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/scans/42/export", func(w http.ResponseWriter, r *http.Request) {
		// Some Nessus versions return file ID, not token.
		_, _ = w.Write([]byte(`{"token":"","file":789}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client, err := NewClient(server.URL, WithAPIKeys("a", "s"))
	if err != nil {
		t.Fatal(err)
	}

	token, err := client.ExportScan(context.Background(), 42)
	if err != nil {
		t.Fatal(err)
	}
	if token != "789" {
		t.Errorf("token = %q, want 789", token)
	}
}

func TestExportScanNoTokenOrFile(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/scans/42/export", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"token":"","file":0}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client, err := NewClient(server.URL, WithAPIKeys("a", "s"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.ExportScan(context.Background(), 42)
	if err == nil {
		t.Fatal("expected error for missing token and file ID")
	}
}
