package nessus

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// newTestClient creates an httptest.Server with fixture routing and returns a
// configured Client. Fixtures map URL path → JSON response body.
// The server is cleaned up when the test finishes.
func newTestClient(t *testing.T, fixtures map[string]string) *Client {
	t.Helper()

	mux := http.NewServeMux()

	for path, body := range fixtures {
		body := body // capture
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			// Verify API key auth header.
			apiKeys := r.Header.Get("X-ApiKeys")
			if apiKeys != "accessKey=test-access;secretKey=test-secret" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"Invalid Credentials"}`))
				return
			}

			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		})
	}

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	client, err := NewClient(server.URL, WithAPIKeys("test-access", "test-secret"))
	if err != nil {
		t.Fatal(err)
	}

	return client
}
