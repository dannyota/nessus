package nessus

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	t.Run("empty address", func(t *testing.T) {
		_, err := NewClient("", WithAPIKeys("a", "s"))
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("no api keys", func(t *testing.T) {
		_, err := NewClient("https://example.com")
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("defaults", func(t *testing.T) {
		c, err := NewClient("https://example.com", WithAPIKeys("a", "s"))
		if err != nil {
			t.Fatal(err)
		}
		if c.config.timeout != defaultTimeout {
			t.Errorf("timeout = %v, want %v", c.config.timeout, defaultTimeout)
		}
		if c.config.userAgent != defaultUserAgent {
			t.Errorf("userAgent = %q, want %q", c.config.userAgent, defaultUserAgent)
		}
	})

	t.Run("trailing slash stripped", func(t *testing.T) {
		c, err := NewClient("https://example.com/", WithAPIKeys("a", "s"))
		if err != nil {
			t.Fatal(err)
		}
		if c.address != "https://example.com" {
			t.Errorf("address = %q, want no trailing slash", c.address)
		}
	})

	t.Run("all options", func(t *testing.T) {
		transport := &http.Transport{}
		c, err := NewClient("https://example.com",
			WithAPIKeys("ak", "sk"),
			WithInsecureTLS(),
			WithTimeout(5*time.Second),
			WithTransport(transport),
			WithUserAgent("test/1.0"),
		)
		if err != nil {
			t.Fatal(err)
		}
		if c.config.accessKey != "ak" {
			t.Errorf("accessKey = %q", c.config.accessKey)
		}
		if c.config.secretKey != "sk" {
			t.Errorf("secretKey = %q", c.config.secretKey)
		}
		if c.config.timeout != 5*time.Second {
			t.Errorf("timeout = %v", c.config.timeout)
		}
		if c.config.userAgent != "test/1.0" {
			t.Errorf("userAgent = %q", c.config.userAgent)
		}
	})

	t.Run("with http client", func(t *testing.T) {
		hc := &http.Client{Timeout: 10 * time.Second}
		c, err := NewClient("https://example.com",
			WithAPIKeys("a", "s"),
			WithHTTPClient(hc),
		)
		if err != nil {
			t.Fatal(err)
		}
		if c.httpClient != hc {
			t.Error("expected custom http client")
		}
	})

	t.Run("insecure tls", func(t *testing.T) {
		c, err := NewClient("https://example.com",
			WithAPIKeys("a", "s"),
			WithInsecureTLS(),
		)
		if err != nil {
			t.Fatal(err)
		}
		tr, ok := c.httpClient.Transport.(*http.Transport)
		if !ok {
			t.Fatal("transport is not *http.Transport")
		}
		if !tr.TLSClientConfig.InsecureSkipVerify {
			t.Error("expected InsecureSkipVerify = true")
		}
	})
}

func TestAuthFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"Invalid Credentials"}`))
	}))
	defer server.Close()

	c, err := NewClient(server.URL, WithAPIKeys("bad", "keys"))
	if err != nil {
		t.Fatal(err)
	}

	var resp struct{}
	err = c.getJSON(context.Background(), "/scans", &resp)
	if err != ErrAuth {
		t.Errorf("err = %v, want ErrAuth", err)
	}
}

func TestCertificateError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()

	c, err := NewClient(server.URL, WithAPIKeys("a", "s"))
	if err != nil {
		t.Fatal(err)
	}
	// Override transport to NOT trust the test server's cert.
	c.httpClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
	}

	var resp struct{}
	err = c.getJSON(context.Background(), "/scans", &resp)
	if err == nil {
		t.Fatal("expected certificate error")
	}
	if !isCertificateError(err) {
		t.Errorf("expected certificate error, got: %v", err)
	}
}
