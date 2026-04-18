package nessus

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"strings"
)

// Client communicates with a Nessus self-hosted scanner via its REST API.
type Client struct {
	address    string
	config     clientConfig
	httpClient *http.Client
	logger     *slog.Logger
}

// NewClient creates a new Nessus client.
// Address is the base URL (e.g. "https://nessus.example.com:8834").
// At minimum, WithAPIKeys must be provided.
//
// HTTP client precedence: WithHTTPClient > WithTransport > default.
// When WithHTTPClient is used, WithTransport, WithTimeout, and WithInsecureTLS
// are ignored — the caller controls the full HTTP stack.
func NewClient(address string, opts ...ClientOption) (*Client, error) {
	if address == "" {
		return nil, errors.New("nessus: address is required")
	}

	cfg := clientConfig{
		timeout:   defaultTimeout,
		userAgent: defaultUserAgent,
	}
	for _, o := range opts {
		o.apply(&cfg)
	}

	if cfg.accessKey == "" || cfg.secretKey == "" {
		return nil, errors.New("nessus: API keys are required (use WithAPIKeys)")
	}

	address = strings.TrimRight(address, "/")

	var httpClient *http.Client
	switch {
	case cfg.httpClient != nil:
		httpClient = cfg.httpClient
	case cfg.transport != nil:
		httpClient = &http.Client{
			Transport: cfg.transport,
			Timeout:   cfg.timeout,
		}
	default:
		httpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: cfg.insecureTLS,
				},
			},
			Timeout: cfg.timeout,
		}
	}

	logger := cfg.logger
	if logger == nil {
		logger = slog.New(nopHandler{})
	}

	return &Client{
		address:    address,
		config:     cfg,
		httpClient: httpClient,
		logger:     logger,
	}, nil
}

// Close releases resources. No-op for Nessus (stateless API key auth).
func (c *Client) Close() error {
	return nil
}

type nopHandler struct{}

func (nopHandler) Enabled(context.Context, slog.Level) bool  { return false }
func (nopHandler) Handle(context.Context, slog.Record) error { return nil }
func (h nopHandler) WithAttrs([]slog.Attr) slog.Handler      { return h }
func (h nopHandler) WithGroup(string) slog.Handler           { return h }
