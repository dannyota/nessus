package nessus

import (
	"net/http"
	"time"
)

const (
	defaultTimeout   = 30 * time.Second
	defaultUserAgent = "nessus-go/0.1"
)

// ClientOption configures the Client.
type ClientOption interface {
	apply(*clientConfig)
}

type clientConfig struct {
	accessKey   string
	secretKey   string
	insecureTLS bool
	timeout     time.Duration
	transport   http.RoundTripper
	httpClient  *http.Client
	userAgent   string
}

type withAPIKeys struct{ accessKey, secretKey string }

func (o withAPIKeys) apply(c *clientConfig) { c.accessKey = o.accessKey; c.secretKey = o.secretKey }

// WithAPIKeys sets the access key and secret key for Nessus API authentication.
func WithAPIKeys(accessKey, secretKey string) ClientOption {
	return withAPIKeys{accessKey, secretKey}
}

type withInsecureTLS struct{}

func (withInsecureTLS) apply(c *clientConfig) { c.insecureTLS = true }

// WithInsecureTLS disables TLS certificate verification.
// Use only for scanners with self-signed certificates on trusted networks.
func WithInsecureTLS() ClientOption { return withInsecureTLS{} }

type withTimeout struct{ d time.Duration }

func (o withTimeout) apply(c *clientConfig) { c.timeout = o.d }

// WithTimeout sets the HTTP client timeout.
func WithTimeout(d time.Duration) ClientOption { return withTimeout{d} }

type withTransport struct{ rt http.RoundTripper }

func (o withTransport) apply(c *clientConfig) { c.transport = o.rt }

// WithTransport sets a custom RoundTripper (e.g. for rate limiting).
func WithTransport(rt http.RoundTripper) ClientOption { return withTransport{rt} }

type withHTTPClient struct{ c *http.Client }

func (o withHTTPClient) apply(c *clientConfig) { c.httpClient = o.c }

// WithHTTPClient replaces the entire HTTP client.
// When used, WithTransport, WithTimeout, and WithInsecureTLS are ignored.
func WithHTTPClient(hc *http.Client) ClientOption { return withHTTPClient{hc} }

type withUserAgent struct{ ua string }

func (o withUserAgent) apply(c *clientConfig) { c.userAgent = o.ua }

// WithUserAgent overrides the User-Agent header.
func WithUserAgent(ua string) ClientOption { return withUserAgent{ua} }
