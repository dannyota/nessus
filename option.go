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

// clientConfig holds resolved options.
type clientConfig struct {
	accessKey   string
	secretKey   string
	insecureTLS bool
	timeout     time.Duration
	transport   http.RoundTripper
	httpClient  *http.Client
	userAgent   string
}

// WithAPIKeys sets the access key and secret key for Nessus API authentication.
type withAPIKeys struct{ accessKey, secretKey string }

func (o withAPIKeys) apply(c *clientConfig) { c.accessKey = o.accessKey; c.secretKey = o.secretKey }
func WithAPIKeys(accessKey, secretKey string) ClientOption {
	return withAPIKeys{accessKey, secretKey}
}

// WithInsecureTLS disables TLS certificate verification.
type withInsecureTLS struct{}

func (withInsecureTLS) apply(c *clientConfig) { c.insecureTLS = true }
func WithInsecureTLS() ClientOption            { return withInsecureTLS{} }

// WithTimeout sets the HTTP client timeout.
type withTimeout struct{ d time.Duration }

func (o withTimeout) apply(c *clientConfig) { c.timeout = o.d }
func WithTimeout(d time.Duration) ClientOption { return withTimeout{d} }

// WithTransport sets a custom RoundTripper (e.g. for rate limiting).
type withTransport struct{ rt http.RoundTripper }

func (o withTransport) apply(c *clientConfig) { c.transport = o.rt }
func WithTransport(rt http.RoundTripper) ClientOption { return withTransport{rt} }

// WithHTTPClient replaces the entire HTTP client.
// When used, WithTransport, WithTimeout, and WithInsecureTLS are ignored.
type withHTTPClient struct{ c *http.Client }

func (o withHTTPClient) apply(c *clientConfig) { c.httpClient = o.c }
func WithHTTPClient(hc *http.Client) ClientOption { return withHTTPClient{hc} }

// WithUserAgent overrides the User-Agent header.
type withUserAgent struct{ ua string }

func (o withUserAgent) apply(c *clientConfig) { c.userAgent = o.ua }
func WithUserAgent(ua string) ClientOption { return withUserAgent{ua} }
