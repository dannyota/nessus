package nessus

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// get sends an authenticated GET request and returns the raw response body.
func (c *Client) get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.address+path, nil)
	if err != nil {
		return nil, fmt.Errorf("nessus: create request: %w", err)
	}

	req.Header.Set("X-ApiKeys", fmt.Sprintf("accessKey=%s;secretKey=%s", c.config.accessKey, c.config.secretKey))
	req.Header.Set("Accept", "application/json")
	if c.config.userAgent != "" {
		req.Header.Set("User-Agent", c.config.userAgent)
	}

	c.logger.DebugContext(ctx, "request", "method", "GET", "path", path)
	start := time.Now()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.ErrorContext(ctx, "request failed", "method", "GET", "path", path, "error", err)
		if isCertificateError(err) {
			return nil, fmt.Errorf("nessus: TLS certificate error: %w", err)
		}
		return nil, fmt.Errorf("nessus: send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("nessus: read response: %w", err)
	}

	duration := time.Since(start)

	switch resp.StatusCode {
	case http.StatusOK:
		c.logger.DebugContext(ctx, "response", "method", "GET", "path", path, "status", resp.StatusCode, "duration", duration, "bytes", len(body))
		return body, nil
	case http.StatusUnauthorized:
		c.logger.WarnContext(ctx, "api error", "method", "GET", "path", path, "status", resp.StatusCode)
		return nil, ErrAuth
	case http.StatusForbidden:
		c.logger.WarnContext(ctx, "api error", "method", "GET", "path", path, "status", resp.StatusCode)
		return nil, ErrPermission
	case http.StatusNotFound:
		c.logger.WarnContext(ctx, "api error", "method", "GET", "path", path, "status", resp.StatusCode)
		return nil, ErrNotFound
	default:
		msg := string(body)
		var errResp struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			msg = errResp.Error
		}
		c.logger.WarnContext(ctx, "api error", "method", "GET", "path", path, "status", resp.StatusCode)
		return nil, &APIError{StatusCode: resp.StatusCode, Message: msg}
	}
}

// getJSON sends an authenticated GET request and unmarshals the response into v.
func (c *Client) getJSON(ctx context.Context, path string, v any) error {
	body, err := c.get(ctx, path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("nessus: parse response: %w", err)
	}
	return nil
}

// post sends an authenticated POST request with a JSON body and returns the raw response body.
func (c *Client) post(ctx context.Context, path string, body any) ([]byte, error) {
	jsonData, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("nessus: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.address+path, bytes.NewReader(jsonData))
	if err != nil {
		return nil, fmt.Errorf("nessus: create request: %w", err)
	}

	req.Header.Set("X-ApiKeys", fmt.Sprintf("accessKey=%s;secretKey=%s", c.config.accessKey, c.config.secretKey))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.config.userAgent != "" {
		req.Header.Set("User-Agent", c.config.userAgent)
	}

	c.logger.DebugContext(ctx, "request", "method", "POST", "path", path)
	start := time.Now()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.ErrorContext(ctx, "request failed", "method", "POST", "path", path, "error", err)
		if isCertificateError(err) {
			return nil, fmt.Errorf("nessus: TLS certificate error: %w", err)
		}
		return nil, fmt.Errorf("nessus: send request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("nessus: read response: %w", err)
	}

	duration := time.Since(start)

	switch resp.StatusCode {
	case http.StatusOK:
		c.logger.DebugContext(ctx, "response", "method", "POST", "path", path, "status", resp.StatusCode, "duration", duration, "bytes", len(respBody))
		return respBody, nil
	case http.StatusUnauthorized:
		c.logger.WarnContext(ctx, "api error", "method", "POST", "path", path, "status", resp.StatusCode)
		return nil, ErrAuth
	case http.StatusForbidden:
		c.logger.WarnContext(ctx, "api error", "method", "POST", "path", path, "status", resp.StatusCode)
		return nil, ErrPermission
	case http.StatusNotFound:
		c.logger.WarnContext(ctx, "api error", "method", "POST", "path", path, "status", resp.StatusCode)
		return nil, ErrNotFound
	default:
		msg := string(respBody)
		var errResp struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(respBody, &errResp) == nil && errResp.Error != "" {
			msg = errResp.Error
		}
		c.logger.WarnContext(ctx, "api error", "method", "POST", "path", path, "status", resp.StatusCode)
		return nil, &APIError{StatusCode: resp.StatusCode, Message: msg}
	}
}

// postJSON sends an authenticated POST request and unmarshals the response into v.
func (c *Client) postJSON(ctx context.Context, path string, body, v any) error {
	respBody, err := c.post(ctx, path, body)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(respBody, v); err != nil {
		return fmt.Errorf("nessus: parse response: %w", err)
	}
	return nil
}
