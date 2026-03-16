package nessus

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

	resp, err := c.httpClient.Do(req)
	if err != nil {
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

	switch resp.StatusCode {
	case http.StatusOK:
		return body, nil
	case http.StatusUnauthorized:
		return nil, ErrAuth
	case http.StatusForbidden:
		return nil, ErrPermission
	case http.StatusNotFound:
		return nil, ErrNotFound
	default:
		msg := string(body)
		// Try to extract error message from JSON response.
		var errResp struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			msg = errResp.Error
		}
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

	resp, err := c.httpClient.Do(req)
	if err != nil {
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

	switch resp.StatusCode {
	case http.StatusOK:
		return respBody, nil
	case http.StatusUnauthorized:
		return nil, ErrAuth
	case http.StatusForbidden:
		return nil, ErrPermission
	case http.StatusNotFound:
		return nil, ErrNotFound
	default:
		msg := string(respBody)
		var errResp struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(respBody, &errResp) == nil && errResp.Error != "" {
			msg = errResp.Error
		}
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
