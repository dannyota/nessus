package nessus

import (
	"context"
	"fmt"
	"time"
)

// ExportOption configures an export request.
type ExportOption interface {
	apply(*exportConfig)
}

type exportConfig struct {
	historyID int
}

// WithHistoryID exports a specific historical scan run instead of the latest.
type withHistoryID struct{ id int }

func (o withHistoryID) apply(c *exportConfig) { c.historyID = o.id }
func WithHistoryID(id int) ExportOption       { return withHistoryID{id} }

type apiExportRequest struct {
	Format string `json:"format"`
}

type apiExportResponse struct {
	Token string `json:"token"`
	File  int    `json:"file"`
}

type apiExportStatus struct {
	Status string `json:"status"`
}

// ExportScan requests a scan export in Nessus XML format.
// Returns a token used to poll status and download the export.
func (c *Client) ExportScan(ctx context.Context, scanID int, opts ...ExportOption) (string, error) {
	cfg := exportConfig{}
	for _, o := range opts {
		o.apply(&cfg)
	}

	path := fmt.Sprintf("/scans/%d/export", scanID)
	if cfg.historyID > 0 {
		path = fmt.Sprintf("/scans/%d/export?history_id=%d", scanID, cfg.historyID)
	}

	var resp apiExportResponse
	if err := c.postJSON(ctx, path, apiExportRequest{Format: "nessus"}, &resp); err != nil {
		return "", err
	}

	if resp.Token != "" {
		return resp.Token, nil
	}
	// Some Nessus versions return file ID instead of token.
	return fmt.Sprintf("%d", resp.File), nil
}

// ExportStatus checks if an export is ready for download.
// Returns "ready" or "loading".
func (c *Client) ExportStatus(ctx context.Context, token string) (string, error) {
	var resp apiExportStatus
	if err := c.getJSON(ctx, fmt.Sprintf("/tokens/%s/status", token), &resp); err != nil {
		return "", err
	}
	return resp.Status, nil
}

// DownloadExport downloads a completed export as raw bytes.
func (c *Client) DownloadExport(ctx context.Context, token string) ([]byte, error) {
	return c.get(ctx, fmt.Sprintf("/tokens/%s/download", token))
}

// ExportAndWait exports a scan, polls until ready, downloads, and parses the result.
// This is the recommended way to bulk-fetch all findings for a scan.
func (c *Client) ExportAndWait(ctx context.Context, scanID int, opts ...ExportOption) (*ExportResult, error) {
	token, err := c.ExportScan(ctx, scanID, opts...)
	if err != nil {
		return nil, fmt.Errorf("nessus: export scan: %w", err)
	}

	// Poll until ready.
	for {
		status, err := c.ExportStatus(ctx, token)
		if err != nil {
			return nil, fmt.Errorf("nessus: export status: %w", err)
		}
		if status == "ready" {
			break
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}

	data, err := c.DownloadExport(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("nessus: download export: %w", err)
	}

	return ParseNessusXML(data)
}
