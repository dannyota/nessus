package nessus

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// ExportOption configures an export request.
type ExportOption interface {
	apply(*exportConfig)
}

// ExportProgress reports the current state of an ExportAndWait operation.
type ExportProgress struct {
	Phase string // "exporting", "polling", "downloading", "parsing"
	Token string // export token/identifier
}

type exportConfig struct {
	historyID   int
	minSeverity int
	onProgress  func(ExportProgress)
}

type withHistoryID struct{ id int }

func (o withHistoryID) apply(c *exportConfig) { c.historyID = o.id }

// WithHistoryID exports a specific historical scan run instead of the latest.
func WithHistoryID(id int) ExportOption { return withHistoryID{id} }

type withMinSeverity struct{ level int }

func (o withMinSeverity) apply(c *exportConfig) { c.minSeverity = o.level }

// WithMinSeverity filters findings during XML parsing.
// 0=all (default), 1=low+, 2=medium+, 3=high+, 4=critical only.
func WithMinSeverity(level int) ExportOption { return withMinSeverity{level} }

type withOnProgress struct{ fn func(ExportProgress) }

func (o withOnProgress) apply(c *exportConfig) { c.onProgress = o.fn }

// WithOnProgress sets a callback that is invoked during ExportAndWait
// to report progress through export phases. Useful for Temporal heartbeats.
func WithOnProgress(fn func(ExportProgress)) ExportOption { return withOnProgress{fn} }

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
// Returns an identifier (token or file ID) used to poll status and download the export.
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
	if resp.File > 0 {
		return fmt.Sprintf("%d", resp.File), nil
	}
	return "", fmt.Errorf("nessus: export response missing token and file ID")
}

// ExportStatus checks if an export is ready for download.
// Returns "ready" or "loading".
func (c *Client) ExportStatus(ctx context.Context, token string) (string, error) {
	if !validToken(token) {
		return "", fmt.Errorf("nessus: invalid export token")
	}
	var resp apiExportStatus
	if err := c.getJSON(ctx, fmt.Sprintf("/tokens/%s/status", token), &resp); err != nil {
		return "", err
	}
	return resp.Status, nil
}

// DownloadExport downloads a completed export as raw bytes.
func (c *Client) DownloadExport(ctx context.Context, token string) ([]byte, error) {
	if !validToken(token) {
		return nil, fmt.Errorf("nessus: invalid export token")
	}
	return c.get(ctx, fmt.Sprintf("/tokens/%s/download", token))
}

// validToken checks that a token contains only safe characters (alphanumeric, dash).
func validToken(token string) bool {
	if token == "" {
		return false
	}
	for _, r := range token {
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && r != '-' {
			return false
		}
	}
	return true
}

// ExportAndWait exports a scan, polls until ready, downloads, and parses the result.
// This is the recommended way to bulk-fetch all findings for a scan.
//
// Use WithMinSeverity to filter findings during parsing:
//
//	result, err := client.ExportAndWait(ctx, scanID, nessus.WithMinSeverity(3)) // high+ only
func (c *Client) ExportAndWait(ctx context.Context, scanID int, opts ...ExportOption) (*ExportResult, error) {
	cfg := exportConfig{}
	for _, o := range opts {
		o.apply(&cfg)
	}

	log := c.logger.With(slog.Int("scan_id", scanID))

	notify := func(phase, token string) {
		if cfg.onProgress != nil {
			cfg.onProgress(ExportProgress{Phase: phase, Token: token})
		}
	}

	var exportOpts []ExportOption
	if cfg.historyID > 0 {
		exportOpts = append(exportOpts, WithHistoryID(cfg.historyID))
	}

	log.DebugContext(ctx, "export", "phase", "exporting")
	notify("exporting", "")
	start := time.Now()

	token, err := c.ExportScan(ctx, scanID, exportOpts...)
	if err != nil {
		return nil, fmt.Errorf("nessus: export scan: %w", err)
	}

	log = log.With(slog.String("token", token))

	log.DebugContext(ctx, "export", "phase", "polling")
	notify("polling", token)
	for {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("nessus: export wait: %w", err)
		}
		status, err := c.ExportStatus(ctx, token)
		if err != nil {
			return nil, fmt.Errorf("nessus: export status: %w", err)
		}
		if status == "ready" {
			break
		}

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("nessus: export wait: %w", ctx.Err())
		case <-time.After(2 * time.Second):
			log.DebugContext(ctx, "export", "phase", "polling")
			notify("polling", token)
		}
	}

	log.DebugContext(ctx, "export", "phase", "downloading")
	notify("downloading", token)
	data, err := c.DownloadExport(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("nessus: download export: %w", err)
	}

	log.DebugContext(ctx, "export", "phase", "parsing")
	notify("parsing", token)
	result, err := ParseNessusXML(data, cfg.minSeverity)
	if err != nil {
		return nil, err
	}

	log.InfoContext(ctx, "export complete", "duration", time.Since(start), "bytes", len(data))
	return result, nil
}
