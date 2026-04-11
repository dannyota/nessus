package nessus

import "context"

type apiScannerList struct {
	Scanners []apiScanner `json:"scanners"`
}

type apiScanner struct {
	ID            int    `json:"id"`
	UUID          string `json:"uuid"`
	Name          string `json:"name"`
	Status        string `json:"status"`
	Type          string `json:"type"`
	Platform      string `json:"platform"`
	UIVersion     string `json:"ui_version"`
	EngineVersion string `json:"engine_version"`
	Linked        int    `json:"linked"`
}

// ListScanners retrieves all scanners.
func (c *Client) ListScanners(ctx context.Context) ([]Scanner, error) {
	var resp apiScannerList
	if err := c.getJSON(ctx, "/scanners", &resp); err != nil {
		return nil, err
	}

	scanners := make([]Scanner, len(resp.Scanners))
	for i, s := range resp.Scanners {
		scanners[i] = Scanner{
			ID:            s.ID,
			UUID:          s.UUID,
			Name:          s.Name,
			Status:        s.Status,
			Type:          s.Type,
			Platform:      s.Platform,
			UIVersion:     s.UIVersion,
			EngineVersion: s.EngineVersion,
			Linked:        s.Linked,
		}
	}
	return scanners, nil
}
