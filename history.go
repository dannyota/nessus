package nessus

import (
	"context"
	"fmt"
)

type apiScanDetailWithHistory struct {
	Info    apiScanDetailInfo `json:"info"`
	History []apiHistory      `json:"history"`
}

type apiHistory struct {
	HistoryID    int    `json:"history_id"`
	Status       string `json:"status"`
	CreationDate int64  `json:"creation_date"`
}

// GetScanHistory retrieves the list of historical scan runs for a scan.
func (c *Client) GetScanHistory(ctx context.Context, scanID int) ([]ScanHistory, error) {
	var resp apiScanDetailWithHistory
	if err := c.getJSON(ctx, fmt.Sprintf("/scans/%d", scanID), &resp); err != nil {
		return nil, err
	}

	history := make([]ScanHistory, len(resp.History))
	for i, h := range resp.History {
		history[i] = ScanHistory{
			HistoryID:    h.HistoryID,
			Status:       h.Status,
			CreationDate: h.CreationDate,
		}
	}

	return history, nil
}
