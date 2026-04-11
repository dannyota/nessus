package nessus

import (
	"context"
	"fmt"
)

type apiScanList struct {
	Scans []apiScan `json:"scans"`
}

type apiScan struct {
	ID              int    `json:"id"`
	Name            string `json:"name"`
	Status          string `json:"status"`
	FolderID        int    `json:"folder_id"`
	Enabled         bool   `json:"enabled"`
	Control         bool   `json:"control"`
	StartTime       any    `json:"starttime"`
	EndTime         any    `json:"endtime"`
	LastModified    int64  `json:"last_modification_date"`
	CreationDate    int64  `json:"creation_date"`
	UserPermissions int    `json:"user_permissions"`
}

type apiScanDetail struct {
	Info  apiScanDetailInfo `json:"info"`
	Hosts []apiHost         `json:"hosts"`
}

type apiScanDetailInfo struct {
	Name      string `json:"name"`
	Status    string `json:"status"`
	Policy    string `json:"policy"`
	Scanner   string `json:"scanner_name"`
	Targets   string `json:"targets"`
	Start     int64  `json:"scanner_start"`
	End       int64  `json:"scanner_end"`
	HostCount int    `json:"hostcount"`
}

type apiHost struct {
	HostID   int    `json:"host_id"`
	Hostname string `json:"hostname"`
	IP       string `json:"host_ip"`
	OS       string `json:"operating-system"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Medium   int    `json:"medium"`
	Low      int    `json:"low"`
	Info     int    `json:"info"`
	Progress string `json:"progress"`
}

// ListScans retrieves all scans from the Nessus scanner.
func (c *Client) ListScans(ctx context.Context) ([]Scan, error) {
	var resp apiScanList
	if err := c.getJSON(ctx, "/scans", &resp); err != nil {
		return nil, err
	}

	scans := make([]Scan, len(resp.Scans))
	for i, s := range resp.Scans {
		scans[i] = Scan{
			ID:              s.ID,
			Name:            s.Name,
			Status:          s.Status,
			FolderID:        s.FolderID,
			Enabled:         s.Enabled,
			Control:         s.Control,
			StartTime:       toInt64(s.StartTime),
			EndTime:         toInt64(s.EndTime),
			LastModified:    s.LastModified,
			CreationDate:    s.CreationDate,
			UserPermissions: s.UserPermissions,
		}
	}

	return scans, nil
}

// GetScan retrieves scan details including the list of scanned hosts.
func (c *Client) GetScan(ctx context.Context, scanID int) (*ScanDetail, error) {
	var resp apiScanDetail
	if err := c.getJSON(ctx, fmt.Sprintf("/scans/%d", scanID), &resp); err != nil {
		return nil, err
	}

	hosts := make([]ScanHost, len(resp.Hosts))
	for i, h := range resp.Hosts {
		hosts[i] = ScanHost{
			HostID:   h.HostID,
			Hostname: h.Hostname,
			IP:       h.IP,
			OS:       h.OS,
			Critical: h.Critical,
			High:     h.High,
			Medium:   h.Medium,
			Low:      h.Low,
			Info:     h.Info,
			Progress: h.Progress,
		}
	}

	return &ScanDetail{
		Info: ScanInfo{
			Name:      resp.Info.Name,
			Status:    resp.Info.Status,
			Policy:    resp.Info.Policy,
			Scanner:   resp.Info.Scanner,
			Targets:   resp.Info.Targets,
			StartTime: resp.Info.Start,
			EndTime:   resp.Info.End,
			HostCount: resp.Info.HostCount,
		},
		Hosts: hosts,
	}, nil
}
