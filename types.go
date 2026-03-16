package nessus

// Scan represents a scan summary from the scan list.
type Scan struct {
	ID             int
	Name           string
	Status         string // "completed", "running", "paused", "canceled", "empty"
	FolderID       int
	Enabled        bool
	Control        bool
	StartTime      int64 // Unix timestamp, 0 if never run
	EndTime        int64 // Unix timestamp, 0 if never run
	LastModified   int64 // Unix timestamp
	CreationDate   int64 // Unix timestamp
	UserPermissions int
}

// ScanDetail represents full scan details including the host list.
type ScanDetail struct {
	Info  ScanInfo
	Hosts []Host
}

// ScanInfo contains scan metadata from the detail response.
type ScanInfo struct {
	Name       string
	Status     string
	Policy     string
	Scanner    string
	Targets    string
	StartTime  int64
	EndTime    int64
	HostCount  int
}

// Host represents a scanned host within a scan result.
type Host struct {
	HostID       int
	Hostname     string
	IP           string
	OS           string
	Critical     int
	High         int
	Medium       int
	Low          int
	Info         int
	Progress     string
}

// HostVulnerability represents a vulnerability found on a host.
type HostVulnerability struct {
	PluginID     int
	PluginName   string
	PluginFamily string
	Severity     int    // 0=info, 1=low, 2=medium, 3=high, 4=critical
	Count        int
}

// PluginOutput represents detailed finding output for a specific plugin on a host.
type PluginOutput struct {
	Output      string
	Ports       map[string][]PortInfo
	Info        PluginInfo
}

// PortInfo represents output for a specific port.
type PortInfo struct {
	Port   string
	Output string
}

// PluginInfo contains plugin metadata from the finding detail.
type PluginInfo struct {
	PluginID     int
	Name         string
	Family       string
	Severity     int
	Synopsis     string
	Description  string
	Solution     string
	SeeAlso      string
	RiskFactor   string
	CVE          []string
	BID          []string
	XREF         []string
	CVSSVector   string
	CVSSBaseScore float64
	CVSS3Vector  string
	CVSS3BaseScore float64
}
