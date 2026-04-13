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
	Hosts []ScanHost
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

// ScanHost represents a scanned host within a scan result.
type ScanHost struct {
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

// ScanHostDetail contains host info and the vulnerability list from the detail endpoint.
type ScanHostDetail struct {
	IP              string
	FQDN            string
	Hostname        string
	OS              string
	MAC             string
	NetBIOSName     string
	Vulnerabilities []ScanHostVulnerability
}

// ScanHostVulnerability represents a vulnerability found on a host.
type ScanHostVulnerability struct {
	PluginID     int
	PluginName   string
	PluginFamily string
	Severity     int    // SeverityInfo through SeverityCritical
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

// ScanHistory represents a single historical run of a scan.
type ScanHistory struct {
	HistoryID    int
	Status       string
	CreationDate int64
}

// ExportResult is the parsed output from a Nessus XML export.
// Equivalent to calling GetHostDetails + GetPluginOutput for every host,
// but retrieved in a single bulk download.
type ExportResult struct {
	Name  string
	Hosts []ExportHost
}

// ExportHost contains all findings for one host from an export.
type ExportHost struct {
	IP             string
	FQDN           string
	Hostname       string
	NetBIOSName    string
	OS             string
	MAC            string
	StartTimestamp int64 // Unix timestamp, 0 if unavailable
	EndTimestamp   int64 // Unix timestamp, 0 if unavailable
	Findings       []Finding
}

// Finding is a single vulnerability with full detail from an export.
// Equivalent to ScanHostVulnerability + PluginOutput combined.
type Finding struct {
	PluginID     int
	PluginName   string
	PluginFamily string
	Severity     int    // SeverityInfo through SeverityCritical
	Port         string // "443", "0" for local checks
	Protocol     string // "tcp", "udp"
	Service      string // "www", "ssh", etc.

	Synopsis    string
	Description string
	Solution    string
	SeeAlso     []string
	RiskFactor  string
	Output      string // evidence text ("Remote package installed: X, Should be: Y")

	CVSSBaseScore  float64
	CVSSVector     string
	CVSS3BaseScore float64
	CVSS3Vector    string

	CVE  []string
	BID  []string
	XREF []string
}

// Agent represents a Nessus agent connected to the manager.
type Agent struct {
	ID           int
	UUID         string
	Name         string
	Status       string   // "online", "offline", "unlinked"
	Platform     string   // "LINUX", "WINDOWS", "DARWIN"
	Distro       string   // e.g. "es9-x86-64"
	IP           string
	MACAddresses []string // parsed from JSON-encoded string in API response
	CoreVersion  string
	CoreBuild    string
	LinkedOn     int64 // Unix timestamp
	LastConnect  int64 // Unix timestamp
	LastScanned  int64 // Unix timestamp
	Groups       []string
	PluginFeedID string
}

// AgentGroup represents a Nessus agent group.
type AgentGroup struct {
	ID                   int
	Name                 string
	AgentsCount          int
	OwnerID              int
	OwnerName            string
	CreationDate         int64
	LastModificationDate int64
}

// Scanner represents a Nessus scanner instance.
type Scanner struct {
	ID            int
	UUID          string
	Name          string
	Status        string // "on", "off"
	Type          string // "local", "remote"
	Platform      string
	UIVersion     string
	EngineVersion string
	Linked        int
}

// ServerInfo contains metadata about the Nessus Manager instance.
type ServerInfo struct {
	NessusType       string // "Nessus Manager"
	ServerUUID       string
	Version          string // nessus_ui_version, e.g. "10.8.3"
	Platform         string // "LINUX", "WINDOWS"
	PluginSet        string // e.g. "202604081803"
	LicenseType      string // "manager", "professional", "eval"
	LicenseExpiry    int64  // Unix timestamp
	LicensedHosts    int    // license.ips
	LicensedAgents   int    // license.agents (capacity)
	AgentsUsed       int    // license.agents_used
	LicensedScanners int    // license.scanners (capacity)
	ScannersUsed     int    // license.scanners_used
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
	SeeAlso      []string
	RiskFactor   string
	CVE          []string
	BID          []string
	XREF         []string
	CVSSVector   string
	CVSSBaseScore float64
	CVSS3Vector  string
	CVSS3BaseScore float64
}
