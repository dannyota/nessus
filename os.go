package nessus

import (
	"regexp"
	"strconv"
	"strings"
)

// Nessus OS Identification plugin ID.
const PluginIDOSIdentification = 11936

// OSInfo contains parsed OS detection information.
type OSInfo struct {
	Family     string // "windows", "linux", "macos", "freebsd", etc.; empty if unknown
	Name       string // full OS string, e.g. "Microsoft Windows Server 2019 Standard"
	Confidence int    // 0-100 from plugin output; 0 if unavailable
}

var (
	osNamePattern       = regexp.MustCompile(`(?i)Remote operating system\s*:\s*(.+)`)
	osConfidencePattern = regexp.MustCompile(`(?i)Confidence level\s*:\s*(\d+)`)
)

// OS family matchers, ordered so more specific prefixes come first.
var osFamilyMatchers = []struct {
	family  string
	matches []string
}{
	{"windows", []string{"windows"}},
	{"linux", []string{"linux", "ubuntu", "debian", "centos", "red hat", "redhat", "rhel", "fedora", "suse", "sles", "amazon linux", "oracle linux", "alma", "almalinux", "rocky", "rocky linux", "arch linux", "gentoo", "slackware"}},
	{"macos", []string{"mac os", "macos", "os x", "darwin"}},
	{"freebsd", []string{"freebsd"}},
	{"netbsd", []string{"netbsd"}},
	{"openbsd", []string{"openbsd"}},
	{"solaris", []string{"solaris", "sunos"}},
	{"aix", []string{"aix"}},
	{"hpux", []string{"hp-ux", "hpux"}},
	{"fortinet", []string{"fortigate", "fortios", "fortinet"}},
	{"cisco", []string{"cisco"}},
	{"vmware", []string{"vmware", "esxi"}},
	{"juniper", []string{"junos", "juniper"}},
}

// ExtractOS extracts OS detection info from an ExportHost's findings.
// It looks for plugin 11936 (OS Identification) and parses the OS name
// and confidence from the plugin output. If the plugin is not present,
// it falls back to the host's OS property.
// Returns zero-value OSInfo if no OS information is available.
func ExtractOS(host ExportHost) OSInfo {
	for _, f := range host.Findings {
		if f.PluginID == PluginIDOSIdentification {
			if info := ParseOS(f.Output); info.Name != "" {
				return info
			}
		}
	}

	// Fall back to host OS property.
	if host.OS != "" {
		return OSInfo{
			Family: OSFamily(host.OS),
			Name:   firstLine(host.OS),
		}
	}
	return OSInfo{}
}

// ParseOS parses OS detection info from plugin 11936 output text.
// Use this with GetPluginOutput results for plugin 11936.
func ParseOS(output string) OSInfo {
	var info OSInfo

	if m := osNamePattern.FindStringSubmatch(output); len(m) > 1 {
		info.Name = strings.TrimSpace(m[1])
		info.Family = OSFamily(info.Name)
	}

	if m := osConfidencePattern.FindStringSubmatch(output); len(m) > 1 {
		info.Confidence, _ = strconv.Atoi(m[1])
	}

	return info
}

// OSFamily classifies an OS string into a family name.
// Works with any OS string (ScanHost.OS, ExportHost.OS, or free text).
// Returns empty string if the OS cannot be classified.
func OSFamily(os string) string {
	lower := strings.ToLower(os)
	for _, m := range osFamilyMatchers {
		for _, keyword := range m.matches {
			if strings.Contains(lower, keyword) {
				return m.family
			}
		}
	}
	return ""
}

// firstLine returns the first non-empty line from a potentially multi-line string.
func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return ""
}
