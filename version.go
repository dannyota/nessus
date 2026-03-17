package nessus

import (
	"regexp"
	"strings"
)

// VersionInfo contains version details extracted from plugin output.
type VersionInfo struct {
	Package   string // file path or package name; empty if not present
	Installed string // installed or remote version
	Fixed     string // required version; may contain " / " for alternatives
}

var (
	pathPattern        = regexp.MustCompile(`(?i)^\s*Path\s*:\s*(.+)`)
	patchedPathPattern = regexp.MustCompile(`(?i)^-\s*(.+)\s+has not been patched`)
	installedPattern   = regexp.MustCompile(`(?i)^\s*(?:Installed version|Reported version|Remote version)\s*:\s*(.+)`)
	packagePattern     = regexp.MustCompile(`(?i)Remote package installed\s*:\s*(.+)`)
	fixedPattern       = regexp.MustCompile(`(?i)^\s*(?:Fixed version|Should be)\s*:\s*(.+)`)
)

// ParseVersions extracts installed/fixed version pairs from plugin output text.
// It handles Windows-style (Path + Installed version + Fixed version),
// library-style (Path + Reported version + Fixed version),
// SQL Server-style (Remote version + Should be), and Linux package-style
// (Remote package installed + Should be) output formats.
// Returns nil if no version information is found.
func ParseVersions(output string) []VersionInfo {
	var results []VersionInfo
	var currentPath string
	var currentInstalled string

	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)

		// Path context: "Path : C:\..."
		if m := pathPattern.FindStringSubmatch(trimmed); len(m) > 1 {
			currentPath = strings.TrimSpace(m[1])
			continue
		}

		// SQL Server style: "- C:\...\sqlservr.exe has not been patched."
		if m := patchedPathPattern.FindStringSubmatch(trimmed); len(m) > 1 {
			currentPath = strings.TrimSpace(m[1])
			continue
		}

		// Linux: "Remote package installed : kernel-5.14.0-570.el9"
		if m := packagePattern.FindStringSubmatch(trimmed); len(m) > 1 {
			currentInstalled = strings.TrimSpace(m[1])
			continue
		}

		// Windows/SQL: "Installed version : 10.8.2" or "Remote version : 2022.160.1000.6"
		if m := installedPattern.FindStringSubmatch(trimmed); len(m) > 1 {
			currentInstalled = strings.TrimSpace(m[1])
			continue
		}

		// Fixed: "Fixed version : 10.8.5 / 10.9.0" or "Should be : ..."
		if m := fixedPattern.FindStringSubmatch(trimmed); len(m) > 1 {
			if currentInstalled != "" {
				results = append(results, VersionInfo{
					Package:   currentPath,
					Installed: currentInstalled,
					Fixed:     strings.TrimSpace(m[1]),
				})
				currentInstalled = ""
			}
			currentPath = ""
		}
	}

	return results
}
