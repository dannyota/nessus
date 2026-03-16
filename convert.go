package nessus

import (
	"fmt"
	"strconv"
	"strings"
)

// Severity level constants.
const (
	SeverityInfo     = 0
	SeverityLow      = 1
	SeverityMedium   = 2
	SeverityHigh     = 3
	SeverityCritical = 4
)

var severityNames = map[int]string{
	SeverityInfo:     "info",
	SeverityLow:      "low",
	SeverityMedium:   "medium",
	SeverityHigh:     "high",
	SeverityCritical: "critical",
}

// SeverityName returns the human-readable name for a severity level.
func SeverityName(level int) string {
	if name, ok := severityNames[level]; ok {
		return name
	}
	return "unknown"
}

// parseFloat converts a string to float64, returning 0 on failure.
func parseFloat(s string) float64 {
	f, _ := strconv.ParseFloat(s, 64)
	return f
}

// toInt converts a value (string, float64, int) to int.
func toInt(v any) int {
	switch val := v.(type) {
	case float64:
		return int(val)
	case int:
		return val
	case string:
		n, _ := strconv.Atoi(val)
		return n
	default:
		return 0
	}
}

// toInt64 converts a value (string, float64, int, int64) to int64.
func toInt64(v any) int64 {
	switch val := v.(type) {
	case float64:
		return int64(val)
	case int:
		return int64(val)
	case int64:
		return val
	case string:
		n, _ := strconv.ParseInt(val, 10, 64)
		return n
	default:
		return 0
	}
}

// toSeeAlso converts a see_also field (string or []any) to []string.
func toSeeAlso(v any) []string {
	switch val := v.(type) {
	case string:
		return splitSeeAlso(val)
	case []any:
		parts := make([]string, 0, len(val))
		for _, item := range val {
			s := strings.TrimSpace(fmt.Sprint(item))
			if s != "" {
				parts = append(parts, s)
			}
		}
		return parts
	default:
		return nil
	}
}

// splitSeeAlso splits a newline-separated see_also string into []string.
func splitSeeAlso(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, "\n")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}
