package nessus

import (
	"fmt"
	"strconv"
	"strings"
)

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

// toSeeAlso converts a see_also field (string or []any) to a single newline-separated string.
func toSeeAlso(v any) string {
	switch val := v.(type) {
	case string:
		return val
	case []any:
		parts := make([]string, 0, len(val))
		for _, item := range val {
			parts = append(parts, fmt.Sprint(item))
		}
		return strings.Join(parts, "\n")
	default:
		return ""
	}
}
