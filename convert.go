package nessus

import "strconv"

// parseFloat converts a string to float64, returning 0 on failure.
func parseFloat(s string) float64 {
	f, _ := strconv.ParseFloat(s, 64)
	return f
}
