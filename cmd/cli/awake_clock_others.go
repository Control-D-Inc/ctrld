//go:build !windows

package cli

import "time"

var awakeClockBase = time.Now()

// awakeClock returns how long the host has been awake since ctrld started.
// Go's monotonic clock stops while Linux and macOS sleep.
func awakeClock() time.Duration {
	return time.Since(awakeClockBase)
}
