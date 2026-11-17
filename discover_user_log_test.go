//go:build darwin || linux || windows

package ctrld

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/rs/zerolog"
)

// lineRecorder keeps each write of a logger as its own entry.
type lineRecorder struct {
	mu     sync.Mutex
	writes [][]byte
}

func (r *lineRecorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.writes = append(r.writes, bytes.Clone(p))
	return len(p), nil
}

func (r *lineRecorder) lines() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.writes
}

// TestDiscoverMainUserSendsEachEventOnce checks that user discovery gives each
// debug line its own zerolog event. A send returns the event to a pool that
// all goroutines share. A second send of the same event returns it again, so
// two goroutines can later write into one event at the same time. The second
// send also writes the first line again, so the test sees the fault without
// the race detector. The test runs the real lookups of the host, so it covers
// only the branch that the host takes. For example, on a host with a logged-in
// user, DiscoverMainUser returns before its account-list lines.
func TestDiscoverMainUserSendsEachEventOnce(t *testing.T) {
	var recorder lineRecorder
	logger := zerolog.New(&recorder).Level(zerolog.DebugLevel)
	previousLogger := ProxyLogger.Load()
	ProxyLogger.Store(&logger)
	t.Cleanup(func() { ProxyLogger.Store(previousLogger) })
	previousLevel := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	t.Cleanup(func() { zerolog.SetGlobalLevel(previousLevel) })

	DiscoverMainUser(context.Background())

	lines := recorder.lines()
	// Every path of the discovery logs two lines or more. With fewer, the
	// test cannot see an event that went out twice.
	if len(lines) < 2 {
		t.Fatalf("got %d debug lines, want 2 or more: %q", len(lines), lines)
	}
	for _, line := range lines {
		if !isOneLogLine(line) {
			t.Errorf("one write holds more than one log line, so an event went out twice: %q", line)
		}
	}
}

// isOneLogLine reports whether p is one JSON log line with a level.
func isOneLogLine(p []byte) bool {
	if bytes.Count(p, []byte("\n")) != 1 {
		return false
	}
	var event map[string]any
	if err := json.Unmarshal(p, &event); err != nil {
		return false
	}
	_, hasLevel := event[zerolog.LevelFieldName]
	return hasLevel
}
