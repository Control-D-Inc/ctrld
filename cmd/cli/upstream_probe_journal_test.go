package cli

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Control-D-Inc/ctrld"
)

// probeSecret is the operator text that a custom upstream key, name, and
// endpoint hold in these tests.
const probeSecret = "org-v1-SECRET0123"

// customProbeUpstream builds an upstream whose key, name, and endpoint all
// hold operator text.
func customProbeUpstream() (string, *ctrld.UpstreamConfig) {
	return upstreamPrefix + probeSecret, &ctrld.UpstreamConfig{
		Name:     probeSecret,
		Endpoint: "https://dns.example.com/" + probeSecret,
	}
}

// retainedProbeLines returns the captured lines that the journal keeps.
func retainedProbeLines(t *testing.T, logs *syncBuffer) []map[string]any {
	t.Helper()
	var retained []map[string]any
	for _, event := range jsonLogEvents(t, logs, "") {
		switch event["level"] {
		case "error", "warn":
			retained = append(retained, event)
		}
	}
	return retained
}

// wantNoProbeSecret fails when a retained line carries the operator text.
func wantNoProbeSecret(t *testing.T, logs *syncBuffer) {
	t.Helper()
	for _, event := range retainedProbeLines(t, logs) {
		for field, value := range event {
			text, ok := value.(string)
			if ok && strings.Contains(text, probeSecret) {
				t.Fatalf("retained field %q holds the operator text: %s", field, text)
			}
		}
	}
}

// Test_upstreamFailureLogKeepsACustomKeyOutOfTheJournal drives one recovery
// check failure against an operator-chosen upstream key. The journal keeps
// error lines, so the key, the name, and the endpoint must stay off the line.
func Test_upstreamFailureLogKeepsACustomKeyOutOfTheJournal(t *testing.T) {
	logs := captureDebugMainLog(t)
	upstream, uc := customProbeUpstream()

	(&upstreamFailureLog{}).report(probeTestProg(), upstream, uc, errors.New("probe failed"), time.Second)

	retained := retainedProbeLines(t, logs)
	if len(retained) != 1 {
		t.Fatalf("retained lines: got %d, want 1", len(retained))
	}
	wantField(t, retained[0], "upstream", upstreamPrefix+"custom")
	wantNoProbeSecret(t, logs)
	if !strings.Contains(logs.String(), probeSecret) {
		t.Fatal("the operator text must stay at debug level for diagnosis")
	}
}

// Test_checkUpstreamOnceKeepsACustomKeyOutOfTheJournal drives the resolver
// creation failure of a recovery check. It logs at error level, so the journal
// keeps it.
func Test_checkUpstreamOnceKeepsACustomKeyOutOfTheJournal(t *testing.T) {
	logs := captureDebugMainLog(t)
	upstream, uc := customProbeUpstream()
	// An empty type has no resolver, so the check fails before it sends.
	uc.Type = ""
	p := &prog{}
	p.logger.Store(mainLog.Load())

	if err := p.checkUpstreamOnce(upstream, uc, &upstreamFailureLog{}); err == nil {
		t.Fatal("expected the resolver creation to fail")
	}

	retained := retainedProbeLines(t, logs)
	if len(retained) != 1 {
		t.Fatalf("retained lines: got %d, want 1", len(retained))
	}
	wantField(t, retained[0], "upstream", upstreamPrefix+"custom")
	wantNoProbeSecret(t, logs)
}

// Test_checkDnsLoopKeepsACustomKeyOutOfTheJournal drives the loop checker
// against an operator-chosen upstream key. The loop checker writes at warn
// level, so the journal keeps its line too.
func Test_checkDnsLoopKeepsACustomKeyOutOfTheJournal(t *testing.T) {
	logs := captureDebugMainLog(t)
	uc := &ctrld.UpstreamConfig{
		Name:     probeSecret,
		Type:     ctrld.ResolverTypeLegacy,
		Endpoint: deadUpstreamEndpoint,
		Timeout:  200,
	}
	uc.Init(context.Background())
	cfg := &ctrld.Config{Upstream: map[string]*ctrld.UpstreamConfig{probeSecret: uc}}
	p := &prog{cfg: cfg, um: newUpstreamMonitor(cfg, mainLog.Load()), loop: make(map[string]bool)}
	p.logger.Store(mainLog.Load())

	p.checkDnsLoop()

	retained := retainedProbeLines(t, logs)
	if len(retained) == 0 {
		t.Fatal("the loop check failure must stay visible above debug")
	}
	for _, event := range retained {
		wantField(t, event, "upstream", upstreamPrefix+"custom")
	}
	wantNoProbeSecret(t, logs)
}

// Test_logUpstreamPingFailuresKeepsACustomKeyOutOfTheJournal drives the report
// that follows a failed self-check. It writes at error level, so the journal
// keeps it and the operator text must stay off the line.
func Test_logUpstreamPingFailuresKeepsACustomKeyOutOfTheJournal(t *testing.T) {
	logs := captureDebugMainLog(t)
	_, uc := customProbeUpstream()
	origPing := upstreamPingFn
	t.Cleanup(func() { upstreamPingFn = origPing })
	upstreamPingFn = func(*ctrld.UpstreamConfig, context.Context) error { return errors.New("ping failed") }

	logUpstreamPingFailures(context.Background(), map[string]*ctrld.UpstreamConfig{probeSecret: uc})

	retained := retainedProbeLines(t, logs)
	if len(retained) != 1 {
		t.Fatalf("retained lines: got %d, want 1", len(retained))
	}
	wantField(t, retained[0], "upstream", upstreamPrefix+"custom")
	wantNoProbeSecret(t, logs)
	if !strings.Contains(logs.String(), probeSecret) {
		t.Fatal("the operator text must stay at debug level for diagnosis")
	}
}

// probeTestProg returns a prog that logs through the captured main logger.
func probeTestProg() *prog {
	p := &prog{}
	p.logger.Store(mainLog.Load())
	return p
}
