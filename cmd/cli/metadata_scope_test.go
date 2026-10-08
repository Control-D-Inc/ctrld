package cli

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/Control-D-Inc/ctrld/internal/controld"
)

// requireRuntimeMetadata asserts the runtime half of the startup-versus-runtime
// wire contract in docs/username-detection.md: no username discovery and no
// hostname hints.
func requireRuntimeMetadata(t *testing.T, caller string, req *controld.ResolverConfigRequest) {
	t.Helper()
	if req == nil {
		t.Fatalf("%s did not send a resolver config request", caller)
	}
	if _, ok := req.Metadata["username"]; ok {
		t.Errorf("%s request included username", caller)
	}
	if req.IncludeHostnameHints {
		t.Errorf("%s request asked for hostname hints", caller)
	}
}

func TestDeactivationPinRefreshUsesRuntimeMetadata(t *testing.T) {
	oldFetch, oldUID := fetchResolverConfig, cdUID
	oldPin, oldKnown := cdDeactivationPin.Load(), deactivationPinKnown.Load()
	t.Cleanup(func() {
		fetchResolverConfig, cdUID = oldFetch, oldUID
		cdDeactivationPin.Store(oldPin)
		deactivationPinKnown.Store(oldKnown)
		deactivationLockedUntil.Store(0)
	})
	cdUID = "test-uid"
	deactivationLockedUntil.Store(0)

	var captured *controld.ResolverConfigRequest
	fetchResolverConfig = func(_ context.Context, req *controld.ResolverConfigRequest, _ bool) (*controld.ResolverConfig, error) {
		captured = req
		return &controld.ResolverConfig{}, nil
	}

	p := &prog{cs: &controlServer{mux: http.NewServeMux()}, pinCodeValidCh: make(chan struct{}, 1)}
	p.logger.Store(discardLogger())
	p.registerControlServerHandler()
	body, _ := json.Marshal(&deactivationRequest{Pin: defaultDeactivationPin})
	req := httptest.NewRequest(http.MethodPost, deactivationPath, strings.NewReader(string(body)))
	p.cs.mux.ServeHTTP(httptest.NewRecorder(), req)

	requireRuntimeMetadata(t, "deactivation-PIN refresh", captured)
}

func TestSelfUninstallCheckUsesRuntimeMetadata(t *testing.T) {
	oldFetch, oldUID := fetchResolverConfig, cdUID
	t.Cleanup(func() { fetchResolverConfig, cdUID = oldFetch, oldUID })
	cdUID = "test-uid"

	var captured *controld.ResolverConfigRequest
	fetchResolverConfig = func(_ context.Context, req *controld.ResolverConfigRequest, _ bool) (*controld.ResolverConfig, error) {
		captured = req
		// A generic failure is not a device-deleted answer, so no uninstall runs.
		return nil, errors.New("stop after capturing metadata")
	}

	p := &prog{}
	p.logger.Store(discardLogger())
	p.canSelfUninstall.Store(true)
	p.refusedQueryCount = selfUninstallMaxQueries + 1
	refused := new(dns.Msg)
	refused.SetRcode(newDnsMsgWithHostname("example.com.", dns.TypeA), dns.RcodeRefused)
	p.doSelfUninstall(&proxyResponse{answer: refused})

	requireRuntimeMetadata(t, "self-uninstall check", captured)
}
