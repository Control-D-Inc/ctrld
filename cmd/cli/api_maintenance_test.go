package cli

import (
	"context"
	"net/http"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/controld"
)

// maintenanceAPIErr builds the API's hard maintenance answer: the dedicated
// code with the maintenance message.
func maintenanceAPIErr(status int) error {
	e := &controld.ErrorResponse{StatusCode: status}
	e.ErrorField.Code = controld.MaintenanceCode
	e.ErrorField.Message = controld.MaintenanceMessage + " Please try again later."
	return e
}

// legacyMaintenanceAPIErr is the answer of a deployment that predates the
// dedicated code: the maintenance message alone.
func legacyMaintenanceAPIErr(status int) error {
	e := &controld.ErrorResponse{StatusCode: status}
	e.ErrorField.Message = controld.MaintenanceMessage + " Please try again later."
	return e
}

// deviceInvalidErr models the API refusing a device that no longer exists.
func deviceInvalidErr() error {
	e := &controld.ErrorResponse{StatusCode: http.StatusNotFound}
	e.ErrorField.Code = controld.InvalidConfigCode
	e.ErrorField.Message = "device does not exist"
	return e
}

// provisionedConfig models the configuration an earlier successful run wrote.
func provisionedConfig() *ctrld.Config {
	return &ctrld.Config{
		Listener: map[string]*ctrld.ListenerConfig{
			"0": {IP: "127.0.0.1", Port: 53},
		},
		Network: map[string]*ctrld.NetworkConfig{
			"0": {Name: "Network 0", Cidrs: []string{"0.0.0.0/0"}},
		},
		Upstream: map[string]*ctrld.UpstreamConfig{
			"0": {Name: "Control D", Type: ctrld.ResolverTypeDOH, Endpoint: "https://dns.controld.com/abcd1234", Timeout: 5000},
		},
	}
}

// withConfigOnDisk sets up what startup would have left behind: whether a
// configuration file was read, and whether a previous run recorded that the
// API produced it. Both are required for a fallback, and the marker lives in a
// temp dir so a real one on this host cannot influence the result.
func withConfigOnDisk(t *testing.T, read, managed bool) {
	t.Helper()
	oldRead, oldMarker, oldUID := configReadFromDisk, managedConfigMarkerPath, cdUID
	t.Cleanup(func() {
		configReadFromDisk, managedConfigMarkerPath, cdUID = oldRead, oldMarker, oldUID
	})
	dir := t.TempDir()
	managedConfigMarkerPath = func() string { return filepath.Join(dir, managedConfigMarkerFile) }
	oldFile := defaultConfigFile
	t.Cleanup(func() { defaultConfigFile = oldFile })
	defaultConfigFile = filepath.Join(dir, "ctrld.toml")
	cdUID = "test-uid"
	configReadFromDisk = read
	if managed {
		// The marker is bound to the file it vouches for, so one has to exist.
		if err := writeConfigFile(provisionedConfig()); err != nil {
			t.Fatalf("write config: %v", err)
		}
		if err := recordManagedConfig(cdUID); err != nil {
			t.Fatalf("recordManagedConfig: %v", err)
		}
	}
}

// Test_apiFailureCodeClassifiesMaintenance covers the classification the whole
// fallback rests on. Maintenance must not be reported as unreachability, which
// is what the incident showed (API_UNREACHABLE after a successful connection),
// and must never reach the device-invalid path that self-uninstalls.
func Test_apiFailureCodeClassifiesMaintenance(t *testing.T) {
	for _, answer := range []func(int) error{maintenanceAPIErr, legacyMaintenanceAPIErr} {
		for _, status := range []int{http.StatusServiceUnavailable, http.StatusBadGateway, http.StatusBadRequest, http.StatusNotFound} {
			code, ok := apiFailureCode(answer(status))
			if !ok || code != provisionCodeAPIMaintenance {
				t.Fatalf("status %d: code = %q ok = %v, want API_MAINTENANCE", status, code, ok)
			}
		}
	}
}

// Test_maintenanceIsNotAPermanentRejection covers the status trap: a
// maintenance answer carrying a client-error status would otherwise be read as
// "this request will be refused again" and stop the service for good.
func Test_maintenanceIsNotAPermanentRejection(t *testing.T) {
	for _, answer := range []func(int) error{maintenanceAPIErr, legacyMaintenanceAPIErr} {
		for _, status := range []int{http.StatusBadRequest, http.StatusNotFound, http.StatusForbidden} {
			if _, permanent := permanentAPIRejection(answer(status)); permanent {
				t.Fatalf("status %d classified as a permanent rejection", status)
			}
		}
	}
}

func Test_useLastKnownConfigDuringMaintenance(t *testing.T) {
	t.Run("a previously working config carries the start", func(t *testing.T) {
		withConfigOnDisk(t, true, true)
		if !useLastKnownConfigDuringMaintenance(maintenanceAPIErr(http.StatusServiceUnavailable), provisionedConfig()) {
			t.Fatal("maintenance did not fall back to the config on disk")
		}
	})

	t.Run("a generated default is not a fallback", func(t *testing.T) {
		// A fresh install: no file existed, so startup wrote the freedns
		// default. Serving it would answer outside the operator's profile.
		withConfigOnDisk(t, false, false)
		if useLastKnownConfigDuringMaintenance(maintenanceAPIErr(http.StatusServiceUnavailable), provisionedConfig()) {
			t.Fatal("a generated default was accepted as a last known configuration")
		}
	})

	t.Run("an unusable config on disk is not a fallback", func(t *testing.T) {
		withConfigOnDisk(t, true, true)
		cfg := provisionedConfig()
		cfg.Upstream = nil
		if useLastKnownConfigDuringMaintenance(maintenanceAPIErr(http.StatusServiceUnavailable), cfg) {
			t.Fatal("an invalid config was accepted as a last known configuration")
		}
	})

	t.Run("a file with no record of an API answer is not a fallback", func(t *testing.T) {
		withConfigOnDisk(t, true, false)
		if useLastKnownConfigDuringMaintenance(maintenanceAPIErr(http.StatusServiceUnavailable), provisionedConfig()) {
			t.Fatal("a configuration no API answer produced was accepted")
		}
	})

	t.Run("other failures never take this path", func(t *testing.T) {
		withConfigOnDisk(t, true, true)
		for _, err := range []error{retryableNetworkErr(), deviceInvalidErr()} {
			if useLastKnownConfigDuringMaintenance(err, provisionedConfig()) {
				t.Fatalf("%v was treated as maintenance", err)
			}
		}
	})
}

// Test_maintenanceWithoutFallbackFails covers the other half of the request:
// when there is nothing to fall back on, ctrld still stops, but says what
// cannot be done rather than reporting a fetch or connectivity failure.
func Test_maintenanceWithoutFallbackFails(t *testing.T) {
	exitCode, notified := stubProvisionGlobals(t)
	uninstalled := false
	uninstallInvalidCdUIDFn = func(*prog, *ctrld.Logger, bool) bool { uninstalled = true; return true }

	handleAPIPreflightFailure(&prog{}, maintenanceAPIErr(http.StatusServiceUnavailable), func() { *notified = true })

	if want := provisionExitCodeForCode[provisionCodeAPIMaintenance]; *exitCode != want {
		t.Errorf("exit = %d, want %d", *exitCode, want)
	}
	if uninstalled {
		t.Error("maintenance reached the self-uninstall path")
	}
	if !*notified {
		t.Error("notify not called")
	}
	r, err := readProvisionResult()
	if err != nil {
		t.Fatal(err)
	}
	if r.Code != string(provisionCodeAPIMaintenance) {
		t.Errorf("code = %q, want API_MAINTENANCE", r.Code)
	}
	if r.Message != maintenanceNoConfigDetail {
		t.Errorf("message = %q, want the maintenance guidance", r.Message)
	}
}

// maintenanceWithDeviceCode is the answer that makes the guard load-bearing:
// maintenance carried alongside the device-invalid code. Without the guard in
// selfUninstallCheck, this uninstalls a working install over a temporary API
// outage.
func maintenanceWithDeviceCode() error {
	e := &controld.ErrorResponse{StatusCode: http.StatusServiceUnavailable}
	e.ErrorField.Code = controld.InvalidConfigCode
	e.ErrorField.Message = controld.MaintenanceMessage + " Please try again later."
	return e
}

func stubSelfUninstall(t *testing.T) *bool {
	t.Helper()
	old := selfUninstallFn
	t.Cleanup(func() { selfUninstallFn = old })
	called := false
	selfUninstallFn = func(*prog, *ctrld.Logger) { called = true }
	return &called
}

func newSelfUninstallTestProg() *prog {
	return &prog{dnsWatcherStopCh: make(chan struct{})}
}

func Test_selfUninstallCheckSkipsMaintenance(t *testing.T) {
	t.Run("maintenance never uninstalls", func(t *testing.T) {
		called := stubSelfUninstall(t)
		p := newSelfUninstallTestProg()
		selfUninstallCheck(maintenanceWithDeviceCode(), p, discardLogger())
		if *called {
			t.Fatal("maintenance triggered a self-uninstall")
		}
		select {
		case <-p.dnsWatcherStopCh:
			t.Fatal("maintenance stopped the DNS watchers")
		default:
		}
	})

	t.Run("a real device rejection still uninstalls", func(t *testing.T) {
		called := stubSelfUninstall(t)
		selfUninstallCheck(deviceInvalidErr(), newSelfUninstallTestProg(), discardLogger())
		if !*called {
			t.Fatal("a deleted device no longer self-uninstalls")
		}
	})

	t.Run("an unrelated failure does nothing", func(t *testing.T) {
		called := stubSelfUninstall(t)
		selfUninstallCheck(retryableNetworkErr(), newSelfUninstallTestProg(), discardLogger())
		if *called {
			t.Fatal("a network failure triggered a self-uninstall")
		}
	})
}

// Test_logResolverConfigFetchFailure covers what the reload paths say. The
// incident was first triaged as a connectivity fault because the only line was
// "could not fetch resolver config" after a successful connection.
func Test_logResolverConfigFetchFailure(t *testing.T) {
	t.Run("maintenance is named and retained", func(t *testing.T) {
		logs := captureDebugMainLog(t)
		logger := mainLog.Load().With().Str("mode", "api-reload")
		logResolverConfigFetchFailure(logger, maintenanceAPIErr(http.StatusServiceUnavailable))

		events := jsonLogEvents(t, logs, "Control D API is in maintenance; keeping the current configuration until it returns")
		if len(events) != 1 {
			t.Fatalf("maintenance events: got %d, want 1", len(events))
		}
		if events[0]["reason"] != "api_maintenance" {
			t.Errorf("reason = %v, want api_maintenance", events[0]["reason"])
		}
		if events[0]["journal"] != true {
			t.Error("the maintenance line is not retained in the journal")
		}
	})

	t.Run("other failures keep the existing line", func(t *testing.T) {
		logs := captureDebugMainLog(t)
		logger := mainLog.Load().With().Str("mode", "api-reload")
		logResolverConfigFetchFailure(logger, retryableNetworkErr())

		if got := len(jsonLogEvents(t, logs, "Could not fetch resolver config")); got != 1 {
			t.Fatalf("generic fetch-failure events: got %d, want 1", got)
		}
	})
}

// Test_maintenanceReloadDelay covers the two properties the retry depends on:
// it is far below refetch_time so a degraded run recovers promptly, and it is
// spread so hosts that fell back together do not return as one burst.
func Test_maintenanceReloadDelay(t *testing.T) {
	const refetchDefault = time.Hour
	seen := make(map[time.Duration]bool)
	for range 200 {
		d := maintenanceReloadDelay()
		if d < maintenanceReloadInterval || d >= maintenanceReloadInterval+maintenanceReloadJitter {
			t.Fatalf("delay %s outside [%s, %s)", d, maintenanceReloadInterval, maintenanceReloadInterval+maintenanceReloadJitter)
		}
		if d >= refetchDefault {
			t.Fatalf("delay %s is no faster than the normal refetch interval", d)
		}
		seen[d] = true
	}
	if len(seen) < 2 {
		t.Fatal("every delay was identical; the fleet would retry in lockstep")
	}
}

// Test_maintenanceRetryRecoversBeforeRefetchInterval drives the real reload
// loop: a run that started on the configuration on disk must ask the API again
// without waiting out refetch_time, and must stop asking once it gets an
// answer.
func Test_maintenanceRetryRecoversBeforeRefetchInterval(t *testing.T) {
	oldFetch, oldDelay, oldUID := fetchResolverConfigFn, maintenanceReloadDelay, cdUID
	t.Cleanup(func() {
		fetchResolverConfigFn, maintenanceReloadDelay, cdUID = oldFetch, oldDelay, oldUID
	})
	cdUID = "test-uid"
	maintenanceReloadDelay = func() time.Duration { return time.Millisecond }

	var calls atomic.Int64
	recovered := make(chan struct{})
	var once sync.Once
	fetchResolverConfigFn = func(context.Context, *controld.ResolverConfigRequest, bool) (*controld.ResolverConfig, error) {
		// Stay in maintenance for the first few retries, then answer.
		if calls.Add(1) < 3 {
			return nil, maintenanceAPIErr(http.StatusServiceUnavailable)
		}
		once.Do(func() { close(recovered) })
		return &controld.ResolverConfig{}, nil
	}

	p := &prog{
		cfg: &ctrld.Config{
			// An hour: the test must pass because of the maintenance retry,
			// never because the normal ticker happened to fire.
			Service: ctrld.ServiceConfig{RefetchTime: ptrTo(3600)},
		},
		stopCh:           make(chan struct{}),
		runAbortCh:       make(chan struct{}),
		apiForceReloadCh: make(chan struct{}),
		apiReloadCh:      make(chan *ctrld.Config),
	}
	p.logger.Store(discardLogger())
	p.startedInAPIMaintenance.Store(true)

	// Recovery now means the configuration reached the reload, so something
	// has to receive it.
	go func() {
		for {
			select {
			case <-p.apiReloadCh:
				// Stand in for the reload receiver applying it.
				p.maintenanceConfigApplied(discardLogger())
			case <-p.stopCh:
				return
			}
		}
	}()

	done := make(chan struct{})
	go func() { defer close(done); p.apiConfigReload() }()
	t.Cleanup(func() {
		close(p.stopCh)
		<-done
	})

	select {
	case <-recovered:
	case <-time.After(10 * time.Second):
		t.Fatal("the maintenance retry never reached the API")
	}

	// The flag clears on the successful fetch, which is what stops the retry.
	deadline := time.Now().Add(5 * time.Second)
	for p.startedInAPIMaintenance.Load() {
		if time.Now().After(deadline) {
			t.Fatal("the run stayed in maintenance after the API answered")
		}
		time.Sleep(time.Millisecond)
	}

	settled := calls.Load()
	time.Sleep(50 * time.Millisecond)
	if extra := calls.Load() - settled; extra > 1 {
		t.Fatalf("the faster retry kept running after recovery: %d more fetches", extra)
	}
}

func ptrTo[T any](v T) *T { return &v }
