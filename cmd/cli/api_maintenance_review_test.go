package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/viper"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/controld"
)

// TestMaintenanceFallbackRejectsGeneratedDefaultAcrossStarts covers the gap a
// boolean set by hand cannot: a first start with no configuration writes the
// seeded default before the API is ever reached, so a provisioning that failed
// leaves a file the next start reads successfully. Without the managed-config
// marker that file is accepted as a "last known configuration" and the
// endpoint runs on the public freedns upstreams instead of its profile.
func TestMaintenanceFallbackRejectsGeneratedDefaultAcrossStarts(t *testing.T) {
	dir := t.TempDir()
	oldV, oldFile, oldPath := v, defaultConfigFile, configPath
	oldRead, oldUID, oldMarker := configReadFromDisk, cdUID, managedConfigMarkerPath
	t.Cleanup(func() {
		v, defaultConfigFile, configPath = oldV, oldFile, oldPath
		configReadFromDisk, cdUID, managedConfigMarkerPath = oldRead, oldUID, oldMarker
	})
	configPath = ""
	cdUID = "provisioned-uid"
	managedConfigMarkerPath = func() string { return filepath.Join(dir, managedConfigMarkerFile) }
	cfgPath := filepath.Join(dir, "ctrld.toml")

	// One process start, using the real config reader and default generation.
	start := func(t *testing.T) (*ctrld.Config, bool) {
		t.Helper()
		v = viper.NewWithOptions(viper.KeyDelimiter("::"))
		ctrld.InitConfig(v, "ctrld")
		ctrld.SetConfigNameWithPath(v, "ctrld", dir)
		defaultConfigFile = cfgPath
		configReadFromDisk = false
		// writeDefaultConfig is false: the file exists by now, and default
		// generation is covered above.
		readConfigFile(false, false)
		started := &ctrld.Config{}
		if err := v.Unmarshal(started); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return started, lastKnownConfigUsable(started)
	}

	// The failed first start: no configuration existed, so ctrld generated the
	// seeded default and wrote it. Reproduced by writing exactly what
	// readConfigFile writes there, minus its listener probe, which binds
	// privileged ports and cannot run in a test. What matters for the guard is
	// the file's content and that no read set configReadFromDisk.
	v = viper.NewWithOptions(viper.KeyDelimiter("::"))
	ctrld.InitConfig(v, "ctrld")
	defaultConfigFile = cfgPath
	configReadFromDisk = false
	generated := &ctrld.Config{}
	if err := v.Unmarshal(generated); err != nil {
		t.Fatalf("unmarshal defaults: %v", err)
	}
	if err := writeConfigFile(generated); err != nil {
		t.Fatalf("write generated default: %v", err)
	}
	if configReadFromDisk {
		t.Fatal("generating a default must not count as reading one")
	}
	if lastKnownConfigUsable(generated) {
		t.Fatal("the first start accepted a configuration it had just generated")
	}
	// Prove the generated default is the thing that must never be trusted.
	var endpoints []string
	for _, uc := range generated.Upstream {
		endpoints = append(endpoints, uc.Endpoint)
	}
	if !strings.Contains(strings.Join(endpoints, " "), "freedns.controld.com") {
		t.Fatalf("expected the seeded freedns default, got %v", endpoints)
	}

	// Second start: the leftover file now reads back through the real reader,
	// but no API answer ever produced it.
	second, ok := start(t)
	if !configReadFromDisk {
		t.Fatal("the leftover file was not read, so the boundary is not being exercised")
	}
	if ok {
		t.Fatal("a generated default was accepted as a last known configuration on a later start")
	}

	// A genuine provisioning records the marker; the fallback then applies.
	if err := recordManagedConfig(cdUID); err != nil {
		t.Fatalf("recordManagedConfig: %v", err)
	}
	if _, ok := start(t); !ok {
		t.Fatal("a configuration the API produced was rejected")
	}

	// The marker belongs to one identity and must not carry to another.
	cdUID = "a-different-uid"
	if _, ok := start(t); ok {
		t.Fatal("a marker for another identity authorized this one")
	}
	_ = second
}

// TestMaintenanceRecoveryDeliversReload covers what recovery has to mean. The
// first answer after a maintenance start is the only one that differs from the
// nil configuration the run holds; if it is compared away, every later answer
// equals the stored one and the excludes and Internal Domains of the previous
// run stay in place for good.
func TestMaintenanceRecoveryDeliversReload(t *testing.T) {
	oldFetch, oldDelay, oldUID := fetchResolverConfigFn, maintenanceReloadDelay, cdUID
	t.Cleanup(func() {
		fetchResolverConfigFn, maintenanceReloadDelay, cdUID = oldFetch, oldDelay, oldUID
	})
	cdUID = "test-uid"
	maintenanceReloadDelay = func() time.Duration { return time.Millisecond }

	var calls atomic.Int64
	fetchResolverConfigFn = func(context.Context, *controld.ResolverConfigRequest, bool) (*controld.ResolverConfig, error) {
		calls.Add(1)
		// A plain answer: no custom config, and excludes the run has never seen.
		return &controld.ResolverConfig{Exclude: []string{"excluded.example"}}, nil
	}

	p := &prog{
		cfg:              &ctrld.Config{Service: ctrld.ServiceConfig{RefetchTime: ptrTo(3600)}},
		stopCh:           make(chan struct{}),
		runAbortCh:       make(chan struct{}),
		apiForceReloadCh: make(chan struct{}),
		apiReloadCh:      make(chan *ctrld.Config),
	}
	p.logger.Store(discardLogger())
	p.startedInAPIMaintenance.Store(true)

	done := make(chan struct{})
	go func() { defer close(done); p.apiConfigReload() }()
	t.Cleanup(func() {
		close(p.stopCh)
		<-done
	})

	select {
	case <-p.apiReloadCh:
		// Stand in for the reload receiver applying it.
		p.maintenanceConfigApplied(discardLogger())
	case <-time.After(10 * time.Second):
		t.Fatal("recovery never delivered a reload, so the endpoint kept the configuration it started with")
	}

	deadline := time.Now().Add(5 * time.Second)
	for p.startedInAPIMaintenance.Load() {
		if time.Now().After(deadline) {
			t.Fatal("the run stayed in maintenance after applying the configuration")
		}
		time.Sleep(time.Millisecond)
	}
	if calls.Load() == 0 {
		t.Fatal("no fetch happened")
	}
}

// TestDeactivationPinUnknownDuringMaintenance covers the PIN state a
// maintenance start leaves behind. cdDeactivationPin's default means "the API
// says there is none"; a run that never asked must not present that as
// permission to deactivate.
func TestDeactivationPinUnknownDuringMaintenance(t *testing.T) {
	oldUID, oldPin, oldKnown := cdUID, cdDeactivationPin.Load(), deactivationPinKnown.Load()
	t.Cleanup(func() {
		cdUID = oldUID
		cdDeactivationPin.Store(oldPin)
		deactivationPinKnown.Store(oldKnown)
		deactivationLockedUntil.Store(0)
	})
	cdUID = "test-uid"
	deactivationLockedUntil.Store(0)

	// The handler re-fetches before it checks the PIN. Without this the test
	// reaches the production API with a made-up uid, and the statuses below
	// would depend on that call failing rather than on the maintenance answer
	// the case is about.
	oldFetch := fetchResolverConfig
	t.Cleanup(func() { fetchResolverConfig = oldFetch })
	var fetches atomic.Int64
	fetchResolverConfig = func(context.Context, *controld.ResolverConfigRequest, bool) (*controld.ResolverConfig, error) {
		fetches.Add(1)
		return nil, maintenanceAPIErr(http.StatusServiceUnavailable)
	}

	post := func(t *testing.T) int {
		t.Helper()
		p := &prog{cs: &controlServer{mux: http.NewServeMux()}, pinCodeValidCh: make(chan struct{}, 1)}
		p.logger.Store(discardLogger())
		p.registerControlServerHandler()
		body, _ := json.Marshal(&deactivationRequest{Pin: defaultDeactivationPin})
		req := httptest.NewRequest(http.MethodPost, deactivationPath, strings.NewReader(string(body)))
		w := httptest.NewRecorder()
		p.cs.mux.ServeHTTP(w, req)
		return w.Code
	}

	t.Run("a run that never asked refuses", func(t *testing.T) {
		cdDeactivationPin.Store(defaultDeactivationPin)
		deactivationPinKnown.Store(false)
		if got := post(t); got != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want %d: an unknown PIN authorized deactivation", got, http.StatusServiceUnavailable)
		}
	})

	t.Run("a confirmed no-PIN configuration still allows it", func(t *testing.T) {
		cdDeactivationPin.Store(defaultDeactivationPin)
		deactivationPinKnown.Store(true)
		if got := post(t); got != http.StatusOK {
			t.Fatalf("status = %d, want 200: a device with no PIN can no longer be deactivated", got)
		}
	})

	t.Run("an answering API settles the question", func(t *testing.T) {
		// The re-fetch is what makes the PIN knowable again mid-run, so the
		// stub has to be able to answer, not only fail.
		fetchResolverConfig = func(context.Context, *controld.ResolverConfigRequest, bool) (*controld.ResolverConfig, error) {
			return &controld.ResolverConfig{}, nil
		}
		cdDeactivationPin.Store(defaultDeactivationPin)
		deactivationPinKnown.Store(false)
		if got := post(t); got != http.StatusOK {
			t.Fatalf("status = %d, want 200: an API answer did not settle the PIN", got)
		}
		if !deactivationPinKnown.Load() {
			t.Fatal("an API answer left the PIN unknown")
		}
	})

	if fetches.Load() == 0 {
		t.Fatal("the handler never reached the fetch seam, so the stub proved nothing")
	}
}

// The client must not report an unverifiable PIN as a wrong one, and must
// still refuse the operation.
func TestUnverifiableDeactivationPinIsARefusal(t *testing.T) {
	if !isCheckDeactivationPinErr(errUnverifiableDeactivationPin) {
		t.Fatal("an unverifiable PIN did not stop stop/uninstall")
	}
}

// TestManagedMarkerDoesNotOutliveItsConfig covers the provenance residual: a
// marker naming only the identity survives the file it vouched for, so a
// previously managed host whose config goes missing regenerates the seeded
// default and the stale marker certifies it.
func TestManagedMarkerDoesNotOutliveItsConfig(t *testing.T) {
	dir := t.TempDir()
	oldV, oldFile, oldPath := v, defaultConfigFile, configPath
	oldRead, oldUID, oldMarker := configReadFromDisk, cdUID, managedConfigMarkerPath
	t.Cleanup(func() {
		v, defaultConfigFile, configPath = oldV, oldFile, oldPath
		configReadFromDisk, cdUID, managedConfigMarkerPath = oldRead, oldUID, oldMarker
	})
	configPath = ""
	cdUID = "provisioned-uid"
	managedConfigMarkerPath = func() string { return filepath.Join(dir, managedConfigMarkerFile) }
	cfgPath := filepath.Join(dir, "ctrld.toml")

	start := func(t *testing.T) bool {
		t.Helper()
		v = viper.NewWithOptions(viper.KeyDelimiter("::"))
		ctrld.InitConfig(v, "ctrld")
		ctrld.SetConfigNameWithPath(v, "ctrld", dir)
		defaultConfigFile = cfgPath
		configReadFromDisk = false
		readConfigFile(false, false)
		started := &ctrld.Config{}
		if err := v.Unmarshal(started); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return lastKnownConfigUsable(started)
	}

	// A managed configuration and its marker, written the way a successful run
	// writes them.
	managed := provisionedConfig()
	defaultConfigFile = cfgPath
	if err := writeConfigFile(managed); err != nil {
		t.Fatalf("write managed config: %v", err)
	}
	if err := recordManagedConfig(cdUID); err != nil {
		t.Fatalf("recordManagedConfig: %v", err)
	}
	if !start(t) {
		t.Fatal("positive control: a managed configuration was rejected")
	}

	// The file goes missing and the next start regenerates the seeded default,
	// while the marker for the same identity stays behind.
	if err := os.Remove(cfgPath); err != nil {
		t.Fatal(err)
	}
	v = viper.NewWithOptions(viper.KeyDelimiter("::"))
	ctrld.InitConfig(v, "ctrld")
	defaultConfigFile = cfgPath
	regenerated := &ctrld.Config{}
	if err := v.Unmarshal(regenerated); err != nil {
		t.Fatalf("unmarshal defaults: %v", err)
	}
	if err := writeConfigFile(regenerated); err != nil {
		t.Fatalf("write regenerated default: %v", err)
	}
	var endpoints []string
	for _, uc := range regenerated.Upstream {
		endpoints = append(endpoints, uc.Endpoint)
	}
	if !strings.Contains(strings.Join(endpoints, " "), "freedns.controld.com") {
		t.Fatalf("expected the seeded freedns default, got %v", endpoints)
	}

	if start(t) {
		t.Fatal("a stale marker certified a regenerated default")
	}
}

// TestMaintenanceRecoveryOutlivesAFailedApply covers the other residual: the
// reload receiver fetches again and can fail. Acknowledging recovery when the
// trigger is sent would clear the flag while the endpoint still serves what it
// started with, and every later identical answer would then compare equal to
// the already-stored response and never be applied again.
func TestMaintenanceRecoveryOutlivesAFailedApply(t *testing.T) {
	oldFetch, oldDelay, oldUID := fetchResolverConfigFn, maintenanceReloadDelay, cdUID
	t.Cleanup(func() {
		fetchResolverConfigFn, maintenanceReloadDelay, cdUID = oldFetch, oldDelay, oldUID
	})
	cdUID = "test-uid"
	maintenanceReloadDelay = func() time.Duration { return time.Millisecond }

	// The same answer every time, as a recovered API would give.
	fetchResolverConfigFn = func(context.Context, *controld.ResolverConfigRequest, bool) (*controld.ResolverConfig, error) {
		return &controld.ResolverConfig{Exclude: []string{"excluded.example"}}, nil
	}

	p := &prog{
		cfg:              &ctrld.Config{Service: ctrld.ServiceConfig{RefetchTime: ptrTo(3600)}},
		stopCh:           make(chan struct{}),
		runAbortCh:       make(chan struct{}),
		apiForceReloadCh: make(chan struct{}),
		apiReloadCh:      make(chan *ctrld.Config),
	}
	p.logger.Store(discardLogger())
	p.startedInAPIMaintenance.Store(true)

	// A receiver that takes the trigger and then fails to apply, the way the
	// real one does when its own fetch cannot reach the API.
	var delivered atomic.Int64
	go func() {
		for {
			select {
			case <-p.apiReloadCh:
				delivered.Add(1)
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

	// A failed apply must leave the run pending and keep redelivering, even
	// though every answer after the first is identical.
	deadline := time.Now().Add(10 * time.Second)
	for delivered.Load() < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("redelivery stopped after %d triggers; an identical answer was compared away", delivered.Load())
		}
		time.Sleep(time.Millisecond)
	}
	if !p.startedInAPIMaintenance.Load() {
		t.Fatal("recovery was acknowledged without the configuration being applied")
	}
}

// TestManagedReloadKeepsFallbackEligibility covers the provenance residual on
// the reload path: the marker is bound to the file's contents, and every
// API-driven change rewrites that file. A reload that persists a new managed
// configuration without refreshing the marker leaves the host unable to fall
// back on the configuration it just successfully applied.
func TestManagedReloadKeepsFallbackEligibility(t *testing.T) {
	dir := t.TempDir()
	oldV, oldFile, oldPath := v, defaultConfigFile, configPath
	oldRead, oldUID, oldMarker := configReadFromDisk, cdUID, managedConfigMarkerPath
	t.Cleanup(func() {
		v, defaultConfigFile, configPath = oldV, oldFile, oldPath
		configReadFromDisk, cdUID, managedConfigMarkerPath = oldRead, oldUID, oldMarker
	})
	configPath = ""
	cdUID = "provisioned-uid"
	managedConfigMarkerPath = func() string { return filepath.Join(dir, managedConfigMarkerFile) }
	cfgPath := filepath.Join(dir, "ctrld.toml")

	// A restart that reads whatever is on disk now, as a maintenance start does.
	restart := func(t *testing.T) bool {
		t.Helper()
		v = viper.NewWithOptions(viper.KeyDelimiter("::"))
		ctrld.InitConfig(v, "ctrld")
		ctrld.SetConfigNameWithPath(v, "ctrld", dir)
		defaultConfigFile = cfgPath
		configReadFromDisk = false
		readConfigFile(false, false)
		started := &ctrld.Config{}
		if err := v.Unmarshal(started); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return lastKnownConfigUsable(started)
	}

	// Managed startup.
	defaultConfigFile = cfgPath
	if err := writeConfigFile(provisionedConfig()); err != nil {
		t.Fatal(err)
	}
	if err := recordManagedConfig(cdUID); err != nil {
		t.Fatal(err)
	}
	if !restart(t) {
		t.Fatal("a managed startup was not eligible to fall back")
	}

	// An API-driven reload persists a changed managed configuration, through
	// the same call the reload receiver makes.
	changed := provisionedConfig()
	changed.Upstream["0"].Endpoint = "https://dns.controld.com/changed5678"
	logger := mainLog.Load()
	defaultConfigFile = cfgPath
	persistManagedConfig(changed, logger)

	onDisk, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(onDisk), "changed5678") {
		t.Fatal("the reload did not persist the changed configuration")
	}
	if !restart(t) {
		t.Fatal("a successfully applied managed configuration was not eligible to fall back")
	}

	// The guards must survive: a write with no resolver UID certifies nothing.
	cdUID = ""
	stillChanged := provisionedConfig()
	stillChanged.Upstream["0"].Endpoint = "https://dns.controld.com/unmanaged9999"
	persistManagedConfig(stillChanged, logger)
	cdUID = "provisioned-uid"
	if restart(t) {
		t.Fatal("a write outside managed mode refreshed the marker")
	}
}

// TestFallbackStartRewriteKeepsEligibility covers the startup half of the
// content-bound marker. A maintenance fallback fetches nothing, so it records
// no new marker, but it can still rewrite the file through the listener or
// intercept-mode updates. If the marker is left on the pre-write bytes, the
// next start in the same window is denied the fallback this one just used.
func TestFallbackStartRewriteKeepsEligibility(t *testing.T) {
	dir := t.TempDir()
	oldV, oldFile, oldPath := v, defaultConfigFile, configPath
	oldRead, oldUID, oldMarker := configReadFromDisk, cdUID, managedConfigMarkerPath
	t.Cleanup(func() {
		v, defaultConfigFile, configPath = oldV, oldFile, oldPath
		configReadFromDisk, cdUID, managedConfigMarkerPath = oldRead, oldUID, oldMarker
	})
	configPath = ""
	cdUID = "provisioned-uid"
	managedConfigMarkerPath = func() string { return filepath.Join(dir, managedConfigMarkerFile) }
	cfgPath := filepath.Join(dir, "ctrld.toml")

	restart := func(t *testing.T) bool {
		t.Helper()
		v = viper.NewWithOptions(viper.KeyDelimiter("::"))
		ctrld.InitConfig(v, "ctrld")
		ctrld.SetConfigNameWithPath(v, "ctrld", dir)
		defaultConfigFile = cfgPath
		configReadFromDisk = false
		readConfigFile(false, false)
		started := &ctrld.Config{}
		if err := v.Unmarshal(started); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return lastKnownConfigUsable(started)
	}

	// An earlier successful run left a managed configuration and its marker.
	defaultConfigFile = cfgPath
	if err := writeConfigFile(provisionedConfig()); err != nil {
		t.Fatal(err)
	}
	if err := recordManagedConfig(cdUID); err != nil {
		t.Fatal(err)
	}
	if !restart(t) {
		t.Fatal("a managed configuration was not eligible to fall back")
	}

	// A maintenance start: no fetch happened, so nothing new is recorded, but
	// the listener/intercept updates still rewrite the file. This mirrors the
	// startup ordering in run(): remember provenance, rewrite, then re-record.
	managedConfigFetched := false
	wasManagedConfig := managedConfigRecordedFor(cdUID)
	if !wasManagedConfig {
		t.Fatal("the pre-write file was not recognized as managed")
	}
	rewritten := provisionedConfig()
	rewritten.Listener["0"].Port = 5354 // e.g. the macOS intercept port fallback
	if err := writeConfigFile(rewritten); err != nil {
		t.Fatal(err)
	}
	recordManagedConfigForStart(managedConfigFetched, wasManagedConfig)

	if !restart(t) {
		t.Fatal("a rewrite during a maintenance fallback denied the next start its fallback")
	}

	// The guard must survive: a rewrite with no prior managed provenance and no
	// fetch still certifies nothing.
	if err := os.Remove(managedConfigMarkerPath()); err != nil {
		t.Fatal(err)
	}
	if managedConfigRecordedFor(cdUID) {
		t.Fatal("the marker survived its own removal")
	}
	if restart(t) {
		t.Fatal("a file with no managed provenance was accepted")
	}
}
