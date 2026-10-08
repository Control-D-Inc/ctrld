package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/controld"
)

// configReadFromDisk records that startup read a configuration file this host
// already had, instead of generating a default one because none existed.
//
// The distinction only matters while the API is in maintenance. A generated
// default carries the public freedns upstreams, so falling back to it would
// answer queries outside the Control D profile the operator provisioned —
// quietly serving a policy nobody chose, which is worse than not starting.
// Only a file the host already had can stand in for the configuration the API
// would have returned.
var configReadFromDisk bool

// maintenanceNoConfigDetail is what ctrld reports when maintenance stops a
// start that has nothing to fall back on. It names the operation that cannot
// happen rather than the fetch that failed, because "could not fetch resolver
// config" reads as a network fault and sends the reader after connectivity
// that is not broken.
const maintenanceNoConfigDetail = "cannot provision during Control D API maintenance: " +
	"this host has no previously working configuration to fall back on. Retry once maintenance ends."

// managedConfigMarkerFile records that the configuration file next to it was
// written from an API answer, and for which identity.
//
// File presence cannot carry this on its own. A start that has no
// configuration writes the seeded default before the API is ever reached, so a
// provisioning that failed leaves a file behind that the next start reads
// successfully. That file holds the public freedns upstreams, so trusting it
// would run the endpoint outside the Control D profile it was provisioned for
// — the exact outcome the fallback exists to avoid.
const managedConfigMarkerFile = ".managed_config"

// managedConfigMarkerPath is a var so tests can place the marker in a temp dir.
var managedConfigMarkerPath = func() string { return absHomeDir(managedConfigMarkerFile) }

// managedConfigMarker fingerprints both the identity and the configuration file
// the marker is recorded for.
//
// The identity alone cannot carry it. A marker that names only the identity
// outlives the file it vouched for: delete or move that file and the next start
// regenerates the seeded default, which the stale marker then certifies. The
// same happens when --config points somewhere else under the same home. Binding
// to the contents means any file the API did not produce fails the check,
// without having to detect how it got there.
//
// The raw identity is kept off disk: it is redacted from retained logs, and a
// marker only ever has to answer whether this is the same identity.
func managedConfigMarker(uid, path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	identity := sha256.Sum256([]byte(uid))
	contents := sha256.Sum256(data)
	return hex.EncodeToString(identity[:]) + ":" + hex.EncodeToString(contents[:]), nil
}

// recordManagedConfig notes that the configuration on disk came from the API
// for uid. The caller must have persisted that configuration first, or the
// marker would vouch for a file that does not match it.
func recordManagedConfig(uid string) error {
	if uid == "" {
		return nil
	}
	marker, err := managedConfigMarker(uid, defaultConfigFile)
	if err != nil {
		return err
	}
	return os.WriteFile(managedConfigMarkerPath(), []byte(marker), 0600)
}

// managedConfigRecordedFor reports whether the configuration file in use was
// written from an API answer for uid.
func managedConfigRecordedFor(uid string) bool {
	if uid == "" {
		return false
	}
	recorded, err := os.ReadFile(managedConfigMarkerPath())
	if err != nil {
		return false
	}
	want, err := managedConfigMarker(uid, defaultConfigFile)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(recorded)) == want
}

// lastKnownConfigUsable reports whether cfg can carry this start by itself.
//
// It is deliberately quiet: this is a probe, and the caller reports either
// outcome. Startup validates the configuration again further on and reports
// its own errors there, so a failure here must not also print them.
func lastKnownConfigUsable(cfg *ctrld.Config) bool {
	if !configReadFromDisk || cfg == nil {
		return false
	}
	// A file this host already had is necessary but not sufficient: it must
	// also be one the API produced, for the identity being asked for now.
	if !managedConfigRecordedFor(cdUID) {
		return false
	}
	return ctrld.ValidateConfig(validator.New(), cfg) == nil
}

// useLastKnownConfigDuringMaintenance reports whether startup may continue on
// the configuration already on disk because the API is in maintenance.
//
// Maintenance says nothing about this host's configuration — the same request
// succeeds once the window ends — so stopping DNS for its duration turns a
// temporary API outage into an endpoint outage. Continuing is only honest when
// the configuration on disk is one the API itself produced on an earlier run:
// configReadFromDisk establishes that this host already had the file, and the
// managed-config marker that the API produced it for this identity. The marker
// is the load-bearing half - a file alone can be a generated default.
//
// The resolver config stays nil: this run has none, and the reload path
// already treats a nil one as "no previous response to compare against", so
// the first successful reload after maintenance adopts the fresh answer.
func useLastKnownConfigDuringMaintenance(err error, cfg *ctrld.Config) bool {
	if !controld.IsMaintenance(err) {
		return false
	}
	logger := mainLog.Load().With().Str("mode", "cd")
	if !lastKnownConfigUsable(cfg) {
		journal(logger.Error()).Str("reason", "api_maintenance").
			Msg("Control D API is in maintenance and no previously working configuration is on disk")
		return false
	}
	journal(logger.Warn()).Str("reason", "api_maintenance").
		Msg("Control D API is in maintenance; starting with the last known working configuration on disk")
	return true
}

// logResolverConfigFetchFailure reports a resolver-config fetch that failed on
// a path which keeps serving DNS afterwards: the periodic reload and the
// self-uninstall probe.
//
// Maintenance gets its own line, and it is journaled. "could not fetch
// resolver config" reads as a fault on this host and sends the reader after
// connectivity that is not broken, which is how the reported incident was
// first triaged. It also leaves a later "why is my configuration stale"
// question unanswerable once the debug stream has rotated. The reload runs
// hourly by default, so one retained line per window is bounded.
func logResolverConfigFetchFailure(logger *ctrld.Logger, err error) {
	if controld.IsMaintenance(err) {
		journal(logger.Warn()).Err(err).Str("reason", "api_maintenance").
			Msg("Control D API is in maintenance; keeping the current configuration until it returns")
		return
	}
	logger.Warn().Err(err).Msg("Could not fetch resolver config")
}

const (
	// maintenanceReloadInterval is how soon a run that started on the
	// configuration on disk asks the API again. It is deliberately far below
	// refetch_time: such a run holds no answer from the API at all, so its
	// exclude list, Internal Domains, deactivation pin and self-upgrade check
	// are all still those of the previous run until one arrives.
	maintenanceReloadInterval = 5 * time.Minute
	// maintenanceReloadJitter spreads those retries across the hosts that
	// started during the same window.
	//
	// The hourly ticker needs no jitter because each host starts it at its own
	// boot time, which spreads the fleet on its own. A maintenance window
	// removes that spread: every host that falls back does so within the same
	// few minutes, so a fixed retry would put them all in lockstep and land as
	// one burst on the API exactly as it comes back.
	maintenanceReloadJitter = 2 * time.Minute
)

// maintenanceReloadDelay returns the wait before the next retry of a run that
// started on the configuration on disk. It is a var so a test can drive the
// reload loop without waiting out a real interval.
var maintenanceReloadDelay = func() time.Duration {
	return maintenanceReloadInterval + time.Duration(rand.Int63n(int64(maintenanceReloadJitter)))
}

// maintenanceConfigApplied records that a run which started on the
// configuration on disk has handed an answer from the API to the reload path.
//
// It is deliberately not called when the fetch succeeds, nor when the response
// is handed to the reload. The reload receiver reads the configuration and
// fetches again, and either step can fail; until it does not, the endpoint is
// still serving what it started with. Clearing the flag earlier would stop the
// faster retry and report a recovery that had not happened.
func (p *prog) maintenanceConfigApplied(logger *ctrld.Logger) {
	if p.startedInAPIMaintenance.CompareAndSwap(true, false) {
		journal(logger.Info()).Str("reason", "api_maintenance").
			Msg("Control D API answered again; this run applied the configuration it returned")
	}
}

// persistManagedConfig writes cfg and, on a run the API manages, records that
// the file it just wrote came from there.
//
// The two belong together. The marker is bound to the file's contents, and
// every API-driven change rewrites that file, so a write that does not refresh
// the marker leaves the host ineligible for the very fallback its own
// configuration is meant to provide - including recovery from a maintenance
// start. A failed write certifies nothing, and a run with no resolver UID
// writes nothing the API produced: generated defaults and NextDNS
// configurations must never be certified.
func persistManagedConfig(cfg *ctrld.Config, logger *ctrld.Logger) {
	if err := writeConfigFile(cfg); err != nil {
		logger.Error().Err(err).Msg("Could not write new config")
		return
	}
	if cdUID == "" {
		return
	}
	if err := recordManagedConfig(cdUID); err != nil {
		logger.Warn().Err(err).Msg("Could not record that this configuration came from the API")
	}
}

// recordManagedConfigForStart refreshes the marker once a start has finished
// writing its configuration.
//
// fetchedThisRun is whether the API answered this run. wasManagedBeforeWrite is
// whether the file already carried a marker for this identity before anything
// this start rewrote it. Either is enough: a maintenance fallback fetches
// nothing, yet still rewrites the file through the listener and intercept-mode
// updates, and the marker is bound to the file's contents - so without the
// second the next start in the same window loses the fallback this one used.
// Neither means the file is a generated default or otherwise unmanaged, which
// must never be certified.
func recordManagedConfigForStart(fetchedThisRun, wasManagedBeforeWrite bool) {
	if !fetchedThisRun && !wasManagedBeforeWrite {
		return
	}
	if err := recordManagedConfig(cdUID); err != nil {
		// Not fatal: this run is fine. It only costs the next start its
		// fallback if the API is in maintenance then.
		mainLog.Load().Warn().Err(err).Msg("Could not record that this configuration came from the API")
	}
}
