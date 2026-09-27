package merlin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/kardianos/service"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/router/dnsmasq"
	"github.com/Control-D-Inc/ctrld/internal/router/ntp"
	"github.com/Control-D-Inc/ctrld/internal/router/nvram"
)

const Name = "merlin"

const (
	merlinManagedStatePath       = "/jffs/controld/.merlin-dnsmasq-hooks-v2"
	merlinSnapshotStatePath      = "/jffs/controld/.merlin-dnsmasq-snapshot"
	merlinSnapshotAnchorPath     = "/jffs/configs/.dnsmasq.conf.ctrld-anchor"
	merlinSnapshotQuarantinePath = "/jffs/configs/.dnsmasq.conf.ctrld-quarantine"
	merlinCleanupPendingPath     = "/jffs/controld/.merlin-dnsmasq-cleanup-pending"
)

// nvramKvMap is a map of NVRAM key-value pairs used to configure and manage Merlin-specific settings.
var nvramKvMap = map[string]string{
	"dnspriv_enable": "0", // Ensure Merlin native DoT disabled.
}


// Merlin represents a configuration handler for setting up and managing ctrld on Merlin routers.
type Merlin struct {
	cfg *ctrld.Config
}

// New returns a router.Router for configuring/setup/run ctrld on Merlin routers.
func New(cfg *ctrld.Config) *Merlin {
	return &Merlin{cfg: cfg}
}

// ConfigureService configures the service based on the provided configuration. It returns an error if the configuration fails.
func (m *Merlin) ConfigureService(config *service.Config) error {
	return nil
}

// Install sets up the necessary configurations and services required for the Merlin instance to function properly.
func (m *Merlin) Install(_ *service.Config) error {
	return nil
}

// Uninstall removes the ctrld-related configurations and services from the Merlin router and reverts to the original state.
func (m *Merlin) Uninstall(_ *service.Config) error {
	return nil
}

// PreRun prepares the Merlin instance for operation by waiting for essential services and directories to become available.
func (m *Merlin) PreRun() error {
	// Reconcile any previous Merlin integration before starting again. Router
	// startup is a one-shot launch, so retry transient JFFS/NVRAM/dnsmasq errors
	// here instead of abandoning DNS in a partially reconciled state.
	var cleanupErr error
	for attempt := 1; attempt <= 3; attempt++ {
		cleanupErr = m.Cleanup()
		if cleanupErr == nil {
			break
		}
		if attempt < 3 {
			time.Sleep(time.Second)
		}
	}
	if cleanupErr != nil {
		return fmt.Errorf("failed to cleanup previous Merlin integration after retries: %w", cleanupErr)
	}
	// Wait NTP ready.
	if err := ntp.WaitNvram(); err != nil {
		return err
	}
	// Wait until directories mounted.
	for _, dir := range []string{"/tmp", "/proc"} {
		waitDirExists(dir)
	}
	// Wait dnsmasq started.
	for {
		out, _ := exec.Command("pidof", "dnsmasq").CombinedOutput()
		if len(bytes.TrimSpace(out)) > 0 {
			break
		}
		time.Sleep(time.Second)
	}
	return nil
}

// Setup initializes and configures the Merlin instance for use, including setting up dnsmasq and necessary nvram settings.
func (m *Merlin) Setup() (retErr error) {
	if m.cfg.FirstListener().IsDirectDnsListener() {
		return nil
	}
	// Already setup.
	setupVal, err := nvram.Run("get", nvram.CtrldSetupKey)
	if err != nil {
		return fmt.Errorf("read Merlin setup state: %w", err)
	}
	if setupVal == "1" {
		return nil
	}

	// Mark this as the hook-based integration before changing NVRAM so any
	// failure after this point is rollback-visible.
	if err := atomicWriteFile(merlinManagedStatePath, []byte("hooks-v2\n"), 0600); err != nil {
		return fmt.Errorf("failed to write Merlin integration state: %w", err)
	}

	defer func() {
		if retErr == nil {
			return
		}
		if cleanupErr := m.Cleanup(); cleanupErr != nil {
			retErr = fmt.Errorf("%v; rollback failed: %w", retErr, cleanupErr)
		}
	}()

	// Apply NVRAM changes before regenerating dnsmasq so the firmware-generated
	// config reflects ctrld's desired DNS Privacy state. nvram.SetKV rolls back
	// its own partial mutations on failure.
	if err := nvram.SetKVWithVolatileRetryMarker(nvramKvMap, nvram.CtrldSetupKey); err != nil {
		return err
	}

	if err := m.writeDnsmasqPostconf(); err != nil {
		return err
	}

	// On Merlin 3006 this restarts the main and all SDN dnsmasq instances,
	// causing dnsmasq.postconf and dnsmasq-sdn.postconf to run.
	if err := restartDNSMasq(); err != nil {
		return err
	}

	mainOK, err := m.dnsmasqConfigUsesCtrld(dnsmasq.MerlinConfPath)
	if err != nil {
		return err
	}
	if !mainOK {
		// Compatibility fallback for older Merlin devices where postconf is
		// known not to execute. Never overwrite an unowned user config.
		if err := m.setupMainDnsmasqFallback(); err != nil {
			return err
		}
		if err := restartDNSMasq(); err != nil {
			return err
		}
		mainOK, err = m.dnsmasqConfigUsesCtrld(dnsmasq.MerlinConfPath)
		if err != nil {
			return err
		}
		if !mainOK {
			return fmt.Errorf("Merlin dnsmasq integration was not applied to %s", dnsmasq.MerlinConfPath)
		}
	}

	// Additional dnsmasq instances are Guest Network Pro / SDN instances on
	// Merlin 3006. Their supported extension point is dnsmasq-sdn.postconf;
	// full /jffs/configs/dnsmasq-N.conf files are not consumed by Merlin.
	for _, path := range dnsmasq.AdditionalConfigFiles() {
		ok, err := m.dnsmasqConfigUsesCtrld(path)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("Merlin SDN dnsmasq integration was not applied to %s", path)
		}
	}

	return nil
}

const (
	legacyCleanupPhase = "cleanup-v2"
	legacyFinalizePhase = "finalize-v2"

	legacyEntryPending = "pending"
	legacyEntryDelete  = "delete"
	legacyEntryRestore = "restore"
)

type legacySnapshotEntry struct {
	state string
	path  string
	hash  string
}

type legacyCleanupJournal struct {
	phase   string
	entries []legacySnapshotEntry
}

// Cleanup restores the original dnsmasq and nvram configurations and restarts dnsmasq if necessary.
func (m *Merlin) Cleanup() error {
	// Preserve the existing direct-listener lifecycle. A direct listener needs
	// port 53 itself; restarting dnsmasq here would reclaim that port before
	// ctrld binds. Transitioning between forwarding and direct-listener modes
	// requires a separate port-ownership design and is outside this change.
	if m.cfg.FirstListener().IsDirectDnsListener() {
		return nil
	}

	setupVal, err := nvram.Run("get", nvram.CtrldSetupKey)
	if err != nil {
		return fmt.Errorf("read Merlin setup state during cleanup: %w", err)
	}
	managed, err := pathExists(merlinManagedStatePath)
	if err != nil {
		return fmt.Errorf("stat Merlin managed state: %w", err)
	}

	journal, err := readLegacyCleanupJournal()
	if err != nil {
		return fmt.Errorf("read Merlin legacy cleanup state: %w", err)
	}
	if setupVal != "1" && !managed && journal.phase == "" {
		return nil
	}

	legacy := journal.phase != "" || (setupVal == "1" && !managed)
	if legacy && journal.phase == "" {
		journal, err = buildLegacyCleanupJournal()
		if err != nil {
			return err
		}
		if err := writeLegacyCleanupJournal(journal); err != nil {
			if cleanupErr := cleanupLegacyCaptureAnchors(journal); cleanupErr != nil {
				return fmt.Errorf("journal legacy dnsmasq snapshots: %w; cleanup captured anchors: %v", err, cleanupErr)
			}
			return fmt.Errorf("journal legacy dnsmasq snapshots: %w", err)
		}
	}

	for _, path := range []string{dnsmasq.MerlinPostConfPath, dnsmasq.MerlinSdnPostConfPath} {
		if err := cleanupDnsmasqPostconf(path); err != nil {
			return err
		}
	}

	if legacy {
		if err := cleanupLegacySnapshots(&journal); err != nil {
			return err
		}
	} else {
		if err := cleanupOwnedMainSnapshot(); err != nil {
			return err
		}
	}

	// Restore NVRAM only after ctrld-owned artifacts are cleaned successfully.
	if setupVal == "1" {
		if err := nvram.RestoreWithVolatileRetryMarker(nvramKvMap, nvram.CtrldSetupKey); err != nil {
			return err
		}
	}

	if err := restartDNSMasq(); err != nil {
		return err
	}

	if err := removeFileDurable(merlinManagedStatePath); err != nil {
		return fmt.Errorf("remove Merlin managed state: %w", err)
	}
	if journal.phase != "" {
		if err := removeFileDurable(merlinCleanupPendingPath); err != nil {
			return fmt.Errorf("remove Merlin legacy cleanup state: %w", err)
		}
	}
	return nil
}

func legacySnapshotAnchorPath(path string) string {
	return filepath.Join(
		"/jffs/controld",
		"."+filepath.Base(path)+".ctrld-legacy-anchor",
	)
}

func removeLegacySnapshotAnchor(path string) error {
	if err := removeFileDurable(legacySnapshotAnchorPath(path)); err != nil {
		return fmt.Errorf("remove legacy snapshot anchor for %s: %w", path, err)
	}
	return nil
}

func cleanupLegacyCaptureAnchors(journal legacyCleanupJournal) error {
	for _, entry := range journal.entries {
		if err := removeLegacySnapshotAnchor(entry.path); err != nil {
			return err
		}
	}
	return nil
}

func buildLegacyCleanupJournal() (journal legacyCleanupJournal, retErr error) {
	// A quarantine is meaningful only together with a durable journal. Never
	// adopt an unjournaled private-looking pathname as ctrld-owned data.
	orphans, err := filepath.Glob(filepath.Join(
		dnsmasq.MerlinJffsConfDir,
		".dnsmasq*.ctrld-legacy-quarantine",
	))
	if err != nil {
		return legacyCleanupJournal{}, err
	}
	if len(orphans) != 0 {
		return legacyCleanupJournal{}, fmt.Errorf(
			"unjournaled Merlin legacy quarantine requires manual reconciliation: %s",
			strings.Join(orphans, ", "),
		)
	}

	// With no durable journal present, any ctrld-private legacy anchors can only
	// be leftovers from a crash before journal publication. Removing an anchor
	// drops only ctrld's extra hard link; it never touches the public snapshot.
	anchorOrphans, err := filepath.Glob("/jffs/controld/.dnsmasq*.ctrld-legacy-anchor")
	if err != nil {
		return legacyCleanupJournal{}, err
	}
	for _, anchor := range anchorOrphans {
		if err := removeFileDurable(anchor); err != nil {
			return legacyCleanupJournal{}, fmt.Errorf("remove orphaned legacy snapshot anchor %s: %w", anchor, err)
		}
	}

	paths := []string{dnsmasq.MerlinJffsConfPath}
	matches, err := filepath.Glob(filepath.Join(dnsmasq.MerlinJffsConfDir, "dnsmasq-*.conf"))
	if err != nil {
		return legacyCleanupJournal{}, err
	}
	paths = append(paths, matches...)

	journal = legacyCleanupJournal{phase: legacyCleanupPhase}
	captured := make([]string, 0, len(paths))
	defer func() {
		if retErr == nil {
			return
		}
		for _, path := range captured {
			_ = removeLegacySnapshotAnchor(path)
		}
	}()

	for _, path := range paths {
		if !isLegacySnapshotPath(path) {
			continue
		}

		f, err := os.Open(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return legacyCleanupJournal{}, fmt.Errorf("open legacy dnsmasq snapshot %s: %w", path, err)
		}
		info, err := f.Stat()
		if err != nil {
			_ = f.Close()
			return legacyCleanupJournal{}, fmt.Errorf("stat legacy dnsmasq snapshot %s: %w", path, err)
		}
		buf, err := io.ReadAll(f)
		closeErr := f.Close()
		if err != nil {
			return legacyCleanupJournal{}, fmt.Errorf("read legacy dnsmasq snapshot %s: %w", path, err)
		}
		if closeErr != nil {
			return legacyCleanupJournal{}, fmt.Errorf("close legacy dnsmasq snapshot %s: %w", path, closeErr)
		}
		hash := merlinSnapshotHash(buf)

		anchor := legacySnapshotAnchorPath(path)
		if err := os.Link(path, anchor); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return legacyCleanupJournal{}, fmt.Errorf("capture legacy snapshot identity %s: %w", path, err)
		}
		captured = append(captured, path)
		if err := syncParentDir(filepath.Dir(anchor)); err != nil {
			return legacyCleanupJournal{}, fmt.Errorf("sync legacy snapshot anchor %s: %w", anchor, err)
		}

		anchorInfo, err := os.Stat(anchor)
		if err != nil {
			return legacyCleanupJournal{}, fmt.Errorf("stat legacy snapshot anchor %s: %w", anchor, err)
		}
		if !os.SameFile(info, anchorInfo) {
			// The public pathname was replaced between Open and Link. Drop only
			// our private link and never claim the replacement.
			if err := removeLegacySnapshotAnchor(path); err != nil {
				return legacyCleanupJournal{}, err
			}
			captured = captured[:len(captured)-1]
			continue
		}
		anchorBuf, err := os.ReadFile(anchor)
		if err != nil {
			return legacyCleanupJournal{}, fmt.Errorf("read legacy snapshot anchor %s: %w", anchor, err)
		}
		if merlinSnapshotHash(anchorBuf) != hash {
			// Same inode was modified while identity was being captured. Treat it
			// as no longer safely attributable to ctrld.
			if err := removeLegacySnapshotAnchor(path); err != nil {
				return legacyCleanupJournal{}, err
			}
			captured = captured[:len(captured)-1]
			continue
		}

		journal.entries = append(journal.entries, legacySnapshotEntry{
			state: legacyEntryPending,
			path:  path,
			hash:  hash,
		})
	}
	return journal, nil
}

func writeLegacyCleanupJournal(journal legacyCleanupJournal) error {
	buf, err := encodeLegacyCleanupJournal(journal)
	if err != nil {
		return err
	}
	return atomicWriteFile(merlinCleanupPendingPath, buf, 0600)
}

func encodeLegacyCleanupJournal(journal legacyCleanupJournal) ([]byte, error) {
	var b strings.Builder
	b.WriteString(journal.phase)
	b.WriteByte('\n')
	if journal.phase == legacyFinalizePhase {
		if len(journal.entries) != 0 {
			return nil, fmt.Errorf("finalize journal contains snapshot entries")
		}
		return []byte(b.String()), nil
	}
	if journal.phase != legacyCleanupPhase {
		return nil, fmt.Errorf("unknown legacy cleanup phase %q", journal.phase)
	}
	for _, entry := range journal.entries {
		if !isLegacySnapshotPath(entry.path) {
			return nil, fmt.Errorf("invalid legacy snapshot path %q", entry.path)
		}
		switch entry.state {
		case legacyEntryPending, legacyEntryDelete, legacyEntryRestore:
		default:
			return nil, fmt.Errorf("invalid legacy snapshot state %q for %s", entry.state, entry.path)
		}
		if _, err := hex.DecodeString(entry.hash); err != nil || len(entry.hash) != sha256.Size*2 {
			return nil, fmt.Errorf("invalid legacy snapshot hash for %s", entry.path)
		}
		b.WriteString(entry.state)
		b.WriteByte('\t')
		b.WriteString(entry.path)
		b.WriteByte('\t')
		b.WriteString(entry.hash)
		b.WriteByte('\n')
	}
	return []byte(b.String()), nil
}

func readLegacyCleanupJournal() (legacyCleanupJournal, error) {
	buf, err := os.ReadFile(merlinCleanupPendingPath)
	if os.IsNotExist(err) {
		return legacyCleanupJournal{}, nil
	}
	if err != nil {
		return legacyCleanupJournal{}, err
	}
	return parseLegacyCleanupJournal(buf)
}

func parseLegacyCleanupJournal(buf []byte) (legacyCleanupJournal, error) {
	lines := strings.Split(strings.TrimSpace(string(buf)), "\n")
	if len(lines) == 0 || lines[0] == "" {
		return legacyCleanupJournal{}, fmt.Errorf("empty legacy cleanup journal")
	}
	journal := legacyCleanupJournal{phase: lines[0]}
	if journal.phase == legacyFinalizePhase {
		if len(lines) != 1 {
			return legacyCleanupJournal{}, fmt.Errorf("finalize journal contains snapshot entries")
		}
		return journal, nil
	}
	if journal.phase != legacyCleanupPhase {
		return legacyCleanupJournal{}, fmt.Errorf("unknown legacy cleanup phase %q", journal.phase)
	}
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 3)
		if len(parts) != 3 || !isLegacySnapshotPath(parts[1]) {
			return legacyCleanupJournal{}, fmt.Errorf("invalid legacy cleanup journal entry %q", line)
		}
		switch parts[0] {
		case legacyEntryPending, legacyEntryDelete, legacyEntryRestore:
		default:
			return legacyCleanupJournal{}, fmt.Errorf("invalid legacy snapshot state %q", parts[0])
		}
		if len(parts[2]) != sha256.Size*2 {
			return legacyCleanupJournal{}, fmt.Errorf("invalid legacy snapshot hash for %s", parts[1])
		}
		if _, err := hex.DecodeString(parts[2]); err != nil {
			return legacyCleanupJournal{}, fmt.Errorf("invalid legacy snapshot hash for %s: %w", parts[1], err)
		}
		journal.entries = append(journal.entries, legacySnapshotEntry{state: parts[0], path: parts[1], hash: parts[2]})
	}
	return journal, nil
}

func legacySnapshotQuarantinePath(path string) string {
	return filepath.Join(
		dnsmasq.MerlinJffsConfDir,
		"."+filepath.Base(path)+".ctrld-legacy-quarantine",
	)
}

func removeLegacyJournalEntry(journal *legacyCleanupJournal, index int) error {
	journal.entries = append(journal.entries[:index], journal.entries[index+1:]...)
	return writeLegacyCleanupJournal(*journal)
}

func cleanupLegacySnapshots(journal *legacyCleanupJournal) error {
	switch journal.phase {
	case legacyFinalizePhase:
		return nil
	case legacyCleanupPhase:
	default:
		return fmt.Errorf("unknown Merlin legacy cleanup phase %q", journal.phase)
	}

	for len(journal.entries) > 0 {
		entry := journal.entries[0]
		var err error
		switch entry.state {
		case legacyEntryPending:
			err = cleanupPendingLegacySnapshot(journal, 0)
		case legacyEntryDelete:
			err = finalizeLegacySnapshotDelete(journal, 0)
		case legacyEntryRestore:
			err = restoreLegacySnapshot(journal, 0)
		default:
			err = fmt.Errorf("unknown legacy snapshot state %q", entry.state)
		}
		if err != nil {
			return err
		}
	}

	journal.phase = legacyFinalizePhase
	if err := writeLegacyCleanupJournal(*journal); err != nil {
		return fmt.Errorf("advance Merlin legacy cleanup state: %w", err)
	}
	return nil
}

// cleanupPendingLegacySnapshot uses the private hard-link captured before
// journal publication as the durable identity proof for the original legacy
// snapshot. Public-path hashes alone are never treated as ownership. A rename
// race is detected by comparing the quarantined inode with that anchor; any
// ambiguous or unproven quarantined data is restored rather than deleted.
func cleanupPendingLegacySnapshot(journal *legacyCleanupJournal, index int) error {
	entry := journal.entries[index]
	qpath := legacySnapshotQuarantinePath(entry.path)
	anchor := legacySnapshotAnchorPath(entry.path)

	qExists, err := pathExists(qpath)
	if err != nil {
		return err
	}
	anchorExists, err := pathExists(anchor)
	if err != nil {
		return err
	}

	if qExists {
		if !anchorExists {
			// A prior attempt already moved data out of the public pathname but
			// the private identity proof is gone. Preservation wins: restore the
			// quarantined data rather than orphaning it.
			journal.entries[index].state = legacyEntryRestore
			if err := writeLegacyCleanupJournal(*journal); err != nil {
				return fmt.Errorf("journal anchorless legacy snapshot restoration: %w", err)
			}
			return restoreLegacySnapshot(journal, index)
		}
		owned, err := snapshotFileStillOwned(qpath, anchor, entry.hash)
		if err != nil {
			return err
		}
		if owned {
			journal.entries[index].state = legacyEntryDelete
			if err := writeLegacyCleanupJournal(*journal); err != nil {
				return fmt.Errorf("journal quarantined legacy snapshot deletion: %w", err)
			}
			return finalizeLegacySnapshotDelete(journal, index)
		}
		journal.entries[index].state = legacyEntryRestore
		if err := writeLegacyCleanupJournal(*journal); err != nil {
			return fmt.Errorf("journal ambiguous legacy snapshot restoration: %w", err)
		}
		return restoreLegacySnapshot(journal, index)
	}

	if !anchorExists {
		// No destructive operation has occurred and the durable identity proof is
		// gone. Never infer ownership from public bytes alone.
		return removeLegacyJournalEntry(journal, index)
	}

	targetExists, err := pathExists(entry.path)
	if err != nil {
		return err
	}
	if !targetExists {
		if err := removeLegacySnapshotAnchor(entry.path); err != nil {
			return err
		}
		return removeLegacyJournalEntry(journal, index)
	}

	owned, err := snapshotFileStillOwned(entry.path, anchor, entry.hash)
	if err != nil {
		return err
	}
	if !owned {
		// The public pathname was replaced or modified after journal creation.
		// Drop only ctrld's private anchor and leave the public file untouched.
		if err := removeLegacySnapshotAnchor(entry.path); err != nil {
			return err
		}
		return removeLegacyJournalEntry(journal, index)
	}

	if err := os.Rename(entry.path, qpath); err != nil {
		if os.IsNotExist(err) {
			return cleanupPendingLegacySnapshot(journal, index)
		}
		return fmt.Errorf("quarantine legacy snapshot %s: %w", entry.path, err)
	}
	if err := syncParentDir(dnsmasq.MerlinJffsConfDir); err != nil {
		return fmt.Errorf("sync legacy snapshot quarantine: %w", err)
	}

	owned, err = snapshotFileStillOwned(qpath, anchor, entry.hash)
	if err != nil {
		return err
	}
	if !owned {
		// A pathname replacement won the race between the pre-rename identity
		// check and rename(2). Restore the captured replacement; the original
		// ctrld inode remains proven by the private anchor only.
		journal.entries[index].state = legacyEntryRestore
		if err := writeLegacyCleanupJournal(*journal); err != nil {
			return fmt.Errorf("journal replaced legacy snapshot restoration: %w", err)
		}
		return restoreLegacySnapshot(journal, index)
	}

	journal.entries[index].state = legacyEntryDelete
	if err := writeLegacyCleanupJournal(*journal); err != nil {
		return fmt.Errorf("journal legacy snapshot deletion: %w", err)
	}
	return finalizeLegacySnapshotDelete(journal, index)
}

func finalizeLegacySnapshotDelete(journal *legacyCleanupJournal, index int) error {
	entry := journal.entries[index]
	qpath := legacySnapshotQuarantinePath(entry.path)
	anchor := legacySnapshotAnchorPath(entry.path)

	qExists, err := pathExists(qpath)
	if err != nil {
		return err
	}
	if qExists {
		owned, err := snapshotFileStillOwned(qpath, anchor, entry.hash)
		if err != nil {
			return err
		}
		if !owned {
			journal.entries[index].state = legacyEntryRestore
			if err := writeLegacyCleanupJournal(*journal); err != nil {
				return fmt.Errorf("journal modified legacy snapshot restoration: %w", err)
			}
			return restoreLegacySnapshot(journal, index)
		}
		if err := removeFileDurable(qpath); err != nil {
			return fmt.Errorf("remove quarantined legacy snapshot %s: %w", qpath, err)
		}
	}
	if err := removeLegacySnapshotAnchor(entry.path); err != nil {
		return err
	}
	return removeLegacyJournalEntry(journal, index)
}

func restoreLegacySnapshot(journal *legacyCleanupJournal, index int) error {
	entry := journal.entries[index]
	qpath := legacySnapshotQuarantinePath(entry.path)

	qExists, err := pathExists(qpath)
	if err != nil {
		return err
	}
	if !qExists {
		// Restoration/removal completed before the journal update, or no
		// destructive operation occurred. Never infer ownership from public state.
		if err := removeLegacySnapshotAnchor(entry.path); err != nil {
			return err
		}
		return removeLegacyJournalEntry(journal, index)
	}

	targetExists, err := pathExists(entry.path)
	if err != nil {
		return err
	}
	if targetExists {
		same, err := sameFilePaths(entry.path, qpath)
		if err != nil {
			return err
		}
		if !same {
			return fmt.Errorf(
				"cannot restore captured legacy snapshot because %s was recreated; preserved capture at %s",
				entry.path, qpath,
			)
		}
	} else {
		if err := os.Link(qpath, entry.path); err != nil {
			return fmt.Errorf("restore captured legacy snapshot %s: %w", entry.path, err)
		}
	}
	if err := syncParentDir(dnsmasq.MerlinJffsConfDir); err != nil {
		return fmt.Errorf("sync restored legacy snapshot: %w", err)
	}
	if err := removeFileDurable(qpath); err != nil {
		return fmt.Errorf("remove restored legacy snapshot quarantine: %w", err)
	}
	if err := removeLegacySnapshotAnchor(entry.path); err != nil {
		return err
	}
	return removeLegacyJournalEntry(journal, index)
}

func isLegacySnapshotPath(path string) bool {
	if path == dnsmasq.MerlinJffsConfPath {
		return true
	}
	if filepath.Dir(path) != dnsmasq.MerlinJffsConfDir {
		return false
	}
	base := filepath.Base(path)
	if !strings.HasPrefix(base, "dnsmasq-") || !strings.HasSuffix(base, ".conf") {
		return false
	}
	middle := strings.TrimSuffix(strings.TrimPrefix(base, "dnsmasq-"), ".conf")
	if middle == "" {
		return false
	}
	for _, r := range middle {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func readMerlinState(path string) (string, error) {
	buf, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(buf)), nil
}

// dnsmasqConfigUsesCtrld reports whether a generated dnsmasq config has the
// complete ctrld forwarding shape, not merely one matching server line.
func (m *Merlin) dnsmasqConfigUsesCtrld(path string) (bool, error) {
	buf, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	listener := m.cfg.FirstListener()
	if listener == nil {
		return false, fmt.Errorf("missing ctrld listener")
	}
	ip := listener.IP
	if ip == "" || ip == "0.0.0.0" || ip == "::" {
		ip = "127.0.0.1"
	}
	expectedServer := fmt.Sprintf("server=%s#%d", ip, listener.Port)

	var (
		serverCount int
		expectedSeen bool
		noResolv     bool
		addMAC       bool
		addSubnet    bool
		cacheOff     bool
	)
	for _, raw := range strings.Split(string(buf), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch {
		case strings.HasPrefix(line, "server="):
			serverCount++
			if line == expectedServer {
				expectedSeen = true
			}
		case strings.HasPrefix(line, "servers-file="),
			strings.HasPrefix(line, "resolv-file="),
			line == "dnssec",
			strings.HasPrefix(line, "trust-anchor="):
			return false, nil
		case line == "no-resolv":
			noResolv = true
		case line == "add-mac":
			addMAC = true
		case line == "add-subnet=32,128":
			addSubnet = true
		case line == "cache-size=0":
			cacheOff = true
		}
	}

	return serverCount == 1 && expectedSeen && noResolv && addMAC && addSubnet && cacheOff, nil
}

// setupMainDnsmasqFallback retains the old full-config mechanism only for the
// main dnsmasq when the supported postconf hook demonstrably did not apply.
// Ownership is represented by a private hard-link anchor to the exact inode
// ctrld published, plus a durable phase/hash journal.
func (m *Merlin) setupMainDnsmasqFallback() error {
	// Reconcile any interrupted ctrld fallback transaction first. Private ctrld
	// artifacts are handled without inferring ownership from public-path bytes.
	if err := cleanupOwnedMainSnapshot(); err != nil {
		return err
	}

	snapshotExists, err := pathExists(dnsmasq.MerlinJffsConfPath)
	if err != nil {
		return fmt.Errorf("stat Merlin fallback config: %w", err)
	}
	if snapshotExists {
		return fmt.Errorf("refusing to overwrite unowned Merlin custom config: %s", dnsmasq.MerlinJffsConfPath)
	}

	buf, err := os.ReadFile(dnsmasq.MerlinConfPath)
	if err != nil {
		return fmt.Errorf("failed to read dnsmasq config for fallback: %w", err)
	}
	built, err := m.buildMainDnsmasqFallback(buf)
	if err != nil {
		return err
	}
	if err := publishMainSnapshot(built, 0644); err != nil {
		return fmt.Errorf("publish ctrld dnsmasq fallback: %w", err)
	}
	return nil
}

// publishMainSnapshot publishes ctrld's fallback with identity-based ownership.
//
// The private anchor is a hard link to the exact inode prepared by ctrld. A
// pending journal is made durable before the public hard link is attempted, so
// cleanup can distinguish a failed no-clobber publication from a ctrld-owned
// target even after power loss.
func publishMainSnapshot(data []byte, mode os.FileMode) error {
	dir := dnsmasq.MerlinJffsConfDir
	base := filepath.Base(dnsmasq.MerlinJffsConfPath)
	tmp, err := os.CreateTemp(dir, "."+base+".ctrld-publish-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	// The anchor must be created before the journal/public link. It gives
	// cleanup an inode identity that hashes alone cannot provide.
	if err := os.Link(tmpPath, merlinSnapshotAnchorPath); err != nil {
		return fmt.Errorf("create fallback ownership anchor: %w", err)
	}
	if err := syncParentDir(dir); err != nil {
		return fmt.Errorf("sync fallback ownership anchor: %w", err)
	}

	state := mainSnapshotState{phase: snapshotPhasePending, hash: merlinSnapshotHash(data)}
	if err := writeMainSnapshotState(state); err != nil {
		return fmt.Errorf("journal pending fallback publication: %w", err)
	}

	// Hard-link publication is atomic and no-clobber: a concurrent user/addon
	// file at dnsmasq.conf causes EEXIST rather than replacement.
	if err := os.Link(tmpPath, dnsmasq.MerlinJffsConfPath); err != nil {
		return err
	}
	if err := syncParentDir(dir); err != nil {
		return fmt.Errorf("sync published fallback: %w", err)
	}

	state.phase = snapshotPhasePublished
	if err := writeMainSnapshotState(state); err != nil {
		// Pending state plus the anchor is sufficient for cleanup to prove that
		// the public inode is ours, so this remains safely retryable.
		return fmt.Errorf("journal published fallback: %w", err)
	}
	return nil
}

func (m *Merlin) buildMainDnsmasqFallback(buf []byte) ([]byte, error) {
	tmp, err := os.CreateTemp(dnsmasq.MerlinJffsConfDir, ".dnsmasq.conf.ctrld-build-*")
	if err != nil {
		return nil, fmt.Errorf("create ctrld dnsmasq fallback build file: %w", err)
	}
	path := tmp.Name()
	defer os.Remove(path)

	if err := tmp.Chmod(0644); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if _, err := tmp.Write(buf); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}

	script, err := dnsmasq.ConfTmpl(dnsmasq.MerlinPostConfTmpl, m.cfg)
	if err != nil {
		return nil, fmt.Errorf("render ctrld fallback postconf: %w", err)
	}
	// Apply only ctrld's managed logic. Executing the shared Merlin hook here
	// would also execute unrelated addon/user blocks a second time against a
	// temporary file.
	cmd := exec.Command("/bin/sh", "-c", script, "ctrld-fallback", path)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to apply ctrld fallback postconf: %s: %w", string(out), err)
	}
	built, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read ctrld dnsmasq fallback build: %w", err)
	}
	return built, nil
}

const (
	snapshotPhasePending    = "pending-v2"
	snapshotPhasePublished  = "published-v2"
	snapshotPhaseQuarantine = "quarantine-v2"
	snapshotPhaseDelete     = "delete-v2"
	snapshotPhaseRestore    = "restore-v2"
	snapshotPhaseRestored   = "restored-v2"
)

type mainSnapshotState struct {
	phase string
	hash  string
}

func merlinSnapshotHash(buf []byte) string {
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:])
}

func encodeMainSnapshotState(state mainSnapshotState) ([]byte, error) {
	if state.phase == "" {
		return nil, fmt.Errorf("empty Merlin snapshot phase")
	}
	switch state.phase {
	case snapshotPhasePending, snapshotPhasePublished, snapshotPhaseQuarantine,
		snapshotPhaseDelete, snapshotPhaseRestore, snapshotPhaseRestored:
	default:
		return nil, fmt.Errorf("unknown Merlin snapshot phase %q", state.phase)
	}
	if len(state.hash) != sha256.Size*2 {
		return nil, fmt.Errorf("invalid Merlin snapshot hash length")
	}
	if _, err := hex.DecodeString(state.hash); err != nil {
		return nil, fmt.Errorf("invalid Merlin snapshot hash: %w", err)
	}
	return []byte("snapshot-v2\nphase=" + state.phase + "\nsha256=" + state.hash + "\n"), nil
}

func parseMainSnapshotState(buf []byte) (mainSnapshotState, error) {
	lines := strings.Split(strings.TrimSpace(string(buf)), "\n")
	if len(lines) == 1 && strings.HasPrefix(lines[0], "sha256=") {
		return mainSnapshotState{}, fmt.Errorf("unsafe hash-only Merlin snapshot state")
	}
	if len(lines) != 3 || lines[0] != "snapshot-v2" ||
		!strings.HasPrefix(lines[1], "phase=") ||
		!strings.HasPrefix(lines[2], "sha256=") {
		return mainSnapshotState{}, fmt.Errorf("invalid Merlin snapshot state")
	}
	state := mainSnapshotState{
		phase: strings.TrimPrefix(lines[1], "phase="),
		hash:  strings.TrimPrefix(lines[2], "sha256="),
	}
	if _, err := encodeMainSnapshotState(state); err != nil {
		return mainSnapshotState{}, err
	}
	return state, nil
}

func writeMainSnapshotState(state mainSnapshotState) error {
	buf, err := encodeMainSnapshotState(state)
	if err != nil {
		return err
	}
	return atomicWriteFile(merlinSnapshotStatePath, buf, 0600)
}

func readMainSnapshotState() (mainSnapshotState, bool, error) {
	buf, err := os.ReadFile(merlinSnapshotStatePath)
	if os.IsNotExist(err) {
		return mainSnapshotState{}, false, nil
	}
	if err != nil {
		return mainSnapshotState{}, false, err
	}
	state, err := parseMainSnapshotState(buf)
	if err != nil {
		return mainSnapshotState{}, true, fmt.Errorf("%w: %s", err, merlinSnapshotStatePath)
	}
	return state, true, nil
}

func sameFilePaths(a, b string) (bool, error) {
	ai, err := os.Stat(a)
	if err != nil {
		return false, err
	}
	bi, err := os.Stat(b)
	if err != nil {
		return false, err
	}
	return os.SameFile(ai, bi), nil
}

func cleanupSnapshotPrivateState() error {
	if err := removeFileDurable(merlinSnapshotAnchorPath); err != nil {
		return fmt.Errorf("remove Merlin snapshot anchor: %w", err)
	}
	if err := removeFileDurable(merlinSnapshotStatePath); err != nil {
		return fmt.Errorf("remove Merlin snapshot state: %w", err)
	}
	return nil
}

// cleanupOwnedMainSnapshot reconciles ctrld's fallback transaction without ever
// deleting a pathname based on content alone. The anchor proves inode identity;
// the quarantine phases make every move resumable after power loss.
func cleanupOwnedMainSnapshot() error {
	state, marked, err := readMainSnapshotState()
	if err != nil {
		return err
	}
	if !marked {
		quarantineExists, err := pathExists(merlinSnapshotQuarantinePath)
		if err != nil {
			return err
		}
		if quarantineExists {
			return fmt.Errorf(
				"unjournaled Merlin fallback quarantine requires manual reconciliation: %s",
				merlinSnapshotQuarantinePath,
			)
		}
		// A private anchor without a journal can only precede public publication:
		// publishMainSnapshot makes the journal durable before linking dnsmasq.conf.
		if err := removeFileDurable(merlinSnapshotAnchorPath); err != nil {
			return fmt.Errorf("remove orphaned Merlin snapshot anchor: %w", err)
		}
		return nil
	}

	switch state.phase {
	case snapshotPhasePending:
		return cleanupPendingMainSnapshot(state)
	case snapshotPhasePublished:
		state.phase = snapshotPhaseQuarantine
		if err := writeMainSnapshotState(state); err != nil {
			return fmt.Errorf("journal Merlin fallback quarantine: %w", err)
		}
		return cleanupOwnedMainSnapshot()
	case snapshotPhaseQuarantine:
		return cleanupQuarantinedMainSnapshot(state)
	case snapshotPhaseDelete:
		return finalizeOwnedMainSnapshotDelete(state)
	case snapshotPhaseRestore:
		return restoreQuarantinedMainSnapshot(state)
	case snapshotPhaseRestored:
		return finalizeRestoredMainSnapshot()
	default:
		return fmt.Errorf("unknown Merlin snapshot phase %q", state.phase)
	}
}

func cleanupPendingMainSnapshot(state mainSnapshotState) error {
	anchorExists, err := pathExists(merlinSnapshotAnchorPath)
	if err != nil {
		return err
	}
	targetExists, err := pathExists(dnsmasq.MerlinJffsConfPath)
	if err != nil {
		return err
	}

	if !anchorExists {
		// Without the private inode proof, never touch a public target.
		if err := removeFileDurable(merlinSnapshotStatePath); err != nil {
			return err
		}
		if targetExists {
			return fmt.Errorf(
				"Merlin fallback publication lost its ownership anchor; left %s untouched",
				dnsmasq.MerlinJffsConfPath,
			)
		}
		return nil
	}
	if !targetExists {
		return cleanupSnapshotPrivateState()
	}

	same, err := sameFilePaths(dnsmasq.MerlinJffsConfPath, merlinSnapshotAnchorPath)
	if err != nil {
		return err
	}
	if !same {
		// Publication lost a no-clobber race. The public file belongs to someone
		// else regardless of whether its bytes happen to match ctrld's snapshot.
		return cleanupSnapshotPrivateState()
	}

	state.phase = snapshotPhasePublished
	if err := writeMainSnapshotState(state); err != nil {
		return fmt.Errorf("promote pending Merlin fallback ownership: %w", err)
	}
	return cleanupOwnedMainSnapshot()
}

func cleanupQuarantinedMainSnapshot(state mainSnapshotState) error {
	quarantineExists, err := pathExists(merlinSnapshotQuarantinePath)
	if err != nil {
		return err
	}
	if !quarantineExists {
		targetExists, err := pathExists(dnsmasq.MerlinJffsConfPath)
		if err != nil {
			return err
		}
		if !targetExists {
			// Nothing remains at the public pathname. Drop only ctrld-private proof.
			return cleanupSnapshotPrivateState()
		}
		if err := os.Rename(dnsmasq.MerlinJffsConfPath, merlinSnapshotQuarantinePath); err != nil {
			if os.IsNotExist(err) {
				return cleanupOwnedMainSnapshot()
			}
			return fmt.Errorf("quarantine Merlin fallback: %w", err)
		}
	}
	// Always sync before advancing the journal. On a retry, quarantine may
	// already exist because rename succeeded previously while its directory
	// fsync failed; observing the pathname is not proof that the rename is
	// durable across power loss.
	if err := syncParentDir(dnsmasq.MerlinJffsConfDir); err != nil {
		return fmt.Errorf("sync Merlin fallback quarantine: %w", err)
	}

	anchorExists, err := pathExists(merlinSnapshotAnchorPath)
	if err != nil {
		return err
	}
	if !anchorExists {
		state.phase = snapshotPhaseRestore
		if err := writeMainSnapshotState(state); err != nil {
			return err
		}
		return cleanupOwnedMainSnapshot()
	}

	owned, err := snapshotFileStillOwned(
		merlinSnapshotQuarantinePath,
		merlinSnapshotAnchorPath,
		state.hash,
	)
	if err != nil {
		return err
	}
	if owned {
		state.phase = snapshotPhaseDelete
	} else {
		// Different inode or changed bytes mean user/addon ownership may have
		// superseded ctrld. Preserve and restore the captured file.
		state.phase = snapshotPhaseRestore
	}
	if err := writeMainSnapshotState(state); err != nil {
		return fmt.Errorf("advance Merlin fallback quarantine state: %w", err)
	}
	return cleanupOwnedMainSnapshot()
}

func snapshotFileStillOwned(path, anchor, expectedHash string) (bool, error) {
	pathExistsNow, err := pathExists(path)
	if err != nil {
		return false, err
	}
	if !pathExistsNow {
		return false, nil
	}
	anchorExists, err := pathExists(anchor)
	if err != nil {
		return false, err
	}
	if !anchorExists {
		return false, nil
	}
	same, err := sameFilePaths(path, anchor)
	if err != nil {
		return false, err
	}
	if !same {
		return false, nil
	}
	buf, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	return merlinSnapshotHash(buf) == expectedHash, nil
}

func finalizeOwnedMainSnapshotDelete(state mainSnapshotState) error {
	quarantineExists, err := pathExists(merlinSnapshotQuarantinePath)
	if err != nil {
		return err
	}
	if quarantineExists {
		// Revalidate immediately before finalization. A process may have kept a
		// writable descriptor open across the public->quarantine rename and
		// changed the inode after the earlier classification.
		owned, err := snapshotFileStillOwned(
			merlinSnapshotQuarantinePath,
			merlinSnapshotAnchorPath,
			state.hash,
		)
		if err != nil {
			return err
		}
		if !owned {
			state.phase = snapshotPhaseRestore
			if err := writeMainSnapshotState(state); err != nil {
				return fmt.Errorf("journal late-modified Merlin fallback restoration: %w", err)
			}
			return cleanupOwnedMainSnapshot()
		}
	}
	if err := removeFileDurable(merlinSnapshotQuarantinePath); err != nil {
		return fmt.Errorf("remove quarantined ctrld fallback: %w", err)
	}
	return cleanupSnapshotPrivateState()
}

func restoreQuarantinedMainSnapshot(state mainSnapshotState) error {
	quarantineExists, err := pathExists(merlinSnapshotQuarantinePath)
	if err != nil {
		return err
	}
	if !quarantineExists {
		return fmt.Errorf(
			"Merlin fallback marked for restoration but quarantine is missing: %s",
			merlinSnapshotQuarantinePath,
		)
	}

	targetExists, err := pathExists(dnsmasq.MerlinJffsConfPath)
	if err != nil {
		return err
	}
	if targetExists {
		same, err := sameFilePaths(dnsmasq.MerlinJffsConfPath, merlinSnapshotQuarantinePath)
		if err != nil {
			return err
		}
		if !same {
			return fmt.Errorf(
				"cannot restore captured Merlin fallback because %s was recreated; preserved capture at %s",
				dnsmasq.MerlinJffsConfPath, merlinSnapshotQuarantinePath,
			)
		}
	} else {
		// Restore with no-clobber hard-link semantics. If another actor wins the
		// pathname race, the quarantine remains durably journaled and untouched.
		if err := os.Link(merlinSnapshotQuarantinePath, dnsmasq.MerlinJffsConfPath); err != nil {
			return fmt.Errorf("restore quarantined Merlin fallback: %w", err)
		}
	}
	// Re-sync even when the public hard link already exists. It may be the
	// result of a previous attempt where link(2) succeeded but directory fsync
	// failed, so the pathname alone is not enough to publish restored-v2.
	if err := syncParentDir(dnsmasq.MerlinJffsConfDir); err != nil {
		return fmt.Errorf("sync restored Merlin fallback: %w", err)
	}

	state.phase = snapshotPhaseRestored
	if err := writeMainSnapshotState(state); err != nil {
		return fmt.Errorf("journal restored Merlin fallback: %w", err)
	}
	return cleanupOwnedMainSnapshot()
}

func finalizeRestoredMainSnapshot() error {
	// Restoration was durably recorded only after a public hard link existed.
	// Therefore a retry never needs to infer ownership from the current target.
	if err := removeFileDurable(merlinSnapshotQuarantinePath); err != nil {
		return fmt.Errorf("remove restored Merlin fallback quarantine: %w", err)
	}
	return cleanupSnapshotPrivateState()
}

// merlinHookUpdate is prepared entirely before any shared hook is modified.
// This lets us validate/read both Merlin hook paths before the first write.
type merlinHookUpdate struct {
	path          string
	data          []byte
	original      []byte
	existed       bool
	pathType      os.FileMode
	symlinkTarget string
}

// writeDnsmasqPostconf installs ctrld-owned blocks in Merlin's main and SDN
// hooks while preserving unrelated content. Both paths are preflighted before
// either is modified, avoiding a half-installed integration when the second
// shared hook is unreadable or otherwise invalid.
func (m *Merlin) writeDnsmasqPostconf() error {
	data, err := dnsmasq.ConfTmpl(dnsmasq.MerlinPostConfTmpl, m.cfg)
	if err != nil {
		return err
	}
	block := []byte(strings.Join([]string{
		dnsmasq.MerlinPostConfBeginMarker,
		strings.TrimSpace(data),
		dnsmasq.MerlinPostConfEndMarker,
	}, "\n"))

	return writeMerlinHookUpdates(
		[]string{dnsmasq.MerlinPostConfPath, dnsmasq.MerlinSdnPostConfPath},
		block,
	)
}

func writeMerlinHookUpdates(paths []string, block []byte) error {
	return writeMerlinHookUpdatesWith(paths, block, atomicWriteFile)
}

func writeMerlinHookUpdatesWith(
	paths []string,
	block []byte,
	writeFile func(string, []byte, os.FileMode) error,
) error {
	updates := make([]merlinHookUpdate, 0, len(paths))
	for _, path := range paths {
		update, err := prepareMerlinHookUpdate(path, block)
		if err != nil {
			return err
		}
		updates = append(updates, update)
	}

	written := make([]merlinHookUpdate, 0, len(updates))
	for _, update := range updates {
		if err := revalidateMerlinHookUpdate(update); err != nil {
			if rollbackErr := rollbackMerlinHookUpdates(written); rollbackErr != nil {
				return fmt.Errorf("revalidate Merlin hook %s: %w; rollback failed: %v", update.path, err, rollbackErr)
			}
			return fmt.Errorf("revalidate Merlin hook %s: %w", update.path, err)
		}
		if err := writeFile(update.path, update.data, 0750); err != nil {
			if rollbackErr := rollbackMerlinHookUpdates(written); rollbackErr != nil {
				return fmt.Errorf("write Merlin hook %s: %w; rollback failed: %v", update.path, err, rollbackErr)
			}
			return fmt.Errorf("write Merlin hook %s: %w", update.path, err)
		}
		written = append(written, update)
	}
	return nil
}

func rollbackMerlinHookUpdates(updates []merlinHookUpdate) error {
	for i := len(updates) - 1; i >= 0; i-- {
		update := updates[i]
		if err := revalidateMerlinHookRollback(update); err != nil {
			return fmt.Errorf("refusing to roll back %s: %w", update.path, err)
		}
		if update.existed {
			if err := atomicWriteFile(update.path, update.original, 0750); err != nil {
				return fmt.Errorf("restore %s: %w", update.path, err)
			}
			continue
		}
		if err := removeFileDurable(update.path); err != nil {
			return fmt.Errorf("remove newly created %s: %w", update.path, err)
		}
	}
	return nil
}

func revalidateMerlinHookRollback(update merlinHookUpdate) error {
	info, err := os.Lstat(update.path)
	if err != nil {
		return err
	}
	if update.existed && info.Mode().Type() != update.pathType {
		return fmt.Errorf("shared hook type changed after ctrld write")
	}
	if update.existed && update.pathType&os.ModeSymlink != 0 {
		target, err := os.Readlink(update.path)
		if err != nil {
			return err
		}
		if target != update.symlinkTarget {
			return fmt.Errorf("shared hook symlink target changed after ctrld write")
		}
	}
	current, err := os.ReadFile(update.path)
	if err != nil {
		return err
	}
	if !bytes.Equal(current, update.data) {
		return fmt.Errorf("shared hook content changed after ctrld write")
	}
	return nil
}

func prepareMerlinHookUpdate(path string, block []byte) (merlinHookUpdate, error) {
	return prepareMerlinHookReplacement(path, func(buf []byte) []byte {
		return merlinUpsertPostConf(buf, block)
	})
}

func prepareMerlinHookCleanup(path string) (*merlinHookUpdate, error) {
	_, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	update, err := prepareMerlinHookReplacement(path, merlinParsePostConf)
	if err != nil {
		return nil, err
	}
	return &update, nil
}

func prepareMerlinHookReplacement(path string, transform func([]byte) []byte) (merlinHookUpdate, error) {
	info, statErr := os.Lstat(path)
	pathMissing := os.IsNotExist(statErr)
	if statErr != nil && !pathMissing {
		return merlinHookUpdate{}, statErr
	}

	buf, err := os.ReadFile(path)
	if err != nil {
		if !pathMissing || !os.IsNotExist(err) {
			return merlinHookUpdate{}, err
		}
		buf = nil
	}

	update := merlinHookUpdate{
		path:     path,
		data:     transform(buf),
		original: append([]byte(nil), buf...),
		existed:  !pathMissing,
	}
	if !pathMissing {
		update.pathType = info.Mode().Type()
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return merlinHookUpdate{}, err
			}
			update.symlinkTarget = target
		}
	}
	return update, nil
}

func revalidateMerlinHookUpdate(update merlinHookUpdate) error {
	info, err := os.Lstat(update.path)
	if !update.existed {
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		return fmt.Errorf("shared hook appeared after preflight")
	}
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("shared hook disappeared after preflight")
		}
		return err
	}
	if info.Mode().Type() != update.pathType {
		return fmt.Errorf("shared hook type changed after preflight")
	}
	if update.pathType&os.ModeSymlink != 0 {
		target, err := os.Readlink(update.path)
		if err != nil {
			return err
		}
		if target != update.symlinkTarget {
			return fmt.Errorf("shared hook symlink target changed after preflight")
		}
	}
	current, err := os.ReadFile(update.path)
	if err != nil {
		return err
	}
	if !bytes.Equal(current, update.original) {
		return fmt.Errorf("shared hook content changed after preflight")
	}
	return nil
}

func cleanupDnsmasqPostconf(path string) error {
	update, err := prepareMerlinHookCleanup(path)
	if err != nil || update == nil {
		return err
	}
	if bytes.Equal(update.original, update.data) {
		return nil
	}
	if err := revalidateMerlinHookUpdate(*update); err != nil {
		return fmt.Errorf("revalidate Merlin hook cleanup %s: %w", path, err)
	}
	// Never delete a shared Merlin hook outright. Cleanup removes only ctrld's
	// owned bytes and preserves the path, content and mode belonging to others.
	return atomicWriteFile(path, update.data, 0750)
}

// restartDNSMasq restarts the dnsmasq service by executing the appropriate system command using "service".
// Returns an error if the command fails or if there is an issue processing the command output.
func restartDNSMasq() error {
	if out, err := exec.Command("service", "restart_dnsmasq").CombinedOutput(); err != nil {
		return fmt.Errorf("restart_dnsmasq: %s, %w", string(out), err)
	}
	return nil
}

// merlinExactLineBounds finds marker only when it occupies a complete line.
// The returned end excludes the line ending so callers can decide whether to
// preserve or consume that separator.
func merlinExactLineBounds(buf, marker []byte, from int) (start, end int, ok bool) {
	if from < 0 {
		from = 0
	}
	for pos := from; pos <= len(buf); {
		lineStart := pos
		relNL := bytes.IndexByte(buf[pos:], '\n')
		lineEnd := len(buf)
		next := len(buf) + 1
		if relNL >= 0 {
			lineEnd = pos + relNL
			next = lineEnd + 1
		}

		contentEnd := lineEnd
		if contentEnd > lineStart && buf[contentEnd-1] == '\r' {
			contentEnd--
		}
		if bytes.Equal(buf[lineStart:contentEnd], marker) {
			return lineStart, lineEnd, true
		}

		if relNL < 0 {
			break
		}
		pos = next
	}
	return 0, 0, false
}

// merlinLastExactLineBefore returns the last complete marker line starting
// before limit.
func merlinLastExactLineBefore(buf, marker []byte, limit int) (start, end int, ok bool) {
	from := 0
	for {
		s, e, found := merlinExactLineBounds(buf, marker, from)
		if !found || s >= limit {
			break
		}
		start, end, ok = s, e, true
		if e >= len(buf) {
			break
		}
		from = e + 1
	}
	return start, end, ok
}

type merlinPostConfBlockKind uint8

const (
	merlinPostConfBlockNone merlinPostConfBlockKind = iota
	merlinPostConfBlockCurrent
	merlinPostConfBlockLegacy
)

// merlinPostConfBlock returns the ctrld-owned block bounds and format.
// It understands both the current BEGIN/END format and the legacy <= 1.5.7
// GENERATED/EOF format. Markers must occupy complete lines so shell variables,
// comments or unrelated strings containing the marker text are never claimed.
func merlinPostConfBlock(buf []byte) (start, end int, kind merlinPostConfBlockKind, ok bool) {
	begin := []byte(dnsmasq.MerlinPostConfBeginMarker)
	endMarker := []byte(dnsmasq.MerlinPostConfEndMarker)
	if blockStart, beginEnd, found := merlinExactLineBounds(buf, begin, 0); found {
		from := beginEnd
		if from < len(buf) && buf[from] == '\n' {
			from++
		}
		if _, blockEnd, foundEnd := merlinExactLineBounds(buf, endMarker, from); foundEnd {
			return blockStart, blockEnd, merlinPostConfBlockCurrent, true
		}
	}

	legacyEnd := []byte(dnsmasq.MerlinPostConfMarker)
	if legacyEndStart, legacyEndEnd, found := merlinExactLineBounds(buf, legacyEnd, 0); found {
		legacyBegin := []byte(dnsmasq.CtrldMarker)
		if legacyBeginStart, _, foundBegin := merlinLastExactLineBefore(buf, legacyBegin, legacyEndStart); foundBegin {
			return legacyBeginStart, legacyEndEnd, merlinPostConfBlockLegacy, true
		}
	}

	return 0, 0, merlinPostConfBlockNone, false
}

func merlinConsumeLineEnding(buf []byte, pos int) int {
	if pos >= len(buf) {
		return pos
	}
	if buf[pos] == '\r' {
		pos++
		if pos < len(buf) && buf[pos] == '\n' {
			pos++
		}
		return pos
	}
	if buf[pos] == '\n' {
		return pos + 1
	}
	return pos
}

func merlinBlockHasSyntheticShebang(buf []byte, start, end int) bool {
	if start < 0 || end < start || end > len(buf) {
		return false
	}
	_, _, ok := merlinExactLineBounds(
		buf[start:end],
		[]byte(dnsmasq.MerlinSyntheticShebangMarker),
		0,
	)
	return ok
}

func merlinBlockWithSyntheticShebang(block []byte) []byte {
	prefix := []byte(dnsmasq.MerlinPostConfBeginMarker + "\n")
	if !bytes.HasPrefix(block, prefix) {
		return block
	}
	out := make([]byte, 0, len(block)+len(dnsmasq.MerlinSyntheticShebangMarker)+1)
	out = append(out, prefix...)
	out = append(out, dnsmasq.MerlinSyntheticShebangMarker...)
	out = append(out, '\n')
	out = append(out, block[len(prefix):]...)
	return out
}

// merlinParsePostConf removes only ctrld-owned postconf content while preserving
// unrelated hook logic before and after it. If ctrld had to synthesize the
// leading shebang for a pre-existing hook without one, that shebang is marked
// inside ctrld's block and removed together with the block.
func merlinParsePostConf(buf []byte) []byte {
	if len(buf) == 0 {
		return nil
	}
	start, end, kind, ok := merlinPostConfBlock(buf)
	if !ok {
		return buf
	}

	syntheticShebang := kind == merlinPostConfBlockCurrent &&
		merlinBlockHasSyntheticShebang(buf, start, end)

	// Current blocks own the line ending following END. ctrld <= 1.5.7 wrote
	// its legacy wrapper with strings.Join(..., "\n"), producing three line
	// endings between the EOF marker and the previously existing hook.
	separatorCount := 1
	if kind == merlinPostConfBlockLegacy {
		separatorCount = 3
	}
	after := end
	for i := 0; i < separatorCount; i++ {
		next := merlinConsumeLineEnding(buf, after)
		if next == after {
			break
		}
		after = next
	}

	if syntheticShebang {
		const shebang = "#!/bin/sh\n"
		if start == len(shebang) && bytes.Equal(buf[:start], []byte(shebang)) {
			start = 0
		}
	}

	out := make([]byte, 0, len(buf)-(after-start))
	out = append(out, buf[:start]...)
	out = append(out, buf[after:]...)
	return out
}

// merlinUpsertPostConf replaces an existing ctrld block in place. New hooks,
// and existing hooks that do not already start with a usable shebang, receive a
// ctrld-owned synthetic shebang. The ownership marker lives inside the managed
// block so cleanup can remove that wrapper and restore the original bytes.
func merlinUpsertPostConf(buf, block []byte) []byte {
	if start, end, kind, ok := merlinPostConfBlock(buf); ok {
		if kind == merlinPostConfBlockCurrent {
			if merlinBlockHasSyntheticShebang(buf, start, end) {
				block = merlinBlockWithSyntheticShebang(block)
			}
			out := make([]byte, 0, len(buf)-(end-start)+len(block))
			out = append(out, buf[:start]...)
			out = append(out, block...)
			out = append(out, buf[end:]...)
			return out
		}

		// Legacy ctrld <= 1.5.7 wrote three separators after its EOF marker.
		after := end
		for i := 0; i < 3; i++ {
			next := merlinConsumeLineEnding(buf, after)
			if next == after {
				break
			}
			after = next
		}

		if start == 0 {
			marked := merlinBlockWithSyntheticShebang(block)
			out := make([]byte, 0, len(marked)+len(buf[after:])+16)
			out = append(out, "#!/bin/sh\n"...)
			out = append(out, marked...)
			out = append(out, '\n')
			out = append(out, buf[after:]...)
			return out
		}

		out := make([]byte, 0, len(buf)-(after-start)+len(block)+1)
		out = append(out, buf[:start]...)
		out = append(out, block...)
		if after < len(buf) {
			out = append(out, '\n')
		}
		out = append(out, buf[after:]...)
		return out
	}

	// Preserve a valid existing shebang and inject directly after it.
	if bytes.HasPrefix(buf, []byte("#!")) {
		if nl := bytes.IndexByte(buf, '\n'); nl >= 0 {
			out := make([]byte, 0, len(buf)+len(block)+1)
			out = append(out, buf[:nl+1]...)
			out = append(out, block...)
			out = append(out, '\n')
			out = append(out, buf[nl+1:]...)
			return out
		}
	}

	// Missing/empty/non-shebang hooks are still safe to extend: the synthetic
	// wrapper is explicitly marked as ctrld-owned and cleanup removes it.
	marked := merlinBlockWithSyntheticShebang(block)
	out := make([]byte, 0, len(buf)+len(marked)+16)
	out = append(out, "#!/bin/sh\n"...)
	out = append(out, marked...)
	out = append(out, '\n')
	out = append(out, buf...)
	return out
}

// atomicWriteFile replaces path only after a complete sibling temporary file
// has been written, synced, closed and chmodded. This avoids truncating a shared
// Merlin hook if JFFS fills up or a short write occurs.
func atomicWriteFile(path string, data []byte, mode os.FileMode) (err error) {
	target := path
	if info, lstatErr := os.Lstat(path); lstatErr == nil && info.Mode()&os.ModeSymlink != 0 {
		target, err = filepath.EvalSymlinks(path)
		if err != nil {
			return err
		}
	} else if lstatErr != nil && !os.IsNotExist(lstatErr) {
		return lstatErr
	}

	writeMode := mode
	if info, statErr := os.Stat(target); statErr == nil {
		writeMode = info.Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
	} else if !os.IsNotExist(statErr) {
		return statErr
	}

	dir := filepath.Dir(target)
	base := filepath.Base(target)
	tmp, err := os.CreateTemp(dir, "."+base+".ctrld-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		if err != nil {
			_ = os.Remove(tmpName)
		}
	}()

	if err = tmp.Chmod(writeMode); err != nil {
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmpName, target); err != nil {
		return err
	}
	if err = syncParentDir(dir); err != nil {
		return err
	}
	return nil
}

func syncParentDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		if runtime.GOOS == "windows" {
			return nil
		}
		return err
	}
	return nil
}

func pathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func removeFileDurable(path string) error {
	err := os.Remove(path)
	if os.IsNotExist(err) {
		// The previous attempt may have unlinked the file successfully but
		// failed while syncing the directory. Re-sync even on ENOENT so a retry
		// can make that already-visible deletion durable before its journal is
		// advanced or removed.
		return syncParentDir(filepath.Dir(path))
	}
	if err != nil {
		return err
	}
	return syncParentDir(filepath.Dir(path))
}

// waitDirExists waits until the specified directory exists, polling its existence every second.
func waitDirExists(dir string) {
	for {
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			return
		}
		time.Sleep(time.Second)
	}
}
