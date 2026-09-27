package merlin

import (
	"bytes"
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

// nvramKvMap is a map of NVRAM key-value pairs used to configure and manage Merlin-specific settings.
var nvramKvMap = map[string]string{
	"dnspriv_enable": "0", // Ensure Merlin native DoT disabled.
}

// dnsmasqConfig represents configuration paths for dnsmasq operations in Merlin firmware.
type dnsmasqConfig struct {
	confPath     string
	jffsConfPath string
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
	// Wait NTP ready.
	_ = m.Cleanup()
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
func (m *Merlin) Setup() error {
	if m.cfg.FirstListener().IsDirectDnsListener() {
		return nil
	}
	// Already setup.
	if val, _ := nvram.Run("get", nvram.CtrldSetupKey); val == "1" {
		return nil
	}

	if err := m.writeDnsmasqPostconf(); err != nil {
		return err
	}

	for _, cfg := range getDnsmasqConfigs() {
		if err := m.setupDnsmasq(cfg); err != nil {
			return fmt.Errorf("failed to setup dnsmasq: config: %s, error: %w", cfg.confPath, err)
		}
	}

	// Restart dnsmasq service.
	if err := restartDNSMasq(); err != nil {
		return err
	}

	if err := nvram.SetKV(nvramKvMap, nvram.CtrldSetupKey); err != nil {
		return err
	}

	return nil
}

// Cleanup restores the original dnsmasq and nvram configurations and restarts dnsmasq if necessary.
func (m *Merlin) Cleanup() error {
	if m.cfg.FirstListener().IsDirectDnsListener() {
		return nil
	}
	if val, _ := nvram.Run("get", nvram.CtrldSetupKey); val != "1" {
		return nil // was restored, nothing to do.
	}

	// Restore old configs.
	if err := nvram.Restore(nvramKvMap, nvram.CtrldSetupKey); err != nil {
		return err
	}

	if err := cleanupDnsmasqPostconf(dnsmasq.MerlinPostConfPath); err != nil {
		return err
	}

	for _, cfg := range getDnsmasqConfigs() {
		if err := m.cleanupDnsmasqJffs(cfg); err != nil {
			return fmt.Errorf("failed to cleanup jffs dnsmasq: config: %s, error: %w", cfg.confPath, err)
		}
	}
	// Restart dnsmasq service.
	if err := restartDNSMasq(); err != nil {
		return err
	}
	return nil
}

// setupDnsmasq sets up dnsmasq configuration by writing postconf, copying configuration, and running a postconf script.
func (m *Merlin) setupDnsmasq(cfg *dnsmasqConfig) error {
	src, err := os.Open(cfg.confPath)
	if os.IsNotExist(err) {
		return nil // nothing to do if conf file does not exist.
	}
	if err != nil {
		return fmt.Errorf("failed to open dnsmasq config: %w", err)
	}
	defer src.Close()

	// Copy current dnsmasq config to cfg.jffsConfPath,
	// Then we will run postconf script on this file.
	//
	// Normally, adding postconf script is enough. However, we see
	// reports on some Merlin devices that postconf scripts does not
	// work, but manipulating the config directly via /jffs/configs does.
	dst, err := os.Create(cfg.jffsConfPath)
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", cfg.jffsConfPath, err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("failed to copy current dnsmasq config: %w", err)
	}
	if err := dst.Close(); err != nil {
		return fmt.Errorf("failed to save %s: %w", cfg.jffsConfPath, err)
	}

	// Run postconf script on cfg.jffsConfPath directly.
	cmd := exec.Command("/bin/sh", dnsmasq.MerlinPostConfPath, cfg.jffsConfPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to run post conf: %s: %w", string(out), err)
	}
	return nil
}

// cleanupDnsmasqJffs removes the JFFS configuration file specified in the given dnsmasqConfig, if it exists.
func (m *Merlin) cleanupDnsmasqJffs(cfg *dnsmasqConfig) error {
	// Remove cfg.jffsConfPath file.
	if err := os.Remove(cfg.jffsConfPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

type merlinHookUpdate struct {
	path          string
	data          []byte
	original      []byte
	existed       bool
	pathType      os.FileMode
	symlinkTarget string
}

// writeDnsmasqPostconf manages only ctrld's marked block in the shared main
// dnsmasq.postconf hook. Merlin 3006 SDN support is intentionally handled in a
// separate change so this patch does not alter router lifecycle semantics.
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

	update, err := prepareMerlinHookUpdate(dnsmasq.MerlinPostConfPath, block)
	if err != nil {
		return err
	}
	if err := revalidateMerlinHookUpdate(update); err != nil {
		return fmt.Errorf("revalidate Merlin hook %s: %w", update.path, err)
	}
	if err := atomicWriteFile(update.path, update.data, 0750); err != nil {
		return fmt.Errorf("write Merlin hook %s: %w", update.path, err)
	}
	return nil
}

func prepareMerlinHookUpdate(path string, block []byte) (merlinHookUpdate, error) {
	return prepareMerlinHookReplacement(path, func(buf []byte) []byte {
		return merlinUpsertPostConf(buf, block)
	})
}

func prepareMerlinHookCleanup(path string) (*merlinHookUpdate, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_ = info

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

// getDnsmasqConfigs retrieves a list of dnsmasqConfig containing configuration and JFFS paths for dnsmasq operations.
func getDnsmasqConfigs() []*dnsmasqConfig {
	cfgs := []*dnsmasqConfig{
		{dnsmasq.MerlinConfPath, dnsmasq.MerlinJffsConfPath},
	}
	for _, path := range dnsmasq.AdditionalConfigFiles() {
		jffsConfPath := filepath.Join(dnsmasq.MerlinJffsConfDir, filepath.Base(path))
		cfgs = append(cfgs, &dnsmasqConfig{path, jffsConfPath})
	}

	return cfgs
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
		// Directory fsync is not supported by the Windows CI filesystem. Merlin
		// itself is Unix-only, where this is required for rename durability.
		if runtime.GOOS == "windows" {
			return nil
		}
		return err
	}
	return nil
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
