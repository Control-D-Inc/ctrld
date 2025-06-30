package merlin

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode"

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

	buf, err := os.ReadFile(dnsmasq.MerlinPostConfPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	// Restore dnsmasq post conf file.
	if err := os.WriteFile(dnsmasq.MerlinPostConfPath, merlinParsePostConf(buf), 0750); err != nil {
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

// writeDnsmasqPostconf writes the requireddnsmasqConfigs post-configuration for dnsmasq to enable custom DNS settings with ctrld.
func (m *Merlin) writeDnsmasqPostconf() error {
	buf, err := os.ReadFile(dnsmasq.MerlinPostConfPath)
	// Already setup.
	if bytes.Contains(buf, []byte(dnsmasq.MerlinPostConfMarker)) {
		return nil
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	data, err := dnsmasq.ConfTmpl(dnsmasq.MerlinPostConfTmpl, m.cfg)
	if err != nil {
		return err
	}
	data = strings.Join([]string{
		data,
		"\n",
		dnsmasq.MerlinPostConfMarker,
		"\n",
		string(buf),
	}, "\n")
	// Write dnsmasq post conf file.
	return os.WriteFile(dnsmasq.MerlinPostConfPath, []byte(data), 0750)
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

// merlinParsePostConf parses the dnsmasq post configuration by removing content after the MerlinPostConfMarker, if present.
// If no marker is found, the original buffer is returned unmodified.
// Returns nil if the input buffer is empty.
func merlinParsePostConf(buf []byte) []byte {
	if len(buf) == 0 {
		return nil
	}
	parts := bytes.Split(buf, []byte(dnsmasq.MerlinPostConfMarker))
	if len(parts) != 1 {
		return bytes.TrimLeftFunc(parts[1], unicode.IsSpace)
	}
	return buf
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
