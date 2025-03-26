package merlin

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
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

var nvramKvMap = map[string]string{
	"dnspriv_enable": "0", // Ensure Merlin native DoT disabled.
}

type Merlin struct {
	cfg *ctrld.Config
}

// New returns a router.Router for configuring/setup/run ctrld on Merlin routers.
func New(cfg *ctrld.Config) *Merlin {
	return &Merlin{cfg: cfg}
}

func (m *Merlin) ConfigureService(config *service.Config) error {
	return nil
}

func (m *Merlin) Install(_ *service.Config) error {
	return nil
}

func (m *Merlin) Uninstall(_ *service.Config) error {
	return nil
}

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

	// Copy current dnsmasq config to /jffs/configs/dnsmasq.conf,
	// Then we will run postconf script on this file.
	//
	// Normally, adding postconf script is enough. However, we see
	// reports on some Merlin devices that postconf scripts does not
	// work, but manipulating the config directly via /jffs/configs does.
	src, err := os.Open(dnsmasq.MerlinConfPath)
	if err != nil {
		return fmt.Errorf("failed to open dnsmasq config: %w", err)
	}
	defer src.Close()

	dst, err := os.Create(dnsmasq.MerlinJffsConfPath)
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", dnsmasq.MerlinJffsConfPath, err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("failed to copy current dnsmasq config: %w", err)
	}
	if err := dst.Close(); err != nil {
		return fmt.Errorf("failed to save %s: %w", dnsmasq.MerlinJffsConfPath, err)
	}

	// Run postconf script on /jffs/configs/dnsmasq.conf directly.
	cmd := exec.Command("/bin/sh", dnsmasq.MerlinPostConfPath, dnsmasq.MerlinJffsConfPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to run post conf: %s: %w", string(out), err)
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
	// Remove /jffs/configs/dnsmasq.conf file.
	if err := os.Remove(dnsmasq.MerlinJffsConfPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	// Restart dnsmasq service.
	if err := restartDNSMasq(); err != nil {
		return err
	}
	return nil
}

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

func restartDNSMasq() error {
	if out, err := exec.Command("service", "restart_dnsmasq").CombinedOutput(); err != nil {
		return fmt.Errorf("restart_dnsmasq: %s, %w", string(out), err)
	}
	return nil
}

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

func waitDirExists(dir string) {
	for {
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			return
		}
		time.Sleep(time.Second)
	}
}
