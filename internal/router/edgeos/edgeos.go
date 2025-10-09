package edgeos

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/kardianos/service"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/router/dnsmasq"
)

const (
	Name                       = "edgeos"
	edgeOSDNSMasqConfigPath    = "/etc/dnsmasq.d/dnsmasq-zzz-ctrld.conf"
	usgDNSMasqConfigPath       = "/etc/dnsmasq.conf"
	usgDNSMasqBackupConfigPath = "/etc/dnsmasq.conf.bak"
	toggleContentFilteringLink = "https://community.ui.com/questions/UDM-Pro-disable-enable-DNS-filtering/e2cc4060-e56a-4139-b200-62d7f773ff8f"
	toggleDnsShieldLink        = "https://community.ui.com/questions/UniFi-OS-3-2-7-DNS-Shield-Missing/d3a85905-4ce0-4fe4-8bf0-6cb04f21371d"
)

var ErrContentFilteringEnabled = fmt.Errorf(`the "Content Filtering" feature" is enabled, which is conflicted with ctrld.\n
To disable it, folowing instruction here: %s`, toggleContentFilteringLink)

var ErrDnsShieldEnabled = fmt.Errorf(`the "DNS Shield" feature" is enabled, which is conflicted with ctrld.\n
To disable it, folowing screenshot here: %s`, toggleDnsShieldLink)

type EdgeOS struct {
	cfg   *ctrld.Config
	isUSG bool
}

// New returns a router.Router for configuring/setup/run ctrld on EdgeOS routers.
func New(cfg *ctrld.Config) *EdgeOS {
	e := &EdgeOS{cfg: cfg}
	e.isUSG = checkUSG()
	return e
}

func (e *EdgeOS) ConfigureService(config *service.Config) error {
	return nil
}

func (e *EdgeOS) Install(_ *service.Config) error {
	// If "Content Filtering" is enabled, UniFi OS will create firewall rules to intercept all DNS queries
	// from outside, and route those queries to separated interfaces (e.g: dnsfilter-2@if79) created by UniFi OS.
	// Thus, those queries will never reach ctrld listener. UniFi OS does not provide any mechanism to toggle this
	// feature via command line, so there's nothing ctrld can do to disable this feature. For now, reporting an
	// error and guiding users to disable the feature using UniFi OS web UI.
	if ContentFilteringEnabled() {
		return ErrContentFilteringEnabled
	}
	// If "DNS Shield" is enabled, UniFi OS will spawn dnscrypt-proxy process, and route all DNS queries to it. So
	// reporting an error and guiding users to disable the feature using UniFi OS web UI.
	if DnsShieldEnabled() {
		return ErrDnsShieldEnabled
	}
	return nil
}

func (e *EdgeOS) Uninstall(_ *service.Config) error {
	return nil
}

func (e *EdgeOS) PreRun() error {
	return nil
}

func (e *EdgeOS) Setup() error {
	if e.cfg.FirstListener().IsDirectDnsListener() {
		return nil
	}
	if e.isUSG {
		return e.setupUSG()
	}
	return e.setupUDM()
}

func (e *EdgeOS) Cleanup() error {
	if e.cfg.FirstListener().IsDirectDnsListener() {
		return nil
	}
	if e.isUSG {
		return e.cleanupUSG()
	}
	return e.cleanupUDM()
}

func (e *EdgeOS) setupUSG() error {
	// On USG, dnsmasq is configured to forward queries to external provider by default.
	// So instead of generating config in /etc/dnsmasq.d, we need to create a backup of
	// the config, then modify it to forward queries to ctrld listener.

	// Creating a backup.
	buf, err := os.ReadFile(usgDNSMasqConfigPath)
	if err != nil {
		return fmt.Errorf("setupUSG: reading current config: %w", err)
	}
	if err := os.WriteFile(usgDNSMasqBackupConfigPath, buf, 0600); err != nil {
		return fmt.Errorf("setupUSG: backup current config: %w", err)
	}

	// Removing all configured upstreams and cache config.
	var sb strings.Builder
	scanner := bufio.NewScanner(bytes.NewReader(buf))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "server=") {
			continue
		}
		if strings.HasPrefix(line, "all-servers") {
			continue
		}
		sb.WriteString(line)
	}

	data, err := dnsmasq.ConfTmplWithCacheDisabled(dnsmasq.ConfigContentTmpl, e.cfg, false)
	if err != nil {
		return err
	}
	sb.WriteString("\n")
	sb.WriteString(data)
	if err := os.WriteFile(usgDNSMasqConfigPath, []byte(sb.String()), 0644); err != nil {
		return fmt.Errorf("setupUSG: writing dnsmasq config: %w", err)
	}

	// Restart dnsmasq service.
	if err := restartDNSMasq(); err != nil {
		return fmt.Errorf("setupUSG: restartDNSMasq: %w", err)
	}
	return nil
}

func (e *EdgeOS) setupUDM() error {
	data, err := dnsmasq.ConfTmplWithCacheDisabled(dnsmasq.ConfigContentTmpl, e.cfg, false)
	if err != nil {
		return err
	}
	if err := os.WriteFile(edgeOSDNSMasqConfigPath, []byte(data), 0600); err != nil {
		return fmt.Errorf("setupUDM: generating dnsmasq config: %w", err)
	}
	// Restart dnsmasq service.
	if err := restartDNSMasq(); err != nil {
		return fmt.Errorf("setupUDM: restartDNSMasq: %w", err)
	}
	return nil
}

func (e *EdgeOS) cleanupUSG() error {
	if err := os.Rename(usgDNSMasqBackupConfigPath, usgDNSMasqConfigPath); err != nil {
		return fmt.Errorf("cleanupUSG: os.Rename: %w", err)
	}
	// Restart dnsmasq service.
	if err := restartDNSMasq(); err != nil {
		return fmt.Errorf("cleanupUSG: restartDNSMasq: %w", err)
	}
	return nil
}

func (e *EdgeOS) cleanupUDM() error {
	// Remove the custom dnsmasq config
	if err := os.Remove(edgeOSDNSMasqConfigPath); err != nil {
		return fmt.Errorf("cleanupUDM: os.Remove: %w", err)
	}
	// Restart dnsmasq service.
	if err := restartDNSMasq(); err != nil {
		return fmt.Errorf("cleanupUDM: restartDNSMasq: %w", err)
	}
	return nil
}

func ContentFilteringEnabled() bool {
	st, err := os.Stat("/run/dnsfilter/dnsfilter")
	return err == nil && !st.IsDir()
}

// DnsShieldEnabled reports whether DNS Shield is enabled.
// See: https://community.ui.com/releases/UniFi-OS-Dream-Machines-3-2-7/251dfc1e-f4dd-4264-a080-3be9d8b9e02b
func DnsShieldEnabled() bool {
	buf, err := os.ReadFile("/var/run/dnsmasq.conf.d/dns.conf")
	if err != nil {
		return false
	}
	return bytes.Contains(buf, []byte("server=127.0.0.1#5053"))
}

func LeaseFileDir() string {
	if checkUSG() {
		return ""
	}
	return "/run"
}

func checkUSG() bool {
	out, _ := os.ReadFile("/etc/version")
	return bytes.HasPrefix(out, []byte("UniFiSecurityGateway."))
}

func restartDNSMasq() error {
	if out, err := exec.Command("/etc/init.d/dnsmasq", "restart").CombinedOutput(); err != nil {
		return fmt.Errorf("edgeosRestartDNSMasq: %s, %w", string(out), err)
	}
	return nil
}
