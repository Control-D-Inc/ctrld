package openwrt

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/kardianos/service"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/router/dnsmasq"
)

const (
	Name                           = "openwrt"
	openwrtDNSMasqConfigName       = "ctrld.conf"
	openwrtDNSMasqDefaultConfigDir = "/tmp/dnsmasq.d"
)

var openwrtDnsmasqDefaultConfigPath = filepath.Join(openwrtDNSMasqDefaultConfigDir, openwrtDNSMasqConfigName)

type Openwrt struct {
	cfg              *ctrld.Config
	dnsmasqCacheSize string
}

// New returns a router.Router for configuring/setup/run ctrld on Openwrt routers.
func New(cfg *ctrld.Config) *Openwrt {
	return &Openwrt{cfg: cfg}
}

func (o *Openwrt) ConfigureService(svc *service.Config) error {
	svc.Option["SysvScript"] = openWrtScript
	return nil
}

func (o *Openwrt) Install(config *service.Config) error {
	return exec.Command("/etc/init.d/ctrld", "enable").Run()
}

func (o *Openwrt) Uninstall(config *service.Config) error {
	return nil
}

func (o *Openwrt) PreRun() error {
	return nil
}

func (o *Openwrt) Setup() error {
	if o.cfg.FirstListener().IsDirectDnsListener() {
		return nil
	}

	// Save current dnsmasq config cache size if present.
	if cs, err := uci("get", "dhcp.@dnsmasq[0].cachesize"); err == nil {
		o.dnsmasqCacheSize = cs
		if _, err := uci("delete", "dhcp.@dnsmasq[0].cachesize"); err != nil {
			return err
		}
		// Commit.
		if _, err := uci("commit", "dhcp"); err != nil {
			return err
		}
	}

	data, err := dnsmasq.ConfTmpl(dnsmasq.ConfigContentTmpl, o.cfg)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dnsmasqConfPathFromUbus(), []byte(data), 0600); err != nil {
		return err
	}
	// Restart dnsmasq service.
	if err := restartDNSMasq(); err != nil {
		return err
	}
	return nil
}

func (o *Openwrt) Cleanup() error {
	if o.cfg.FirstListener().IsDirectDnsListener() {
		return nil
	}
	// Remove the custom dnsmasq config
	if err := os.Remove(dnsmasqConfPathFromUbus()); err != nil {
		return err
	}

	// Restore original value if present.
	if o.dnsmasqCacheSize != "" {
		if _, err := uci("set", fmt.Sprintf("dhcp.@dnsmasq[0].cachesize=%s", o.dnsmasqCacheSize)); err != nil {
			return err
		}
		// Commit.
		if _, err := uci("commit", "dhcp"); err != nil {
			return err
		}
	}

	// Restart dnsmasq service.
	if err := restartDNSMasq(); err != nil {
		return err
	}
	return nil
}

func restartDNSMasq() error {
	if out, err := exec.Command("/etc/init.d/dnsmasq", "restart").CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w", string(out), err)
	}
	return nil
}

var errUCIEntryNotFound = errors.New("uci: Entry not found")

func uci(args ...string) (string, error) {
	cmd := exec.Command("uci", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if strings.HasPrefix(stderr.String(), errUCIEntryNotFound.Error()) {
			return "", errUCIEntryNotFound
		}
		return "", fmt.Errorf("%s:%w", stderr.String(), err)
	}
	return strings.TrimSpace(stdout.String()), nil
}

// openwrtServiceList represents openwrt services config.
type openwrtServiceList struct {
	Dnsmasq dnsmasqConf `json:"dnsmasq"`
}

// dnsmasqConf represents dnsmasq config.
type dnsmasqConf struct {
	Instances map[string]confInstances `json:"instances"`
}

// confInstances represents an instance config of a service.
type confInstances struct {
	Mount map[string]string `json:"mount"`
}

// dnsmasqConfPath returns the dnsmasq config path.
//
// Since version 24.10, openwrt makes some changes to dnsmasq to support
// multiple instances of dnsmasq. This change causes breaking changes to
// software which depends on the default dnsmasq path.
//
// There are some discussion/PRs in openwrt repo to address this:
//
// - https://github.com/openwrt/openwrt/pull/16806
// - https://github.com/openwrt/openwrt/pull/16890
//
// In the meantime, workaround this problem by querying the actual config path
// by querying ubus service list.
func dnsmasqConfPath(r io.Reader) string {
	var svc openwrtServiceList
	if err := json.NewDecoder(r).Decode(&svc); err != nil {
		return openwrtDnsmasqDefaultConfigPath
	}
	for _, inst := range svc.Dnsmasq.Instances {
		for mount := range inst.Mount {
			dirName := filepath.Base(mount)
			parts := strings.Split(dirName, ".")
			if len(parts) < 2 {
				continue
			}
			if parts[0] == "dnsmasq" && parts[len(parts)-1] == "d" {
				return filepath.Join(mount, openwrtDNSMasqConfigName)
			}
		}
	}
	return openwrtDnsmasqDefaultConfigPath
}

// dnsmasqConfPathFromUbus get dnsmasq config path from ubus service list.
func dnsmasqConfPathFromUbus() string {
	output, err := exec.Command("ubus", "call", "service", "list").Output()
	if err != nil {
		return openwrtDnsmasqDefaultConfigPath
	}
	return dnsmasqConfPath(bytes.NewReader(output))
}
