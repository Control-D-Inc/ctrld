package openwrt

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/Control-D-Inc/ctrld/internal/router/dnsmasq"

	"github.com/kardianos/service"

	"github.com/Control-D-Inc/ctrld"
)

const (
	Name                     = "openwrt"
	openwrtDNSMasqConfigPath = "/tmp/dnsmasq.d/ctrld.conf"
)

var errUCIEntryNotFound = errors.New("uci: Entry not found")

type Openwrt struct {
	cfg *ctrld.Config
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
	data, err := dnsmasq.ConfTmpl(dnsmasq.ConfigContentTmpl, o.cfg)
	if err != nil {
		return err
	}
	if err := os.WriteFile(openwrtDNSMasqConfigPath, []byte(data), 0600); err != nil {
		return err
	}
	// Commit.
	if _, err := uci("commit"); err != nil {
		return err
	}
	// Restart dnsmasq service.
	if err := restartDNSMasq(); err != nil {
		return err
	}
	return nil
}

func (o *Openwrt) Cleanup() error {
	// Remove the custom dnsmasq config
	if err := os.Remove(openwrtDNSMasqConfigPath); err != nil {
		return err
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
