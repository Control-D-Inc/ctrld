package pfsense

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/Control-D-Inc/ctrld"
	"github.com/kardianos/service"
)

const (
	Name = "pfsens"

	rcPath        = "/usr/local/etc/rc.d"
	unboundRcPath = rcPath + "/unbound"
	dnsmasqRcPath = rcPath + "/dnsmasq"
)

const pfsenseInitScript = `#!/bin/sh

# PROVIDE: {{.Name}}
# REQUIRE: SERVERS
# REQUIRE: unbound dnsmasq securelevel
# KEYWORD: shutdown

. /etc/rc.subr

name="{{.Name}}"
{{.Name}}_env="IS_DAEMON=1"
pidfile="/var/run/${name}.pid"
command="/usr/sbin/daemon"
daemon_args="-P ${pidfile} -r -t \"${name}: daemon\"{{if .WorkingDirectory}} -c {{.WorkingDirectory}}{{end}}"
command_args="${daemon_args} {{.Path}}{{range .Arguments}} {{.}}{{end}}"

run_rc_command "$1"
`

type Pfsense struct {
	cfg     *ctrld.Config
	svcName string
}

// New returns a router.Router for configuring/setup/run ctrld on Pfsense routers.
func New(cfg *ctrld.Config) *Pfsense {
	return &Pfsense{cfg: cfg}
}

func (p *Pfsense) ConfigureService(svc *service.Config) error {
	svc.Option["SysvScript"] = pfsenseInitScript
	p.svcName = svc.Name
	return nil
}

func (p *Pfsense) Install(config *service.Config) error {
	return nil
}

func (p *Pfsense) Uninstall(config *service.Config) error {
	return nil
}

func (p *Pfsense) PreRun() error {
	return nil
}

func (p *Pfsense) Configure() error {
	p.cfg.Listener["0"].IP = "127.0.0.1"
	p.cfg.Listener["0"].Port = 53
	return nil
}

func (p *Pfsense) Setup() error {
	// If Pfsense is in DNS Resolver mode, ensure no unbound processes running.
	_ = exec.Command("killall", "unbound").Run()

	// If Pfsense is in DNS Forwarder mode, ensure no dnsmasq processes running.
	_ = exec.Command("killall", "dnsmasq").Run()
	return nil
}

func (p *Pfsense) Cleanup() error {
	if err := os.Remove(filepath.Join(rcPath, p.svcName+".sh")); err != nil {
		return fmt.Errorf("os.Remove: %w", err)
	}
	_ = exec.Command(unboundRcPath, "onerestart").Run()
	_ = exec.Command(dnsmasqRcPath, "onerestart").Run()

	return nil
}
