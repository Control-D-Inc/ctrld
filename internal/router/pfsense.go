package router

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/kardianos/service"
)

const (
	rcPath        = "/usr/local/etc/rc.d"
	unboundRcPath = rcPath + "/unbound"
	dnsmasqRcPath = rcPath + "/dnsmasq"
)

func setupPfsense() error {
	// If Pfsense is in DNS Resolver mode, ensure no unbound processes running.
	_ = exec.Command("killall", "unbound").Run()

	// If Pfsense is in DNS Forwarder mode, ensure no dnsmasq processes running.
	_ = exec.Command("killall", "dnsmasq").Run()
	return nil
}

func cleanupPfsense(svc *service.Config) error {
	if err := os.Remove(filepath.Join(rcPath, svc.Name+".sh")); err != nil {
		return fmt.Errorf("os.Remove: %w", err)
	}
	_ = exec.Command(unboundRcPath, "onerestart").Run()
	_ = exec.Command(dnsmasqRcPath, "onerestart").Run()

	return nil
}

func postInstallPfsense(svc *service.Config) error {
	// pfsense need ".sh" extension for script to be run at boot.
	// See: https://docs.netgate.com/pfsense/en/latest/development/boot-commands.html#shell-script-option
	oldname := filepath.Join(rcPath, svc.Name)
	newname := filepath.Join(rcPath, svc.Name+".sh")
	_ = os.Remove(newname)
	if err := os.Symlink(oldname, newname); err != nil {
		return fmt.Errorf("os.Symlink: %w", err)
	}
	return nil
}

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
