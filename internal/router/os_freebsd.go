package router

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"

	"github.com/kardianos/service"

	"github.com/Control-D-Inc/ctrld"
)

const (
	osName        = "freebsd"
	rcPath        = "/usr/local/etc/rc.d"
	rcConfPath    = "/etc/rc.conf.d/"
	unboundRcPath = rcPath + "/unbound"
	dnsmasqRcPath = rcPath + "/dnsmasq"
)

func newOsRouter(cfg *ctrld.Config, cdMode bool) Router {
	return &osRouter{cfg: cfg, cdMode: cdMode}
}

type osRouter struct {
	cfg     *ctrld.Config
	svcName string
	// cdMode indicates whether the router will configure ctrld in cd mode (aka --cd=<uid>).
	// When ctrld is running on freebsd-like routers, and there's process running on port 53
	// in cd mode, ctrld will attempt to kill the process and become direct listener.
	// See details implemenation in osRouter.PreRun method.
	cdMode bool
}

func (or *osRouter) ConfigureService(svc *service.Config) error {
	svc.Option["SysvScript"] = bsdInitScript
	or.svcName = svc.Name
	rcFile := filepath.Join(rcConfPath, or.svcName)
	var to = &struct {
		Name string
	}{
		or.svcName,
	}

	f, err := os.Create(rcFile)
	if err != nil {
		return fmt.Errorf("os.Create: %w", err)
	}
	defer f.Close()
	if err := template.Must(template.New("").Parse(rcConfTmpl)).Execute(f, to); err != nil {
		return err
	}
	return f.Close()
}

func (or *osRouter) Install(_ *service.Config) error {
	if isPfsense() {
		// pfsense need ".sh" extension for script to be run at boot.
		// See: https://docs.netgate.com/pfsense/en/latest/development/boot-commands.html#shell-script-option
		oldname := filepath.Join(rcPath, or.svcName)
		newname := filepath.Join(rcPath, or.svcName+".sh")
		_ = os.Remove(newname)
		if err := os.Symlink(oldname, newname); err != nil {
			return fmt.Errorf("os.Symlink: %w", err)
		}
	}
	return nil
}

func (or *osRouter) Uninstall(_ *service.Config) error {
	rcFiles := []string{filepath.Join(rcConfPath, or.svcName)}
	if isPfsense() {
		rcFiles = append(rcFiles, filepath.Join(rcPath, or.svcName+".sh"))
	}
	for _, filename := range rcFiles {
		if err := os.Remove(filename); err != nil {
			return fmt.Errorf("os.Remove: %w", err)
		}
	}

	return nil
}

func (or *osRouter) PreRun() error {
	if or.cdMode {
		addr := "0.0.0.0:53"
		udpLn, udpErr := net.ListenPacket("udp", addr)
		if udpLn != nil {
			udpLn.Close()
		}
		tcpLn, tcpErr := net.Listen("tcp", addr)
		if tcpLn != nil {
			tcpLn.Close()
		}
		// If we could not listen on :53 for any reason, try killing unbound/dnsmasq, become direct listener
		if udpErr != nil || tcpErr != nil {
			_ = exec.Command("killall", "unbound").Run()
			_ = exec.Command("killall", "dnsmasq").Run()
		}
	}
	return nil
}

func (or *osRouter) Setup() error {
	return nil
}

func (or *osRouter) Cleanup() error {
	if or.cdMode {
		_ = exec.Command(unboundRcPath, "onerestart").Run()
		_ = exec.Command(dnsmasqRcPath, "onerestart").Run()
	}
	return nil
}

func isPfsense() bool {
	b, err := os.ReadFile("/etc/platform")
	return err == nil && bytes.HasPrefix(b, []byte("pfSense"))
}

const bsdInitScript = `#!/bin/sh

# PROVIDE: {{.Name}}
# REQUIRE: SERVERS
# REQUIRE: unbound dnsmasq securelevel
# KEYWORD: shutdown

. /etc/rc.subr

name="{{.Name}}"
rcvar="${name}_enable"
{{.Name}}_env="IS_DAEMON=1"
pidfile="/var/run/${name}.pid"
child_pidfile="/var/run/${name}_child.pid"
command="/usr/sbin/daemon"
daemon_args="-P ${pidfile} -p ${child_pidfile} -t \"${name}: daemon\"{{if .WorkingDirectory}} -c {{.WorkingDirectory}}{{end}}"
command_args="${daemon_args} {{.Path}}{{range .Arguments}} {{.}}{{end}}"

stop_cmd="ctrld_stop"

ctrld_stop() {
  pid=$(cat ${pidfile})
  child_pid=$(cat ${child_pidfile})
  if [ -e "${child_pidfile}" ]; then
    kill -s TERM "${child_pid}"
    wait_for_pids "${child_pid}" "${pidfile}"
  fi
}

load_rc_config "${name}"
run_rc_command "$1"
`

var rcConfTmpl = `# {{.Name}}
{{.Name}}_enable="YES"
`
