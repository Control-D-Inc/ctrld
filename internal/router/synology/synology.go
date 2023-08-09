package synology

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/Control-D-Inc/ctrld/internal/router/dnsmasq"

	"github.com/Control-D-Inc/ctrld"
	"github.com/kardianos/service"
)

const (
	Name = "synology"

	synologyDNSMasqConfigPath = "/etc/dhcpd/dhcpd-zzz-ctrld.conf"
	synologyDhcpdInfoPath     = "/etc/dhcpd/dhcpd-zzz-ctrld.info"
)

type Synology struct {
	cfg *ctrld.Config
}

// New returns a router.Router for configuring/setup/run ctrld on Ubios routers.
func New(cfg *ctrld.Config) *Synology {
	return &Synology{cfg: cfg}
}

func (s *Synology) ConfigureService(svc *service.Config) error {
	svc.Option["UpstartScript"] = upstartScript
	return nil
}

func (s *Synology) Install(_ *service.Config) error {
	return nil
}

func (s *Synology) Uninstall(_ *service.Config) error {
	return nil
}

func (s *Synology) PreRun() error {
	return nil
}

func (s *Synology) Setup() error {
	if s.cfg.FirstListener().IsDirectDnsListener() {
		return nil
	}
	data, err := dnsmasq.ConfTmpl(dnsmasq.ConfigContentTmpl, s.cfg)
	if err != nil {
		return err
	}
	if err := os.WriteFile(synologyDNSMasqConfigPath, []byte(data), 0600); err != nil {
		return err
	}
	if err := os.WriteFile(synologyDhcpdInfoPath, []byte(`enable="yes"`), 0600); err != nil {
		return err
	}
	if err := restartDNSMasq(); err != nil {
		return err
	}
	return nil
}

func (s *Synology) Cleanup() error {
	if s.cfg.FirstListener().IsDirectDnsListener() {
		return nil
	}
	// Remove the custom config files.
	for _, f := range []string{synologyDNSMasqConfigPath, synologyDhcpdInfoPath} {
		if err := os.Remove(f); err != nil {
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
	if out, err := exec.Command("/etc/rc.network", "nat-restart-dhcp").CombinedOutput(); err != nil {
		return fmt.Errorf("synologyRestartDNSMasq: %s - %w", string(out), err)
	}
	return nil
}

// Copied from https://github.com/kardianos/service/blob/6fe2824ee8248e776b0f8be39aaeff45a45a4f6c/service_upstart_linux.go#L232
// With modification to wait for dhcpserver started before ctrld.

// The upstart script should stop with an INT or the Go runtime will terminate
// the program before the Stop handler can run.
const upstartScript = `# {{.Description}}

{{if .DisplayName}}description    "{{.DisplayName}}"{{end}}

{{if .HasKillStanza}}kill signal INT{{end}}
{{if .ChRoot}}chroot {{.ChRoot}}{{end}}
{{if .WorkingDirectory}}chdir {{.WorkingDirectory}}{{end}}
start on filesystem or runlevel [2345]
stop on runlevel [!2345]

start on started dhcpserver
normal exit 0 TERM HUP

{{if and .UserName .HasSetUIDStanza}}setuid {{.UserName}}{{end}}

respawn
respawn limit 10 5
umask 022

console none

pre-start script
    test -x {{.Path}} || { stop; exit 0; }
end script

# Start
script
	{{if .LogOutput}}
	stdout_log="/var/log/{{.Name}}.out"
	stderr_log="/var/log/{{.Name}}.err"
	{{end}}
	
	if [ -f "/etc/sysconfig/{{.Name}}" ]; then
		set -a
		source /etc/sysconfig/{{.Name}}
		set +a
	fi

	exec {{if and .UserName (not .HasSetUIDStanza)}}sudo -E -u {{.UserName}} {{end}}{{.Path}}{{range .Arguments}} {{.|cmd}}{{end}}{{if .LogOutput}} >> $stdout_log 2>> $stderr_log{{end}}
end script
`
