package router

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/template"
	"time"

	"github.com/kardianos/service"
)

// This is a copy of https://github.com/kardianos/service/blob/v1.2.1/service_sysv_linux.go,
// with modification for supporting ubios v1 init system.

type ubiosSvc struct {
	i        service.Interface
	platform string
	*service.Config
}

func newUbiosService(i service.Interface, platform string, c *service.Config) (service.Service, error) {
	s := &ubiosSvc{
		i:        i,
		platform: platform,
		Config:   c,
	}
	return s, nil
}

func (s *ubiosSvc) String() string {
	if len(s.DisplayName) > 0 {
		return s.DisplayName
	}
	return s.Name
}

func (s *ubiosSvc) Platform() string {
	return s.platform
}

func (s *ubiosSvc) configPath() string {
	return "/etc/init.d/" + s.Config.Name
}

func (s *ubiosSvc) execPath() (string, error) {
	if len(s.Executable) != 0 {
		return filepath.Abs(s.Executable)
	}
	return os.Executable()
}

func (s *ubiosSvc) template() *template.Template {
	return template.Must(template.New("").Funcs(tf).Parse(ubiosSvcScript))
}

func (s *ubiosSvc) Install() error {
	confPath := s.configPath()
	if _, err := os.Stat(confPath); err == nil {
		return fmt.Errorf("init already exists: %s", confPath)
	}

	f, err := os.Create(confPath)
	if err != nil {
		return fmt.Errorf("failed to create config path: %w", err)
	}
	defer f.Close()

	path, err := s.execPath()
	if err != nil {
		return fmt.Errorf("failed to get exec path: %w", err)
	}

	var to = &struct {
		*service.Config
		Path            string
		DnsMasqConfPath string
	}{
		s.Config,
		path,
		ubiosDNSMasqConfigPath,
	}

	if err := s.template().Execute(f, to); err != nil {
		return fmt.Errorf("failed to create init script: %w", err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to save init script: %w", err)
	}

	if err = os.Chmod(confPath, 0755); err != nil {
		return fmt.Errorf("failed to set init script executable: %w", err)
	}

	// Enable on boot
	script, err := os.CreateTemp("", "ctrld_boot.service")
	if err != nil {
		return fmt.Errorf("failed to create boot service tmp file: %w", err)
	}
	defer script.Close()

	svcConfig := *to.Config
	svcConfig.Arguments = os.Args[1:]
	to.Config = &svcConfig
	if err := template.Must(template.New("").Funcs(tf).Parse(ubiosBootSystemdService)).Execute(script, &to); err != nil {
		return fmt.Errorf("failed to create boot service file: %w", err)
	}
	if err := script.Close(); err != nil {
		return fmt.Errorf("failed to save boot service file: %w", err)
	}

	// Copy the boot script to container and start.
	cmd := exec.Command("podman", "cp", "--pause=false", script.Name(), "unifi-os:/lib/systemd/system/ctrld-boot.service")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to copy boot script, out: %s, err: %v", string(out), err)
	}
	cmd = exec.Command("podman", "exec", "unifi-os", "systemctl", "enable", "--now", "ctrld-boot.service")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to start ctrld boot script, out: %s, err: %v", string(out), err)
	}
	return nil
}

func (s *ubiosSvc) Uninstall() error {
	if err := os.Remove(s.configPath()); err != nil {
		return err
	}
	return nil
}

func (s *ubiosSvc) Logger(errs chan<- error) (service.Logger, error) {
	if service.Interactive() {
		return service.ConsoleLogger, nil
	}
	return s.SystemLogger(errs)
}

func (s *ubiosSvc) SystemLogger(errs chan<- error) (service.Logger, error) {
	return newSysLogger(s.Name, errs)
}

func (s *ubiosSvc) Run() (err error) {
	err = s.i.Start(s)
	if err != nil {
		return err
	}

	if interactice, _ := isInteractive(); !interactice {
		signal.Ignore(syscall.SIGHUP)
		signal.Ignore(sigCHLD)
	}

	var sigChan = make(chan os.Signal, 3)
	signal.Notify(sigChan, syscall.SIGTERM, os.Interrupt)
	<-sigChan

	return s.i.Stop(s)
}

func (s *ubiosSvc) Status() (service.Status, error) {
	if _, err := os.Stat(s.configPath()); os.IsNotExist(err) {
		return service.StatusUnknown, service.ErrNotInstalled
	}
	out, err := exec.Command(s.configPath(), "status").CombinedOutput()
	if err != nil {
		return service.StatusUnknown, err
	}
	switch string(bytes.TrimSpace(out)) {
	case "Running":
		return service.StatusRunning, nil
	default:
		return service.StatusStopped, nil
	}
}

func (s *ubiosSvc) Start() error {
	return exec.Command(s.configPath(), "start").Run()
}

func (s *ubiosSvc) Stop() error {
	return exec.Command(s.configPath(), "stop").Run()
}

func (s *ubiosSvc) Restart() error {
	err := s.Stop()
	if err != nil {
		return err
	}
	time.Sleep(50 * time.Millisecond)
	return s.Start()
}

const ubiosBootSystemdService = `[Unit]
Description=Run ctrld On Startup UDM
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=500
StartLimitBurst=5

[Service]
Restart=on-failure
RestartSec=5s
ExecStart=/sbin/ssh-proxy '[ -f "{{.DnsMasqConfPath}}" ] || {{.Path}}{{range .Arguments}} {{.|cmd}}{{end}}'
RemainAfterExit=true
[Install]
WantedBy=multi-user.target
`

const ubiosSvcScript = `#!/bin/sh
# For RedHat and cousins:
# chkconfig: - 99 01
# description: {{.Description}}
# processname: {{.Path}}

### BEGIN INIT INFO
# Provides:          {{.Path}}
# Required-Start:
# Required-Stop:
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: {{.DisplayName}}
# Description:       {{.Description}}
### END INIT INFO

cmd="{{.Path}}{{range .Arguments}} {{.|cmd}}{{end}}"

name=$(basename $(readlink -f $0))
pid_file="/var/run/$name.pid"
stdout_log="/var/log/$name.log"
stderr_log="/var/log/$name.err"

[ -e /etc/sysconfig/$name ] && . /etc/sysconfig/$name

get_pid() {
    cat "$pid_file"
}

is_running() {
    [ -f "$pid_file" ] && cat /proc/$(get_pid)/stat > /dev/null 2>&1
}

case "$1" in
    start)
        if is_running; then
            echo "Already started"
        else
            echo "Starting $name"
            {{if .WorkingDirectory}}cd '{{.WorkingDirectory}}'{{end}}
            $cmd >> "$stdout_log" 2>> "$stderr_log" &
            echo $! > "$pid_file"
            if ! is_running; then
                echo "Unable to start, see $stdout_log and $stderr_log"
                exit 1
            fi
        fi
    ;;
    stop)
        if is_running; then
            echo -n "Stopping $name.."
            kill $(get_pid)
            for i in $(seq 1 10)
            do
                if ! is_running; then
                    break
                fi
                echo -n "."
                sleep 1
            done
            echo
            if is_running; then
                echo "Not stopped; may still be shutting down or shutdown may have failed"
                exit 1
            else
                echo "Stopped"
                if [ -f "$pid_file" ]; then
                    rm "$pid_file"
                fi
            fi
        else
            echo "Not running"
        fi
    ;;
    restart)
        $0 stop
        if is_running; then
            echo "Unable to stop, will not attempt to start"
            exit 1
        fi
        $0 start
    ;;
    status)
        if is_running; then
            echo "Running"
        else
            echo "Stopped"
            exit 1
        fi
    ;;
    *)
    echo "Usage: $0 {start|stop|restart|status}"
    exit 1
    ;;
esac
exit 0
`

var tf = map[string]interface{}{
	"cmd": func(s string) string {
		return `"` + strings.Replace(s, `"`, `\"`, -1) + `"`
	},
	"cmdEscape": func(s string) string {
		return strings.Replace(s, " ", `\x20`, -1)
	},
}
