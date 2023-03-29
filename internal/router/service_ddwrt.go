package router

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"text/template"

	"github.com/kardianos/service"
)

type ddwrtSvc struct {
	i        service.Interface
	platform string
	*service.Config
	rcStartup string
}

func newddwrtService(i service.Interface, platform string, c *service.Config) (service.Service, error) {
	s := &ddwrtSvc{
		i:        i,
		platform: platform,
		Config:   c,
	}
	if err := os.MkdirAll("/jffs/etc/config", 0644); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *ddwrtSvc) String() string {
	if len(s.DisplayName) > 0 {
		return s.DisplayName
	}
	return s.Name
}

func (s *ddwrtSvc) Platform() string {
	return s.platform
}

func (s *ddwrtSvc) configPath() string {
	return fmt.Sprintf("/jffs/etc/config/%s.startup", s.Config.Name)
}

func (s *ddwrtSvc) template() *template.Template {
	return template.Must(template.New("").Parse(ddwrtSvcScript))
}

func (s *ddwrtSvc) Install() error {
	confPath := s.configPath()
	if _, err := os.Stat(confPath); err == nil {
		return fmt.Errorf("already installed: %s", confPath)
	}

	path, err := os.Executable()
	if err != nil {
		return err
	}

	if !strings.HasPrefix(path, "/jffs/") {
		return errors.New("could not install service outside /jffs")
	}

	var to = &struct {
		*service.Config
		Path string
	}{
		s.Config,
		path,
	}

	f, err := os.Create(confPath)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := s.template().Execute(f, to); err != nil {
		return err
	}

	if err = os.Chmod(confPath, 0755); err != nil {
		return err
	}

	var sb strings.Builder
	if err := template.Must(template.New("").Parse(ddwrtStartupCmd)).Execute(&sb, to); err != nil {
		return err
	}
	s.rcStartup = sb.String()
	curVal, err := nvram("get", nvramRCStartupKey)
	if err != nil {
		return err
	}
	if _, err := nvram("set", nvramCtrldKeyPrefix+nvramRCStartupKey+"="+curVal); err != nil {
		return err
	}
	val := strings.Join([]string{curVal, s.rcStartup + " &", fmt.Sprintf(`echo $! > "/tmp/%s.pid"`, s.Config.Name)}, "\n")

	if _, err := nvram("set", nvramRCStartupKey+"="+val); err != nil {
		return err
	}
	if out, err := nvram("commit"); err != nil {
		return fmt.Errorf("%s: %w", out, err)
	}

	return nil
}

func (s *ddwrtSvc) Uninstall() error {
	if err := os.Remove(s.configPath()); err != nil {
		return err
	}

	ctrldStartupKey := nvramCtrldKeyPrefix + nvramRCStartupKey
	rcStartup, err := nvram("get", ctrldStartupKey)
	if err != nil {
		return err
	}
	_, _ = nvram("unset", ctrldStartupKey)
	if _, err := nvram("set", nvramRCStartupKey+"="+rcStartup); err != nil {
		return err
	}
	if out, err := nvram("commit"); err != nil {
		return fmt.Errorf("%s: %w", out, err)
	}

	return nil
}

func (s *ddwrtSvc) Logger(errs chan<- error) (service.Logger, error) {
	if service.Interactive() {
		return service.ConsoleLogger, nil
	}
	return s.SystemLogger(errs)
}

func (s *ddwrtSvc) SystemLogger(errs chan<- error) (service.Logger, error) {
	// TODO(cuonglm): detect syslog enable and return proper logger?
	//                this at least works with default configuration.
	if service.Interactive() {
		return service.ConsoleLogger, nil

	}
	return &noopLogger{}, nil
}

func (s *ddwrtSvc) Run() (err error) {
	err = s.i.Start(s)
	if err != nil {
		return err
	}

	var sigChan = make(chan os.Signal, 3)
	signal.Notify(sigChan, syscall.SIGTERM, os.Interrupt)
	<-sigChan

	return s.i.Stop(s)
}

func (s *ddwrtSvc) Status() (service.Status, error) {
	if _, err := os.Stat(s.configPath()); os.IsNotExist(err) {
		return service.StatusUnknown, service.ErrNotInstalled
	}
	out, err := exec.Command(s.configPath(), "status").CombinedOutput()
	if err != nil {
		return service.StatusUnknown, err
	}
	switch string(bytes.TrimSpace(out)) {
	case "running":
		return service.StatusRunning, nil
	default:
		return service.StatusStopped, nil
	}
}

func (s *ddwrtSvc) Start() error {
	return exec.Command(s.configPath(), "start").Run()
}

func (s *ddwrtSvc) Stop() error {
	return exec.Command(s.configPath(), "stop").Run()
}

func (s *ddwrtSvc) Restart() error {
	err := s.Stop()
	if err != nil {
		return err
	}
	return s.Start()
}

type noopLogger struct {
}

func (c noopLogger) Error(v ...interface{}) error {
	return nil
}
func (c noopLogger) Warning(v ...interface{}) error {
	return nil
}
func (c noopLogger) Info(v ...interface{}) error {
	return nil
}
func (c noopLogger) Errorf(format string, a ...interface{}) error {
	return nil
}
func (c noopLogger) Warningf(format string, a ...interface{}) error {
	return nil
}
func (c noopLogger) Infof(format string, a ...interface{}) error {
	return nil
}

const ddwrtStartupCmd = `{{.Path}}{{range .Arguments}} {{.}}{{end}}`
const ddwrtSvcScript = `#!/bin/sh

name="{{.Name}}"
cmd="{{.Path}}{{range .Arguments}} {{.}}{{end}}"
pid_file="/tmp/$name.pid"

get_pid() {
  cat "$pid_file"
}

is_running() {
  [ -f "$pid_file" ] && ps | grep -q "^ *$(get_pid) "
}

case "$1" in
  start)
    if is_running; then
      echo "Already started"
    else
      echo "Starting $name"
      $cmd &
      echo $! > "$pid_file"
      chmod 600 "$pid_file"
      if ! is_running; then
       echo "Failed to start $name"
       exit 1
      fi
    fi
  ;;
  stop)
    if is_running; then
      echo -n "Stopping $name..."
      kill "$(get_pid)"
      for _ in 1 2 3 4 5; do
        if ! is_running; then
          echo "stopped"
          if [ -f "$pid_file" ]; then
            rm "$pid_file"
          fi
          exit 0
        fi
        printf "."
        sleep 2
      done
      echo "failed to stop $name"
      exit 1
    fi
    exit 1
  ;;
  restart)
    $0 stop
    $0 start
  ;;
  status)
    if is_running; then
      echo "running"
    else
      echo "stopped"
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
