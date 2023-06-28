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

	"github.com/Control-D-Inc/ctrld/internal/router/nvram"
)

const tomatoNvramScriptWanupKey = "script_wanup"

type tomatoSvc struct {
	i        service.Interface
	platform string
	*service.Config
}

func newTomatoService(i service.Interface, platform string, c *service.Config) (service.Service, error) {
	s := &tomatoSvc{
		i:        i,
		platform: platform,
		Config:   c,
	}
	return s, nil
}

func (s *tomatoSvc) String() string {
	if len(s.DisplayName) > 0 {
		return s.DisplayName
	}
	return s.Name
}

func (s *tomatoSvc) Platform() string {
	return s.platform
}

func (s *tomatoSvc) configPath() string {
	path, err := os.Executable()
	if err != nil {
		return ""
	}
	return path + ".startup"
}

func (s *tomatoSvc) template() *template.Template {
	return template.Must(template.New("").Parse(tomatoSvcScript))
}

func (s *tomatoSvc) Install() error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}

	if !strings.HasPrefix(exePath, "/jffs/") {
		return errors.New("could not install service outside /jffs")
	}
	if _, err := nvram.Run("set", "jffs2_on=1"); err != nil {
		return err
	}
	if _, err := nvram.Run("commit"); err != nil {
		return err
	}

	confPath := s.configPath()
	if _, err := os.Stat(confPath); err == nil {
		return fmt.Errorf("already installed: %s", confPath)
	}

	var to = &struct {
		*service.Config
		Path string
	}{
		s.Config,
		exePath,
	}

	f, err := os.Create(confPath)
	if err != nil {
		return fmt.Errorf("os.Create: %w", err)
	}
	defer f.Close()

	if err := s.template().Execute(f, to); err != nil {
		return fmt.Errorf("s.template.Execute: %w", err)
	}

	if err = os.Chmod(confPath, 0755); err != nil {
		return fmt.Errorf("os.Chmod: startup script: %w", err)
	}

	nvramKvMap := map[string]string{
		tomatoNvramScriptWanupKey: "", // script to start ctrld, filled by tomatoSvc.Install method.
	}
	old, err := nvram.Run("get", tomatoNvramScriptWanupKey)
	if err != nil {
		return fmt.Errorf("nvram: %w", err)
	}
	nvramKvMap[tomatoNvramScriptWanupKey] = strings.Join([]string{old, s.configPath() + " start"}, "\n")
	if err := nvram.SetKV(nvramKvMap, nvram.CtrldInstallKey); err != nil {
		return err
	}
	return nil
}

func (s *tomatoSvc) Uninstall() error {
	if err := os.Remove(s.configPath()); err != nil {
		return fmt.Errorf("os.Remove: %w", err)
	}
	nvramKvMap := map[string]string{
		tomatoNvramScriptWanupKey: "", // script to start ctrld, filled by tomatoSvc.Install method.
	}
	// Restore old configs.
	if err := nvram.Restore(nvramKvMap, nvram.CtrldInstallKey); err != nil {
		return err
	}
	return nil
}

func (s *tomatoSvc) Logger(errs chan<- error) (service.Logger, error) {
	if service.Interactive() {
		return service.ConsoleLogger, nil
	}
	return s.SystemLogger(errs)
}

func (s *tomatoSvc) SystemLogger(errs chan<- error) (service.Logger, error) {
	return newSysLogger(s.Name, errs)
}

func (s *tomatoSvc) Run() (err error) {
	err = s.i.Start(s)
	if err != nil {
		return err
	}

	if interactice, _ := isInteractive(); !interactice {
		signal.Ignore(syscall.SIGHUP)
	}

	var sigChan = make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, os.Interrupt)
	<-sigChan

	return s.i.Stop(s)
}

func (s *tomatoSvc) Status() (service.Status, error) {
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

func (s *tomatoSvc) Start() error {
	return exec.Command(s.configPath(), "start").Run()
}

func (s *tomatoSvc) Stop() error {
	return exec.Command(s.configPath(), "stop").Run()
}

func (s *tomatoSvc) Restart() error {
	return exec.Command(s.configPath(), "restart").Run()
}

// https://wiki.freshtomato.org/doku.php/freshtomato_zerotier?s[]=%2Aservice%2A
const tomatoSvcScript = `#!/bin/sh
 

NAME="{{.Name}}"
CMD="{{.Path}}{{range .Arguments}} {{.}}{{end}}"
LOG_FILE="/var/log/${NAME}.log"
PID_FILE="/tmp/$NAME.pid"
 
 
alias elog="logger -t $NAME -s"
 
 
COND=$1
[ $# -eq 0 ] && COND="start"
 
get_pid() {
  cat "$PID_FILE"
}

is_running() {
  [ -f "$PID_FILE" ] && ps | grep -q "^ *$(get_pid) "
}

start() {
  if is_running; then
    elog "$NAME is already running."
    exit 1
  fi
  elog "Starting $NAME Services: "
  $CMD &
  echo $! > "$PID_FILE"
  chmod 600 "$PID_FILE"
  if is_running; then
    elog "succeeded."
  else
    elog "failed."
  fi
}
 
 
stop() {
  if ! is_running; then
    elog "$NAME is not running."
    exit 1
  fi
  elog "Shutting down $NAME Services: "
  kill -SIGTERM "$(get_pid)"
  for _ in 1 2 3 4 5; do
    if ! is_running; then
      if [ -f "$pid_file" ]; then
        rm "$pid_file"
      fi
      return 0
    fi
    printf "."
    sleep 2
  done
  if ! is_running; then
    elog "succeeded."
  else
    elog "failed."
  fi
}
 
 
do_restart() {
  stop
  start
}


do_status() {
  if ! is_running; then
    echo "stopped"
  else
    echo "running"
  fi
}
 
 
case "$COND" in
start)
  start
  ;;
stop)
  stop
  ;;
restart)
  do_restart
  ;;
status)
  do_status
  ;;
*)
  elog "Usage: $0 (start|stop|restart|status)"
  ;;
esac
exit 0
`
