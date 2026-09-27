package router

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/template"

	"github.com/kardianos/service"

	"github.com/Control-D-Inc/ctrld/internal/router/nvram"
)

const (
	merlinJFFSScriptPath             = "/jffs/scripts/services-start"
	merlinJFFSServiceEventScriptPath = "/jffs/scripts/service-event"
)

type merlinSvc struct {
	i        service.Interface
	platform string
	*service.Config
}

func newMerlinService(i service.Interface, platform string, c *service.Config) (service.Service, error) {
	s := &merlinSvc{
		i:        i,
		platform: platform,
		Config:   c,
	}
	return s, nil
}

func (s *merlinSvc) String() string {
	if len(s.DisplayName) > 0 {
		return s.DisplayName
	}
	return s.Name
}

func (s *merlinSvc) Platform() string {
	return s.platform
}

func (s *merlinSvc) configPath() string {
	bin := s.Config.Executable
	if bin == "" {
		path, err := os.Executable()
		if err != nil {
			return ""
		}
		bin = path
	}
	return bin + ".startup"
}

func (s *merlinSvc) template() *template.Template {
	return template.Must(template.New("").Funcs(template.FuncMap{
		"shellQuote": merlinShellQuote,
	}).Parse(merlinSvcScript))
}

func merlinShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

func writeMerlinStartupScript(path string, data []byte, mode os.FileMode) (published bool, retErr error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".ctrld-*")
	if err != nil {
		return false, err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()

	if err := tmp.Chmod(mode); err != nil {
		return false, err
	}
	if _, err := tmp.Write(data); err != nil {
		return false, err
	}
	if err := tmp.Sync(); err != nil {
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}

	// Publish without replacement semantics. If another actor creates the
	// startup script after our preflight, leave that file untouched.
	if err := os.Link(tmpPath, path); err != nil {
		return false, err
	}
	published = true

	if err := os.Remove(tmpPath); err != nil {
		return true, err
	}
	if err := syncMerlinServiceDir(dir); err != nil {
		return true, err
	}
	return true, nil
}

func syncMerlinServiceDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func (s *merlinSvc) Install() error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}

	if !strings.HasPrefix(exePath, "/jffs/") {
		return errors.New("could not install service outside /jffs")
	}
	if _, err := nvram.Run("set", "jffs2_scripts=1"); err != nil {
		return err
	}
	if _, err := nvram.Run("commit"); err != nil {
		return err
	}

	confPath := s.configPath()

	var to = &struct {
		*service.Config
		Path string
	}{
		s.Config,
		exePath,
	}

	// Render completely before touching the destination. A template error must
	// not leave a truncated startup script which then looks "already installed".
	var rendered bytes.Buffer
	if err := s.template().Execute(&rendered, to); err != nil {
		return fmt.Errorf("s.template.Execute: %w", err)
	}
	startupPublished := false
	existing, err := os.ReadFile(confPath)
	switch {
	case err == nil:
		if !bytes.Equal(existing, rendered.Bytes()) {
			return fmt.Errorf("already installed with different startup script: %s", confPath)
		}
		// An interrupted previous install may have published the private startup
		// script before adding both shared hooks. Identical bytes prove that this
		// install can safely resume instead of getting stuck on "already installed".
		if err := os.Chmod(confPath, 0755); err != nil {
			return fmt.Errorf("os.Chmod: startup script: %w", err)
		}
	case os.IsNotExist(err):
		startupPublished, err = writeMerlinStartupScript(confPath, rendered.Bytes(), 0755)
		if err != nil {
			if startupPublished {
				_ = os.Remove(confPath)
				_ = syncMerlinServiceDir(filepath.Dir(confPath))
			}
			return fmt.Errorf("publish startup script: %w", err)
		}
	default:
		return fmt.Errorf("read startup script: %w", err)
	}

	installComplete := false
	defer func() {
		if !installComplete && startupPublished {
			_ = os.Remove(confPath)
			_ = syncMerlinServiceDir(filepath.Dir(confPath))
		}
	}()

	if err := os.MkdirAll(filepath.Dir(merlinJFFSScriptPath), 0755); err != nil {
		return fmt.Errorf("os.MkdirAll: %w", err)
	}

	tmpScript, err := os.CreateTemp("", "ctrld_install")
	if err != nil {
		return fmt.Errorf("os.CreateTemp: %w", err)
	}
	defer os.Remove(tmpScript.Name())
	defer tmpScript.Close()

	if _, err := tmpScript.WriteString(merlinAddLineToScript); err != nil {
		return fmt.Errorf("tmpScript.WriteString: %w", err)
	}
	if err := tmpScript.Close(); err != nil {
		return fmt.Errorf("tmpScript.Close: %w", err)
	}
	cleanupCreatedHook := func(line, script string) {
		// Remove only ctrld's exact managed line first. If the file is still the
		// pristine stub ctrld created, remove it; otherwise preserve any content
		// another addon/user added concurrently.
		_ = exec.Command("sh", tmpScript.Name(), line, script, "remove").Run()
		buf, err := os.ReadFile(script)
		if err == nil && bytes.Equal(buf, []byte("#!/bin/sh\n")) {
			_ = os.Remove(script)
		}
	}

	addLineToScript := func(line, script string) (created bool, retErr error) {
		if _, err := os.Stat(script); os.IsNotExist(err) {
			if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0755); err != nil {
				return false, err
			}
			created = true
		} else if err != nil {
			return false, err
		}
		defer func() {
			if retErr != nil && created {
				cleanupCreatedHook(line, script)
			}
		}()

		// A pre-existing shared hook owns its mode. Do not chmod it as a side
		// effect of installing ctrld.
		if err := exec.Command("sh", tmpScript.Name(), line, script, "add").Run(); err != nil {
			return created, fmt.Errorf("exec.Command: add startup script: %w", err)
		}
		return created, nil
	}

	type hookLine struct {
		script  string
		line    string
		created bool
	}
	hooks := []hookLine{
		{script: merlinJFFSScriptPath, line: s.configPath() + " start"},
		{script: merlinJFFSServiceEventScriptPath, line: s.configPath() + ` service_event "$1" "$2"`},
	}
	installed := make([]hookLine, 0, len(hooks))
	for _, hook := range hooks {
		created, err := addLineToScript(hook.line, hook.script)
		if err != nil {
			// Best-effort rollback: remove only lines successfully installed by
			// this attempt. Shared hook files created by ctrld are removed again;
			// pre-existing hooks keep all unrelated content.
			for i := len(installed) - 1; i >= 0; i-- {
				prev := installed[i]
				if prev.created {
					cleanupCreatedHook(prev.line, prev.script)
					continue
				}
				_ = exec.Command("sh", tmpScript.Name(), prev.line, prev.script, "remove").Run()
			}
			return err
		}
		hook.created = created
		installed = append(installed, hook)
	}

	installComplete = true
	return nil
}

func (s *merlinSvc) Uninstall() error {
	tmpScript, err := os.CreateTemp("", "ctrld_uninstall")
	if err != nil {
		return fmt.Errorf("os.CreateTemp: %w", err)
	}
	defer os.Remove(tmpScript.Name())
	defer tmpScript.Close()

	if _, err := tmpScript.WriteString(merlinRemoveLineFromScript); err != nil {
		return fmt.Errorf("tmpScript.WriteString: %w", err)
	}
	if err := tmpScript.Close(); err != nil {
		return fmt.Errorf("tmpScript.Close: %w", err)
	}
	removeLineFromScript := func(line, script string) error {
		if _, err := os.Stat(script); os.IsNotExist(err) {
			// Shared Merlin hooks belong to the router/user. Uninstalling ctrld
			// must not create a hook file that did not exist.
			return nil
		} else if err != nil {
			return err
		}

		if err := exec.Command("sh", tmpScript.Name(), line, script, "remove").Run(); err != nil {
			return fmt.Errorf("exec.Command: remove startup script: %w", err)
		}
		return nil
	}

	for script, line := range map[string]string{
		merlinJFFSScriptPath:             s.configPath() + " start",
		merlinJFFSServiceEventScriptPath: s.configPath() + ` service_event "$1" "$2"`,
	} {
		if err := removeLineFromScript(line, script); err != nil {
			return err
		}
	}

	// Remove ctrld's private startup script only after all shared hook
	// references have been removed successfully.
	if err := os.Remove(s.configPath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("os.Remove: %w", err)
	}
	return nil
}

func (s *merlinSvc) Logger(errs chan<- error) (service.Logger, error) {
	if service.Interactive() {
		return service.ConsoleLogger, nil
	}
	return s.SystemLogger(errs)
}

func (s *merlinSvc) SystemLogger(errs chan<- error) (service.Logger, error) {
	return newSysLogger(s.Name, errs)
}

func (s *merlinSvc) Run() (err error) {
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

func (s *merlinSvc) Status() (service.Status, error) {
	if _, err := os.Stat(s.configPath()); os.IsNotExist(err) {
		return service.StatusUnknown, service.ErrNotInstalled
	} else if err != nil {
		return service.StatusUnknown, err
	}
	out, err := exec.Command(s.configPath(), "status").CombinedOutput()
	return merlinServiceStatus(out, err)
}

func merlinServiceStatus(out []byte, cmdErr error) (service.Status, error) {
	switch string(bytes.TrimSpace(out)) {
	case "running":
		if cmdErr != nil {
			return service.StatusUnknown, cmdErr
		}
		return service.StatusRunning, nil
	case "stopped":
		// The generated BusyBox script intentionally exits 1 for "stopped".
		// That is a state, not a failure to determine the state.
		return service.StatusStopped, nil
	default:
		if cmdErr != nil {
			return service.StatusUnknown, cmdErr
		}
		return service.StatusUnknown, fmt.Errorf("unexpected Merlin service status output: %q", bytes.TrimSpace(out))
	}
}

func (s *merlinSvc) Start() error {
	return exec.Command(s.configPath(), "start").Run()
}

func (s *merlinSvc) Stop() error {
	return exec.Command(s.configPath(), "stop").Run()
}

func (s *merlinSvc) Restart() error {
	err := s.Stop()
	if err != nil {
		return err
	}
	return s.Start()
}

const merlinSvcScript = `#!/bin/sh

name={{shellQuote .Name}}
exe={{shellQuote .Path}}
pid_file="/tmp/$name.pid"

get_pid() {
  [ -r "$pid_file" ] || return 1
  pid="$(cat "$pid_file" 2>/dev/null)" || return 1
  case "$pid" in
    ''|*[!0-9]*) return 1 ;;
  esac
  printf '%s\n' "$pid"
}

is_running() {
  pid="$(get_pid)" || return 1
  [ -r "/proc/$pid/cmdline" ] || return 1
  process_cmd="$(tr '\000' ' ' < "/proc/$pid/cmdline" 2>/dev/null)" || return 1
  case "$process_cmd" in
    "$exe"|"$exe "*) return 0 ;;
    *) return 1 ;;
  esac
}

case "$1" in
  start)
    if is_running; then
      logger -c "Already started"
    else
      rm -f "$pid_file"
      logger -c "Starting $name"
      if [ -f /rom/ca-bundle.crt ]; then
        # For John’s fork
        export SSL_CERT_FILE=/rom/ca-bundle.crt
      fi
      {{shellQuote .Path}}{{range .Arguments}} {{shellQuote .}}{{end}} &
      echo $! > "$pid_file"
      chmod 600 "$pid_file"
      started=0
      for _ in 1 2 3 4 5; do
        if is_running; then
          started=1
          break
        fi
        sleep 1
      done
      if [ "$started" -ne 1 ]; then
        logger -c "Failed to start $name"
        rm -f "$pid_file"
        exit 1
      fi
    fi
  ;;
  stop)
    if is_running; then
      logger -c "Stopping $name..."
      kill "$(get_pid)"
      for _ in 1 2 3 4 5; do
        if ! is_running; then
          logger -c "stopped"
          if [ -f "$pid_file" ]; then
            rm "$pid_file"
          fi
          exit 0
        fi
        printf "."
        sleep 2
      done
      logger -c "failed to stop $name"
      exit 1
    fi
    rm -f "$pid_file"
    exit 0
  ;;
  restart)
    "$0" stop || exit $?
    "$0" start
  ;;
  status)
    if is_running; then
      echo "running"
    else
      echo "stopped"
      exit 1
    fi
  ;;
  service_event)
    event=$2
    svc=$3
    dnsmasq_pid_file=$(sed -n '/pid-file=/s///p' /etc/dnsmasq.conf)

    if [ "$event" = "restart" ] && [ "$svc" = "diskmon" ] && [ -r "$dnsmasq_pid_file" ]; then
      dnsmasq_pid="$(cat "$dnsmasq_pid_file" 2>/dev/null)"
      case "$dnsmasq_pid" in
        ''|*[!0-9]*) dnsmasq_pid="" ;;
      esac
      if [ -n "$dnsmasq_pid" ] && [ -r "/proc/$dnsmasq_pid/cmdline" ]; then
        dnsmasq_exe="$(tr '\000' '\n' < "/proc/$dnsmasq_pid/cmdline" 2>/dev/null | sed -n '1p')"
        case "$dnsmasq_exe" in
          dnsmasq|*/dnsmasq) kill "$dnsmasq_pid" >/dev/null 2>&1 ;;
        esac
      fi
    fi
  ;;
  *)
    echo "Usage: $0 {start|stop|restart|status}"
    exit 1
  ;;
esac
exit 0
`

const merlinAddLineToScript = `#!/bin/sh

line=$1
file=$2
mode=$3

. /usr/sbin/helper.sh

pc_delete "$line" "$file"
[ "$mode" = "remove" ] || pc_append "$line" "$file"
`

const merlinRemoveLineFromScript = `#!/bin/sh

line=$1
file=$2

. /usr/sbin/helper.sh

pc_delete "$line" "$file" 
`
