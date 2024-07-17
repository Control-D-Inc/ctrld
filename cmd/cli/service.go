package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/kardianos/service"

	"github.com/Control-D-Inc/ctrld/internal/router"
)

// newService wraps service.New call to return service.Service
// wrapper which is suitable for the current platform.
func newService(i service.Interface, c *service.Config) (service.Service, error) {
	s, err := service.New(i, c)
	if err != nil {
		return nil, err
	}
	switch {
	case router.IsOldOpenwrt(), router.IsNetGearOrbi():
		return &procd{sysV: &sysV{s}, svcConfig: c}, nil
	case router.IsGLiNet():
		return &sysV{s}, nil
	case s.Platform() == "unix-systemv":
		return &sysV{s}, nil
	case s.Platform() == "linux-systemd":
		return &systemd{s}, nil
	case s.Platform() == "darwin-launchd":
		return &launchd{s}, nil

	}
	return s, nil
}

// sysV wraps a service.Service, and provide start/stop/status command
// base on "/etc/init.d/<service_name>".
//
// Use this on system where "service" command is not available, like GL.iNET router.
type sysV struct {
	service.Service
}

func (s *sysV) installed() bool {
	fi, err := os.Stat("/etc/init.d/ctrld")
	if err != nil {
		return false
	}
	mode := fi.Mode()
	return mode.IsRegular() && (mode&0111) != 0
}

func (s *sysV) Start() error {
	if !s.installed() {
		return service.ErrNotInstalled
	}
	_, err := exec.Command("/etc/init.d/ctrld", "start").CombinedOutput()
	return err
}

func (s *sysV) Stop() error {
	if !s.installed() {
		return service.ErrNotInstalled
	}
	_, err := exec.Command("/etc/init.d/ctrld", "stop").CombinedOutput()
	return err
}

func (s *sysV) Restart() error {
	if !s.installed() {
		return service.ErrNotInstalled
	}
	// We don't care about error returned by s.Stop,
	// because the service may already be stopped.
	_ = s.Stop()
	return s.Start()
}

func (s *sysV) Status() (service.Status, error) {
	if !s.installed() {
		return service.StatusUnknown, service.ErrNotInstalled
	}
	return unixSystemVServiceStatus()
}

// procd wraps a service.Service, and provide start/stop command
// base on "/etc/init.d/<service_name>", status command base on parsing "ps" command output.
//
// Use this on system where "/etc/init.d/<service_name> status" command is not available,
// like old GL.iNET Opal router.
type procd struct {
	*sysV
	svcConfig *service.Config
}

func (s *procd) Status() (service.Status, error) {
	if !s.installed() {
		return service.StatusUnknown, service.ErrNotInstalled
	}
	bin := s.svcConfig.Executable
	if bin == "" {
		exe, err := os.Executable()
		if err != nil {
			return service.StatusUnknown, nil
		}
		bin = exe
	}

	// Looking for something like "/sbin/ctrld run ".
	shellCmd := fmt.Sprintf("ps | grep -q %q", bin+" [r]un ")
	if err := exec.Command("sh", "-c", shellCmd).Run(); err != nil {
		return service.StatusStopped, nil
	}
	return service.StatusRunning, nil
}

// systemd wraps a service.Service, and provide status command to
// report the status correctly.
type systemd struct {
	service.Service
}

func (s *systemd) Status() (service.Status, error) {
	out, _ := exec.Command("systemctl", "status", "ctrld").CombinedOutput()
	if bytes.Contains(out, []byte("/FAILURE)")) {
		return service.StatusStopped, nil
	}
	return s.Service.Status()
}

// launchd wraps a service.Service, and provide status command to
// report the status correctly when not running as root on Darwin.
//
// TODO: remove this wrapper once https://github.com/kardianos/service/issues/400 fixed.
type launchd struct {
	service.Service
}

func (l *launchd) Status() (service.Status, error) {
	if os.Geteuid() != 0 {
		return service.StatusUnknown, errors.New("permission denied")
	}
	return l.Service.Status()
}

type task struct {
	f            func() error
	abortOnError bool
}

func doTasks(tasks []task) bool {
	var prevErr error
	for _, task := range tasks {
		if err := task.f(); err != nil {
			if task.abortOnError {
				mainLog.Load().Error().Msg(errors.Join(prevErr, err).Error())
				return false
			}
			prevErr = err
		}
	}
	return true
}

func checkHasElevatedPrivilege() {
	ok, err := hasElevatedPrivilege()
	if err != nil {
		mainLog.Load().Error().Msgf("could not detect user privilege: %v", err)
		return
	}
	if !ok {
		mainLog.Load().Error().Msg("Please relaunch process with admin/root privilege.")
		os.Exit(1)
	}
}

func unixSystemVServiceStatus() (service.Status, error) {
	out, err := exec.Command("/etc/init.d/ctrld", "status").CombinedOutput()
	if err != nil {
		return service.StatusUnknown, nil
	}

	switch string(bytes.ToLower(bytes.TrimSpace(out))) {
	case "running":
		return service.StatusRunning, nil
	default:
		return service.StatusStopped, nil
	}
}
