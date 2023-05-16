package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"

	"github.com/kardianos/service"

	"github.com/Control-D-Inc/ctrld/internal/router"
)

func newService(s service.Service) service.Service {
	// TODO: unify for other SysV system.
	if router.IsGLiNet() {
		return &sysV{s}
	}
	return s
}

// sysV wraps a service.Service, and provide start/stop/status command
// base on "/etc/init.d/<service_name>".
//
// Use this on system wherer "service" command is not available, like GL.iNET router.
type sysV struct {
	service.Service
}

func (s *sysV) Start() error {
	_, err := exec.Command("/etc/init.d/ctrld", "start").CombinedOutput()
	return err
}

func (s *sysV) Stop() error {
	_, err := exec.Command("/etc/init.d/ctrld", "stop").CombinedOutput()
	return err
}

func (s *sysV) Status() (service.Status, error) {
	return unixSystemVServiceStatus()
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
				mainLog.Error().Msg(errors.Join(prevErr, err).Error())
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
		mainLog.Error().Msgf("could not detect user privilege: %v", err)
		return
	}
	if !ok {
		mainLog.Error().Msg("Please relaunch process with admin/root privilege.")
		os.Exit(1)
	}
}

func serviceStatus(s service.Service) (service.Status, error) {
	status, err := s.Status()
	if err != nil && service.Platform() == "unix-systemv" {
		return unixSystemVServiceStatus()
	}
	return status, err
}

func unixSystemVServiceStatus() (service.Status, error) {
	out, err := exec.Command("/etc/init.d/ctrld", "status").CombinedOutput()
	if err != nil {
		return service.StatusUnknown, nil
	}
	switch string(bytes.TrimSpace(out)) {
	case "running":
		return service.StatusRunning, nil
	default:
		return service.StatusStopped, nil
	}
}
