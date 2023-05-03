package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"

	"github.com/kardianos/service"
)

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
