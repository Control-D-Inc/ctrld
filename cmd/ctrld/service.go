package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"

	"github.com/kardianos/service"
	"github.com/spf13/cobra"
)

func stderrMsg(msg string) {
	_, _ = fmt.Fprintln(os.Stderr, msg)
}

func stdoutMsg(msg string) {
	_, _ = fmt.Fprintln(os.Stdout, msg)
}

type task struct {
	f            func() error
	abortOnError bool
}

func doTasks(tasks []task) bool {
	for _, task := range tasks {
		if err := task.f(); err != nil {
			if task.abortOnError {
				stderrMsg(err.Error())
				return false
			}
		}
	}
	return true
}

func checkHasElevatedPrivilege(cmd *cobra.Command, args []string) {
	ok, err := hasElevatedPrivilege()
	if err != nil {
		fmt.Printf("could not detect user privilege: %v", err)
		return
	}
	if !ok {
		fmt.Println("Please relaunch process with admin/root privilege.")
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
