package main

import (
	"fmt"
	"os"

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
