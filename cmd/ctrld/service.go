package main

import (
	"fmt"
	"os"
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
