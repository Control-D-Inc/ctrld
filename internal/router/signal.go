//go:build !windows

package router

import "syscall"

const sigCHLD = syscall.SIGCHLD
