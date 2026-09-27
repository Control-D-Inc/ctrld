//go:build linux

package router

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

const merlinServiceLockPath = "/tmp/ctrld-merlin-service.lock"

func withMerlinServiceLock(fn func() error) error {
	fd, err := unix.Open(
		merlinServiceLockPath,
		unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0600,
	)
	if err != nil {
		return fmt.Errorf("open Merlin service lifecycle lock: %w", err)
	}
	f := os.NewFile(uintptr(fd), merlinServiceLockPath)
	if f == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("wrap Merlin service lifecycle lock descriptor")
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat Merlin service lifecycle lock: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("merlin service lifecycle lock is not a regular file: %s", merlinServiceLockPath)
	}
	if err := f.Chmod(0600); err != nil {
		return fmt.Errorf("chmod Merlin service lifecycle lock: %w", err)
	}

	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		return fmt.Errorf("lock Merlin service lifecycle: %w", err)
	}
	defer unix.Flock(fd, unix.LOCK_UN)

	return fn()
}
