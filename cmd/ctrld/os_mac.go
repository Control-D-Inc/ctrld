//go:build darwin
// +build darwin

package main

import (
	"os/exec"
)

// allocate loopback ip
// sudo ifconfig lo0 alias 127.0.0.2 up
func allocateIP(ip string) error {
	cmd := exec.Command("ifconfig", "lo0", "alias", ip, "up")
	if err := cmd.Run(); err != nil {
		mainLog.Error().Err(err).Msg("allocateIP failed")
		return err
	}
	return nil
}

func deAllocateIP(ip string) error {
	cmd := exec.Command("ifconfig", "lo0", "-alias", ip)
	if err := cmd.Run(); err != nil {
		mainLog.Error().Err(err).Msg("deAllocateIP failed")
		return err
	}
	return nil
}
