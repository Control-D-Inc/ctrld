package main

import (
	"os/exec"
)

// allocate loopback ip
// sudo ip a add 127.0.0.2/24 dev lo
func allocateIP(ip string) error {
	cmd := exec.Command("ip", "a", "add", ip+"/24", "dev", "lo")
	if err := cmd.Run(); err != nil {
		mainLog.Error().Err(err).Msg("allocateIP failed")
		return err
	}
	return nil
}

func deAllocateIP(ip string) error {
	cmd := exec.Command("ip", "a", "del", ip+"/24", "dev", "lo")
	if err := cmd.Run(); err != nil {
		mainLog.Error().Err(err).Msg("deAllocateIP failed")
		return err
	}
	return nil
}
