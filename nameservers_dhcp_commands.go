package ctrld

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

// dhcpNameserversFromCommands shares one context across both discovery attempts.
// Cancellation is unknown state, never a successful empty DNS result.
func dhcpNameserversFromCommands(ctx context.Context, iface string, run func(context.Context, ...string) ([]byte, error)) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	output, optionErr := run(ctx, "getoption", iface, "domain_name_server")
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if optionErr == nil {
		return parseDHCPOptionNameservers(output), nil
	}
	output, packetErr := run(ctx, "getpacket", iface)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if packetErr != nil {
		return nil, fmt.Errorf("error reading DHCP DNS option: getoption: %w; getpacket: %w", optionErr, packetErr)
	}
	return parseDHCPPacketNameservers(output), nil
}

func dhcpCommandOutput(ctx context.Context, path string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.WaitDelay = 100 * time.Millisecond
	output, err := cmd.Output()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return output, err
}
