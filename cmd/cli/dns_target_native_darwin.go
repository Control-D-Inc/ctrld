//go:build darwin

package cli

import (
	"context"
	"net"

	ctrld "github.com/Control-D-Inc/ctrld"
)

var targetDHCPReadFn = ctrld.DHCPNameserversForInterfaceContext

// Bound the DHCP prerequisite separately from the native evidence transaction.
func readTargetDHCPNameservers(device string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), nativeTargetReadBudget)
	defer cancel()
	return targetDHCPReadFn(ctx, device)
}

func readTargetStaticDNS(iface *net.Interface) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), nativeTargetReadBudget)
	defer cancel()
	return readNativeTargetStaticDNS(ctx, iface)
}

func readNativeTargetStaticDNS(ctx context.Context, iface *net.Interface) ([]string, error) {
	out, err := runNativeTargetCommand(ctx, "", "/usr/sbin/networksetup", "-getdnsservers", iface.Name)
	if err != nil {
		return nil, err
	}
	return parseTargetStaticDNS(string(out), iface.Name)
}

func nativeCLATDefaultService(ctx context.Context, device string) (nativeTargetService, error) {
	return (nativeTargetReader{
		run:             runNativeTargetCommand,
		interfaceByName: net.InterfaceByName,
		interfaceAddrs:  (*net.Interface).Addrs,
	}).defaultService(ctx, device)
}
