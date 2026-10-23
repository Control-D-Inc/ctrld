package cli

import (
	"bytes"
	"context"
	"os/exec"
	"time"
)

// scutilDNSTimeout bounds the read. scutil talks to the configuration daemon,
// and that daemon stalls while the network moves.
const scutilDNSTimeout = 5 * time.Second

func runSCUtilDNS() ([]dnsResolverEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), scutilDNSTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "scutil", "--dns").Output()
	if err != nil {
		return nil, err
	}
	return parseSCUtilDNS(bytes.NewReader(out))
}
