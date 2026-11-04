package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

// tailscaleLocalAPITimeout bounds one LocalAPI read. Discovery runs on network
// change paths, so it must never stall them.
const tailscaleLocalAPITimeout = 2 * time.Second

// tailscaleLocalAPIHost is the Host header Tailscale's LocalAPI requires.
const tailscaleLocalAPIHost = "local-tailscaled.sock"

// tailscaleDNSConfigPath returns the network's DNS config, including Split DNS
// and App Connector routes. Tailscale added it in v1.98.0.
const tailscaleDNSConfigPath = "/localapi/v0/dns-config"

// maxTailscaleDNSConfigBytes bounds the response body ctrld reads.
const maxTailscaleDNSConfigBytes = 4 << 20

var errTailscaleLocalAPIUnavailable = errors.New("tailscale LocalAPI not found")

// tailscaleLocalAPIEndpoint is one way to reach a running Tailscale LocalAPI.
type tailscaleLocalAPIEndpoint struct {
	name  string
	dial  func(ctx context.Context) (net.Conn, error)
	token string // HTTP Basic-Auth password; empty for the tailscaled socket
}

// tailscaleAppStoreProc is the exact command name of the Mac App Store
// Tailscale network extension.
const tailscaleAppStoreProc = "IPNExtension"

// sameUserProofPath matches the sameuserproof file of the Mac App Store
// Tailscale extension: <home>/Library/Group Containers/<group>.tailscale.ipn.macos/
// sameuserproof-<port>-<token>. Paths anywhere else are not accepted, because
// any local user can create a file with that name under /tmp.
var sameUserProofPath = regexp.MustCompile(`^/Users/[^/]+/Library/Group Containers/[^/]+\.tailscale\.ipn\.macos/sameuserproof-([0-9]+)-([^/]+)$`)

// macOSSameUserProof is one App Store LocalAPI candidate found by lsof.
type macOSSameUserProof struct {
	pid   int
	port  int
	token string
}

// parseMacOSSameUserProofs extracts App Store LocalAPI candidates from
// `lsof -F pcn` output. A candidate needs a process whose command is exactly
// IPNExtension (lsof -c matches a prefix only) holding open a sameuserproof
// file in a user's Tailscale group container. The caller still has to verify
// the process code signature, because a command name is not proof.
func parseMacOSSameUserProofs(out []byte) []macOSSameUserProof {
	var proofs []macOSSameUserProof
	pid, command := 0, ""
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		value := line[1:]
		switch line[0] {
		case 'p':
			pid, command = 0, ""
			if p, err := strconv.Atoi(value); err == nil && p > 0 {
				pid = p
			}
		case 'c':
			command = value
		case 'n':
			if pid == 0 || command != tailscaleAppStoreProc {
				continue
			}
			m := sameUserProofPath.FindStringSubmatch(value)
			if m == nil {
				continue
			}
			port, err := strconv.Atoi(m[1])
			if err != nil || port <= 0 || port > 65535 {
				continue
			}
			proofs = append(proofs, macOSSameUserProof{pid: pid, port: port, token: m[2]})
		}
	}
	return proofs
}

// fetchTailscaleDNSConfig reads the dns-config body from one endpoint.
func fetchTailscaleDNSConfig(ctx context.Context, ep tailscaleLocalAPIEndpoint) ([]byte, error) {
	tr := &http.Transport{
		DialContext:       func(ctx context.Context, _, _ string) (net.Conn, error) { return ep.dial(ctx) },
		DisableKeepAlives: true,
		Proxy:             nil,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+tailscaleLocalAPIHost+tailscaleDNSConfigPath, nil)
	if err != nil {
		return nil, err
	}
	if ep.token != "" {
		req.SetBasicAuth("", ep.token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ep.name, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTailscaleDNSConfigBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ep.name, err)
	}
	if resp.StatusCode != http.StatusOK {
		// Older Tailscale has no dns-config endpoint and answers 404.
		return nil, fmt.Errorf("%s: dns-config returned HTTP %d", ep.name, resp.StatusCode)
	}
	if len(body) > maxTailscaleDNSConfigBytes {
		return nil, fmt.Errorf("%s: dns-config response exceeds %d bytes", ep.name, maxTailscaleDNSConfigBytes)
	}
	return body, nil
}

// discoverTailscaleRoutesFrom tries each endpoint in order and returns the
// routes of the first that answers. The error never contains the token.
func discoverTailscaleRoutesFrom(ctx context.Context, endpoints []tailscaleLocalAPIEndpoint) ([]tailscaleRoute, error) {
	if len(endpoints) == 0 {
		return nil, errTailscaleLocalAPIUnavailable
	}
	var errs []error
	for _, ep := range endpoints {
		body, err := fetchTailscaleDNSConfig(ctx, ep)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		routes, err := parseTailscaleRoutes(body)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: decode dns-config: %w", ep.name, err))
			continue
		}
		return routes, nil
	}
	return nil, errors.Join(errs...)
}
