//go:build darwin

package cli

import (
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// capturePFGroupRuleFn reads ctrld's anchor once, with the bounds of the IPv6
// diagnostic, and keeps only the group exemption rule. Tests replace it.
var capturePFGroupRuleFn = func() pfGroupRuleSnapshot {
	ctx, cancel := context.WithTimeout(context.Background(), pfDiagnosticTimeout)
	defer cancel()
	out, code := readPFDiagnosticOutput(ctx, exec.CommandContext(ctx, "/sbin/pfctl", "-a", pfAnchorName, "-vvsr"))
	if code != "" {
		return pfGroupRuleSnapshot{Code: code}
	}
	return parsePFGroupRule(out)
}

// lookupCtrldGroupFn returns every group ID the directory resolves the pf
// group name to. More than one, or a number other than the process's
// effective GID, means pf may match a different group than ctrld runs as.
var lookupCtrldGroupFn = func() ([]string, string) {
	ctx, cancel := context.WithTimeout(context.Background(), pfDiagnosticTimeout)
	defer cancel()
	out, code := readPFDiagnosticOutput(ctx, exec.CommandContext(ctx, "/usr/bin/dscacheutil", "-q", "group", "-a", "name", pfGroupName))
	if code != "" {
		return nil, code
	}
	var gids []string
	for _, line := range strings.Split(string(out), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "gid:"); ok {
			gids = append(gids, strings.TrimSpace(v))
		}
	}
	return gids, "ok"
}

// readHostContext runs one bounded read for the host context. Each read has
// its own timeout and the output cap of the pf diagnostic.
func readHostContext(timeout time.Duration, name string, args ...string) (string, string) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, code := readPFDiagnosticOutput(ctx, exec.CommandContext(ctx, name, args...))
	if code != "" {
		return "", code
	}
	return string(out), "ok"
}

// listSystemExtensionsFn returns the activated system extensions as
// "category:bundle_id", and the network ones alone.
var listSystemExtensionsFn = func() ([]string, []string, string) {
	out, code := readHostContext(time.Second, "/usr/bin/systemextensionsctl", "list")
	if code != "ok" {
		return nil, nil, code
	}
	all, network := parseSystemExtensions(out)
	return all, network, code
}

// neConfigurationPath is the Network Extension configuration store.
const neConfigurationPath = "/Library/Preferences/com.apple.networkextension.plist"

// neConfigurationMaxBytes bounds the read of the store; a host with a few
// configurations has well under 100 KB.
const neConfigurationMaxBytes = 1 << 20

// listNEConfigurationsFn returns the configurations that steer traffic or DNS.
var listNEConfigurationsFn = func() ([]string, string) {
	f, err := os.Open(neConfigurationPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, "absent"
		}
		return nil, "read_failed"
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, neConfigurationMaxBytes+1))
	if err != nil {
		return nil, "read_failed"
	}
	if len(data) > neConfigurationMaxBytes {
		return nil, "output_limit"
	}
	return parseNEConfigurations(data)
}

// listVPNServicesFn returns each VPN service as "type:provider:status".
var listVPNServicesFn = func() ([]string, string) {
	out, code := readHostContext(time.Second, "/usr/sbin/scutil", "--nc", "list")
	if code != "ok" {
		return nil, code
	}
	return parseNCList(out), code
}

// listThirdPartyKextsFn returns loaded kernel extensions that are not Apple's.
var listThirdPartyKextsFn = func() ([]string, string) {
	out, code := readHostContext(2*time.Second, "/usr/bin/kmutil", "showloaded", "--list-only")
	if code != "ok" {
		return nil, code
	}
	return parseThirdPartyKexts(out), code
}

// listPFAnchorsFn returns pf anchors other than ctrld's.
var listPFAnchorsFn = func() ([]string, string) {
	out, code := readHostContext(pfDiagnosticTimeout, "/sbin/pfctl", "-sA")
	if code != "ok" {
		return nil, code
	}
	return parsePFAnchors(out, pfAnchorName), code
}

// addSelfLoopHostContext adds what explains a broken pf group exemption, and
// other DNS intercept failures: the group number pf loaded and its counter,
// the group number(s) the name resolves to, the process's effective GID, and
// the software that can take over, filter or redirect DNS traffic: system
// extensions, Network Extension configurations (including app-bundled and
// MDM-installed ones), VPN services, third-party kernel extensions and other
// pf anchors. Product identifiers only; each is a short bounded read, run
// once per report.
func addSelfLoopHostContext(e *zerolog.Event) {
	addHostContext(e)
}

// addHostContext adds the host context to e and returns the enabled DNS
// proxies of other products (see enabledDNSProxies), which are also logged
// as dns_proxies_enabled.
func addHostContext(e *zerolog.Event) []string {
	rule := capturePFGroupRuleFn()
	e.Str("pf_group_rule_status", rule.Code)
	if rule.GID != "" {
		e.Str("pf_group_rule_gid", rule.GID)
	}
	if rule.Known {
		e.Uint64("pf_group_rule_packets", rule.Packets)
	}
	e.Int("process_egid", os.Getegid())
	gids, code := lookupCtrldGroupFn()
	e.Str("ctrld_group_lookup_status", code).Strs("ctrld_group_gids", gids)
	all, network, code := listSystemExtensionsFn()
	e.Str("system_extensions_status", code).Strs("system_extensions", all).Strs("network_extensions", network)
	confs, code := listNEConfigurationsFn()
	proxies := enabledDNSProxies(confs)
	e.Str("ne_configurations_status", code).Strs("ne_configurations", confs).Strs("dns_proxies_enabled", proxies)
	vpns, code := listVPNServicesFn()
	e.Str("vpn_services_status", code).Strs("vpn_services", vpns)
	kexts, code := listThirdPartyKextsFn()
	e.Str("kernel_extensions_status", code).Strs("kernel_extensions", kexts)
	anchors, code := listPFAnchorsFn()
	e.Str("pf_anchors_status", code).Strs("pf_anchors", anchors)
	return proxies
}

// logInterceptExemptionContext logs, once per intercept start, the same host
// context a self loop report carries. A healthy host then has a baseline to
// compare with: the group number pf loaded, what the group name resolves to,
// and which network extensions are active.
//
// When another product's DNS proxy is enabled, it also warns once, before
// any lookup fails: that is the known trigger of a self loop, and naming it
// at start lets support see the cause without waiting for a failure.
func logInterceptExemptionContext() {
	e := journal(mainLog.Load().Info())
	proxies := addHostContext(e)
	e.Msg("DNS intercept: pf exemption context for ctrld's own traffic")
	if len(proxies) == 0 {
		return
	}
	journal(mainLog.Load().Warn()).
		Strs("dns_proxies_enabled", proxies).
		Msg("DNS intercept: another product's DNS proxy is enabled; it may send ctrld's own lookups back to ctrld, so Internal Domain and VPN DNS lookups can fail")
}
