package cli

import (
	"regexp"
	"slices"
	"strconv"
	"strings"

	"howett.net/plist"
)

// Host context for DNS intercept problems on macOS. Each parser turns the
// output of one bounded read into product identifiers only: bundle IDs,
// categories, states and pf anchor names. No user name, VPN service name,
// server address or domain is kept.

// systemExtensionSection matches a category header of systemextensionsctl list.
var systemExtensionSection = regexp.MustCompile(`^--- com\.apple\.system_extension\.([a-z_]+)`)

// systemExtensionLine matches one extension row of systemextensionsctl list:
// enabled, active, team ID, bundle ID (version), name, [state].
var systemExtensionLine = regexp.MustCompile(`^(\*?)\s+(\*?)\s+[A-Z0-9]{10}\s+([A-Za-z0-9.\-]+)\s+\(.*\[([a-z_ ]+)\]\s*$`)

// systemExtensionCategories maps systemextensionsctl categories to short names.
var systemExtensionCategories = map[string]string{
	"network_extension":  "network",
	"endpoint_security":  "endpoint_security",
	"driver_extension":   "driver",
	"virtualization":     "virtualization",
	"file_system":        "file_system",
	"file_provider":      "file_provider",
	"audio":              "audio",
	"media":              "media",
	"accessory_setup":    "accessory_setup",
	"hid_driver":         "driver",
	"network_extension_": "network",
}

// parseSystemExtensions returns "category:bundle_id" for every activated and
// enabled system extension, and the bundle IDs of the network ones. A network
// extension (content filter, DNS proxy, VPN) can re-send ctrld's packets from
// its own socket; an endpoint security extension can block or delay them.
func parseSystemExtensions(out string) (all, network []string) {
	category := ""
	for _, line := range strings.Split(out, "\n") {
		if m := systemExtensionSection.FindStringSubmatch(line); m != nil {
			category = m[1]
			if short, ok := systemExtensionCategories[category]; ok {
				category = short
			}
			continue
		}
		m := systemExtensionLine.FindStringSubmatch(line)
		if m == nil || m[4] != "activated enabled" {
			continue
		}
		c := category
		if c == "" {
			c = "unknown"
		}
		all = append(all, c+":"+m[3])
		if c == "network" {
			network = append(network, m[3])
		}
	}
	slices.Sort(all)
	slices.Sort(network)
	return slices.Compact(all), slices.Compact(network)
}

// ncListLine matches one service of scutil --nc list. Only the status and
// the type with its provider bundle ID are kept; the service name is chosen
// by whoever set it up and can name the organization.
var ncListLine = regexp.MustCompile(`^\*?\s*\(([A-Za-z ]+)\)\s+[0-9A-F-]{36}\s.*\[([A-Za-z]+)(?::([A-Za-z0-9.\-]+))?\]\s*$`)

// parseNCList returns "type:provider:status" for each VPN service, for
// example "VPN:io.tailscale.ipn.macsys:connected".
func parseNCList(out string) []string {
	var services []string
	for _, line := range strings.Split(out, "\n") {
		m := ncListLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		provider := m[3]
		if provider == "" {
			provider = "builtin"
		}
		status := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(m[1])), " ", "_")
		services = append(services, m[2]+":"+provider+":"+status)
	}
	slices.Sort(services)
	return services
}

// neConfigurationKinds are the NEConfiguration payloads that steer traffic or
// DNS, with the name each is logged under.
var neConfigurationKinds = []struct{ key, name string }{
	{"ContentFilter", "content_filter"},
	{"DNSProxy", "dns_proxy"},
	{"DNSSettings", "dns_settings"},
	{"VPN", "vpn"},
	{"AppVPN", "app_vpn"},
	{"AlwaysOnVPN", "always_on_vpn"},
	{"RelayConfiguration", "relay"},
	{"URLFilter", "url_filter"},
}

// neProviderKeys are where an NEConfiguration names the extension that
// implements it.
var neProviderKeys = []string{"DataProviderBundleIdentifier", "PacketProviderBundleIdentifier", "NEProviderBundleIdentifier", "ProviderBundleIdentifier"}

// parseNEConfigurations reads the Network Extension configuration store
// (/Library/Preferences/com.apple.networkextension.plist, a keyed archive)
// and returns "kind:app:provider:enabled|disabled" for each configuration
// that steers traffic or DNS. This covers what system extensions miss:
// app-bundled network extensions (App Store VPNs and filters) and
// configurations installed by an MDM profile.
func parseNEConfigurations(data []byte) ([]string, string) {
	var root map[string]any
	if _, err := plist.Unmarshal(data, &root); err != nil {
		return nil, "parse_failed"
	}
	objects, _ := root["$objects"].([]any)
	if objects == nil {
		return nil, "parse_failed"
	}
	deref := func(v any) any {
		for i := 0; i < 4; i++ {
			uid, ok := v.(plist.UID)
			if !ok {
				return v
			}
			if int(uid) >= len(objects) {
				return nil
			}
			v = objects[uid]
		}
		return v
	}
	str := func(v any) string {
		s, _ := deref(v).(string)
		if s == "$null" {
			return ""
		}
		return s
	}
	var out []string
	for _, o := range objects {
		cfg, ok := o.(map[string]any)
		if !ok {
			continue
		}
		if _, isConfig := cfg["Identifier"]; !isConfig {
			continue
		}
		app := str(cfg["Application"])
		for _, kind := range neConfigurationKinds {
			payload, ok := deref(cfg[kind.key]).(map[string]any)
			if !ok {
				continue
			}
			enabled := "disabled"
			if b, _ := deref(payload["Enabled"]).(bool); b {
				enabled = "enabled"
			}
			provider := ""
			for _, nested := range []any{payload, deref(payload["Provider"]), deref(payload["Protocol"])} {
				m, ok := nested.(map[string]any)
				if !ok {
					continue
				}
				for _, k := range neProviderKeys {
					if s := str(m[k]); s != "" {
						provider = s
						break
					}
				}
				if provider != "" {
					break
				}
			}
			if app == "" && provider == "" {
				continue
			}
			out = append(out, kind.name+":"+orDash(app)+":"+orDash(provider)+":"+enabled)
		}
	}
	slices.Sort(out)
	return slices.Compact(out), "ok"
}

// enabledDNSProxies returns "app:provider" for every enabled DNS proxy
// configuration in the output of parseNEConfigurations. ctrld installs no
// Network Extension, so each one belongs to another product. macOS hands
// that product's extension the DNS traffic of every process, ctrld's own
// lookups included, and it can send them on from a socket of its own. pf's
// group exemption then no longer matches them, and in Intercept mode they
// come back to ctrld's listener (a self loop). A leftover proxy whose app
// was removed (for example by MDM) stays enabled in the store and keeps
// doing this.
func enabledDNSProxies(confs []string) []string {
	var proxies []string
	for _, c := range confs {
		rest, ok := strings.CutPrefix(c, "dns_proxy:")
		if !ok {
			continue
		}
		rest, ok = strings.CutSuffix(rest, ":enabled")
		if !ok {
			continue
		}
		proxies = append(proxies, rest)
	}
	return proxies
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// parseThirdPartyKexts returns the bundle IDs of loaded kernel extensions
// that are not Apple's, from kmutil showloaded --list-only. Older security
// and VPN products still filter traffic from a kext.
func parseThirdPartyKexts(out string) []string {
	var ids []string
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}
		if _, err := strconv.Atoi(fields[0]); err != nil {
			continue
		}
		id := fields[5]
		if strings.HasPrefix(id, "com.apple.") || !strings.Contains(id, ".") {
			continue
		}
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return slices.Compact(ids)
}

// parsePFAnchors returns the anchor names of pfctl -sA other than ctrld's.
// Another product's anchor can redirect or block port 53 before or after
// ctrld's rules.
func parsePFAnchors(out, own string) []string {
	var anchors []string
	for _, line := range strings.Split(out, "\n") {
		a := strings.TrimSpace(line)
		if a == "" || a == own || strings.HasPrefix(a, own+"/") || strings.ContainsAny(a, " \t") {
			continue
		}
		anchors = append(anchors, a)
	}
	slices.Sort(anchors)
	return slices.Compact(anchors)
}
