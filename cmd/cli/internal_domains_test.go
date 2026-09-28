package cli

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/controld"
)

// captureInternalDomainsLogs uses a test-local JSON sink so counts and privacy
// assertions inspect structured fields at their actual levels, independent of
// TestMain's console encoder and any previous test replacing mainLog. Call it
// before constructing a prog: its logger and monitor retain the selected logger.
func captureInternalDomainsLogs(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		zapcore.AddSync(buf),
		zap.DebugLevel,
	)
	old := mainLog.Load()
	mainLog.Store(&ctrld.Logger{Logger: zap.New(core)})
	t.Cleanup(func() { mainLog.Store(old) })
	return buf
}

func internalDomainsTestConfig() *ctrld.Config {
	return &ctrld.Config{
		Listener: map[string]*ctrld.ListenerConfig{"0": {Policy: &ctrld.ListenerPolicyConfig{Name: "My Policy"}}},
		Upstream: map[string]*ctrld.UpstreamConfig{"0": {Endpoint: "https://dns.controld.com/test", Type: ctrld.ResolverTypeDOH, BootstrapIP: "127.0.0.1"}},
		Network:  map[string]*ctrld.NetworkConfig{"0": {Name: "Network 0", Cidrs: []string{"0.0.0.0/0"}}},
	}
}

// ruleTargets returns the targets of the rule for source, and whether it exists.
func ruleTargets(t *testing.T, cfg *ctrld.Config, source string) ([]string, bool) {
	t.Helper()
	for _, rule := range cfg.Listener["0"].Policy.Rules {
		if targets, ok := rule[source]; ok {
			return targets, true
		}
	}
	return nil, false
}

func TestNormalizeInternalDomain(t *testing.T) {
	long63 := strings.Repeat("a", 63)
	for _, tc := range []struct{ name, in, want string }{
		// Canonicalization that cannot change which names match.
		{"plain", "aws.example.com", "aws.example.com"},
		{"case and root dot", "  AWS.Example.COM.  ", "aws.example.com"},
		{"leading wildcard", "*.aws.example.com", "aws.example.com"},
		{"surrounding control whitespace", "\r\nCORP.EXAMPLE.\r\n", "corp.example"},
		{"single label", "intranet", "intranet"},
		{"punycode", "xn--80ak6aa92e.com", "xn--80ak6aa92e.com"},
		{"digits and hyphens", "dc-01.site2.example.com", "dc-01.site2.example.com"},
		{"max label", long63 + ".example.com", long63 + ".example.com"},

		// Rejected: an empty or absent name.
		{"empty", "", ""},
		{"whitespace only", "   ", ""},
		{"root only", ".", ""},
		{"wildcard only", "*.", ""},

		// Rejected: empty labels. A leading dot is not repaired, because the
		// repaired value is a different suffix from the configured one.
		{"leading dot", ".aws.example.com.", ""},
		{"double dot", "aws..example.com", ""},
		{"trailing double dot", "aws.example.com..", ""},

		// Rejected: characters outside the ASCII hostname contract. A denylist
		// would have to name every one of these; the positive rule does not.
		{"space", "has space.com", ""},
		{"embedded wildcard", "we*rd.com", ""},
		{"slash", "a/b.com", ""},
		{"newline", "aws\nevil.example.com", ""},
		{"carriage return", "aws\revil.example.com", ""},
		{"nul", "aws\x00evil.example.com", ""},
		{"escape", "aws\x1bevil.example.com", ""},
		{"delete", "aws\x7fevil.example.com", ""},
		{"quote", "aws\"evil.example.com", ""},
		{"colon", "aws:53.example.com", ""},
		{"underscore", "_msdcs.example.com", ""},
		{"non-ascii", "exämple.com", ""},

		// Rejected: hyphen placement and length.
		{"leading hyphen", "-aws.example.com", ""},
		{"trailing hyphen", "aws-.example.com", ""},
		{"label too long", strings.Repeat("a", 64) + ".example.com", ""},
		{"name too long", strings.Repeat("a.", 127) + "example.com", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeInternalDomain(tc.in); got != tc.want {
				t.Errorf("normalizeInternalDomain(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// A rejected domain is counted and produces no rule, rather than being repaired
// into a suffix nobody configured.
func TestApplyInternalDomainsRejectsMalformedDomains(t *testing.T) {
	cfg := internalDomainsTestConfig()
	summary := applyInternalDomains(cfg, []controld.SplitDNS{
		{Domain: "aws\nevil.example.com", Mode: controld.SplitDNSModeResolvers, Resolvers: []string{"10.0.0.53"}},
		{Domain: "ok.example.com", Mode: controld.SplitDNSModeResolvers, Resolvers: []string{"10.0.0.54"}},
	})
	if summary.domains != 1 || summary.skipped != 1 {
		t.Fatalf("summary = %+v", summary)
	}
	for _, rule := range cfg.Listener["0"].Policy.Rules {
		for source := range rule {
			if strings.ContainsAny(source, "\n\r\x00") {
				t.Errorf("control character reached a policy rule: %q", source)
			}
			if source != "ok.example.com" && source != "*.ok.example.com" {
				t.Errorf("unexpected rule source %q", source)
			}
		}
	}
}

func TestInternalDomainEndpoint(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
		ok   bool
	}{
		{"10.0.0.10", "10.0.0.10:53", true},
		{" 10.0.0.11 ", "10.0.0.11:53", true},
		{"2001:db8::1", "[2001:db8::1]:53", true},
		{"10.0.0.10:5353", "10.0.0.10:5353", true},
		{"[2001:db8::1]:5353", "[2001:db8::1]:5353", true},
		{"dns.internal.example.com", "", false},
		{"10.0.0.256", "", false},
		{"", "", false},
		{"10.0.0.10:0", "", false},
		{"10.0.0.10:70000", "", false},
		{"10.0.0.10:dns", "", false},
	} {
		got, ok := internalDomainEndpoint(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("internalDomainEndpoint(%q) = %q, %v; want %q, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestApplyInternalDomainsOSResolverMode(t *testing.T) {
	cfg := internalDomainsTestConfig()
	summary := applyInternalDomains(cfg, []controld.SplitDNS{{Domain: "corp.example.com"}})

	if summary.domains != 1 || summary.osMode != 1 || summary.explicit != 0 || summary.resolvers != 0 {
		t.Fatalf("summary = %+v", summary)
	}
	for _, source := range []string{"corp.example.com", "*.corp.example.com"} {
		targets, ok := ruleTargets(t, cfg, source)
		if !ok {
			t.Fatalf("no rule for %q", source)
		}
		if len(targets) != 0 {
			t.Errorf("rule %q targets = %v, want empty (OS resolver)", source, targets)
		}
	}
	if len(cfg.Upstream) != 1 {
		t.Errorf("upstreams = %v, want only the Control D upstream", cfg.Upstream)
	}
}

func TestApplyInternalDomainsExplicitResolverMode(t *testing.T) {
	cfg := internalDomainsTestConfig()
	summary := applyInternalDomains(cfg, []controld.SplitDNS{
		{Domain: "aws.example.com", Resolvers: []string{"10.0.0.10", "2001:db8::11"}},
	})

	if summary.domains != 1 || summary.explicit != 1 || summary.osMode != 0 || summary.resolvers != 2 {
		t.Fatalf("summary = %+v", summary)
	}
	want := []string{"upstream.internal_0", "upstream.internal_1"}
	for _, source := range []string{"aws.example.com", "*.aws.example.com"} {
		targets, ok := ruleTargets(t, cfg, source)
		if !ok {
			t.Fatalf("no rule for %q", source)
		}
		if strings.Join(targets, ",") != strings.Join(want, ",") {
			t.Errorf("rule %q targets = %v, want %v (administrator order)", source, targets, want)
		}
	}
	if got := cfg.Upstream["internal_0"]; got == nil || got.Endpoint != "10.0.0.10:53" || got.Type != ctrld.ResolverTypeLegacy {
		t.Errorf("internal_0 = %+v", got)
	}
	if got := cfg.Upstream["internal_1"]; got == nil || got.Endpoint != "[2001:db8::11]:53" {
		t.Errorf("internal_1 = %+v", got)
	}
}

func TestApplyInternalDomainsMalformedResolvers(t *testing.T) {
	t.Run("drops only the malformed address", func(t *testing.T) {
		cfg := internalDomainsTestConfig()
		summary := applyInternalDomains(cfg, []controld.SplitDNS{
			{Domain: "aws.example.com", Resolvers: []string{"not-an-ip", "10.0.0.10"}},
		})
		if summary.domains != 1 || summary.resolvers != 1 || summary.skipped != 0 {
			t.Fatalf("summary = %+v", summary)
		}
		targets, _ := ruleTargets(t, cfg, "aws.example.com")
		if len(targets) != 1 || targets[0] != "upstream.internal_0" {
			t.Errorf("targets = %v", targets)
		}
	})

	t.Run("drops the entry when no address is usable", func(t *testing.T) {
		cfg := internalDomainsTestConfig()
		summary := applyInternalDomains(cfg, []controld.SplitDNS{
			{Domain: "aws.example.com", Resolvers: []string{"not-an-ip", ""}},
		})
		if summary.domains != 0 || summary.skipped != 1 {
			t.Fatalf("summary = %+v", summary)
		}
		// Falling back to the OS resolver here would silently replace the
		// administrator's explicit selection with a different one.
		if _, ok := ruleTargets(t, cfg, "aws.example.com"); ok {
			t.Error("entry with no usable resolver must not produce a rule")
		}
		if len(cfg.Upstream) != 1 {
			t.Errorf("upstreams = %v, want no generated upstream", cfg.Upstream)
		}
	})

	t.Run("drops an unusable domain", func(t *testing.T) {
		cfg := internalDomainsTestConfig()
		summary := applyInternalDomains(cfg, []controld.SplitDNS{{Domain: "  ", Resolvers: []string{"10.0.0.10"}}})
		if summary.domains != 0 || summary.skipped != 1 || len(cfg.Upstream) != 1 {
			t.Fatalf("summary = %+v, upstreams = %v", summary, cfg.Upstream)
		}
	})

	t.Run("drops a duplicate domain", func(t *testing.T) {
		cfg := internalDomainsTestConfig()
		summary := applyInternalDomains(cfg, []controld.SplitDNS{
			{Domain: "aws.example.com", Resolvers: []string{"10.0.0.10"}},
			{Domain: "AWS.Example.com.", Resolvers: []string{"10.0.0.99"}},
		})
		if summary.domains != 1 || summary.skipped != 1 {
			t.Fatalf("summary = %+v", summary)
		}
		targets, _ := ruleTargets(t, cfg, "aws.example.com")
		if len(targets) != 1 || cfg.Upstream["internal_0"].Endpoint != "10.0.0.10:53" {
			t.Errorf("first entry must win: targets = %v", targets)
		}
	})
}

// Magic Folder excludes and endpoint custom configuration are written to the
// policy before Internal Domains are applied, and must keep their routing.
func TestApplyInternalDomainsPrecedence(t *testing.T) {
	t.Run("an existing rule is never overwritten", func(t *testing.T) {
		cfg := internalDomainsTestConfig()
		cfg.Listener["0"].Policy.Rules = []ctrld.Rule{{"aws.example.com": []string{}}}
		summary := applyInternalDomains(cfg, []controld.SplitDNS{
			{Domain: "aws.example.com", Resolvers: []string{"10.0.0.10"}},
		})
		targets, _ := ruleTargets(t, cfg, "aws.example.com")
		if len(targets) != 0 {
			t.Errorf("exclude rule was overwritten: targets = %v", targets)
		}
		// The wildcard was still free, so the domain is only partly preempted.
		if wildcard, ok := ruleTargets(t, cfg, "*.aws.example.com"); !ok || len(wildcard) != 1 {
			t.Errorf("wildcard rule = %v, %v", wildcard, ok)
		}
		if summary.domains != 1 {
			t.Errorf("summary = %+v", summary)
		}
	})

	t.Run("a fully covered domain is reported as preempted", func(t *testing.T) {
		cfg := internalDomainsTestConfig()
		cfg.Listener["0"].Policy.Rules = []ctrld.Rule{
			{"aws.example.com": []string{"upstream.0"}},
			{"*.aws.example.com": []string{"upstream.0"}},
		}
		summary := applyInternalDomains(cfg, []controld.SplitDNS{
			{Domain: "aws.example.com", Resolvers: []string{"10.0.0.10"}},
		})
		if summary.domains != 0 || summary.preempted != 1 {
			t.Fatalf("summary = %+v", summary)
		}
		if len(cfg.Listener["0"].Policy.Rules) != 2 {
			t.Errorf("rules = %v, want no addition", cfg.Listener["0"].Policy.Rules)
		}
	})
}

// A configured suffix must route itself and its subdomains, and nothing else.
func TestApplyInternalDomainsSuffixMatching(t *testing.T) {
	cfg := internalDomainsTestConfig()
	applyInternalDomains(cfg, []controld.SplitDNS{
		{Domain: "aws.example.com", Resolvers: []string{"10.0.0.10"}},
		{Domain: "corp.example.com"},
	})
	p := newInternalDomainsProg(t, cfg)
	addr, err := net.ResolveUDPAddr("udp", "192.168.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		domain string
		want   []string
	}{
		{"aws.example.com", []string{"upstream.internal_0"}},
		{"host.aws.example.com", []string{"upstream.internal_0"}},
		{"a.b.c.aws.example.com", []string{"upstream.internal_0"}},
		{"corp.example.com", []string{}},
		{"host.corp.example.com", []string{}},
		{"example.com", []string{"upstream.0"}},
		{"notaws.example.com", []string{"upstream.0"}},
		{"aws.example.com.evil.test", []string{"upstream.0"}},
	} {
		ufr := p.upstreamFor(context.Background(), "0", cfg.Listener["0"], addr, "", tc.domain)
		if strings.Join(ufr.upstreams, ",") != strings.Join(tc.want, ",") {
			t.Errorf("upstreamFor(%q) = %v, want %v", tc.domain, ufr.upstreams, tc.want)
		}
	}
}

// A refresh rebuilds the generated config, so a removal must leave no rule and
// no upstream behind.
func TestApplyInternalDomainsAuthoritativeReplacement(t *testing.T) {
	first := internalDomainsTestConfig()
	applyInternalDomains(first, []controld.SplitDNS{
		{Domain: "aws.example.com", Resolvers: []string{"10.0.0.10"}},
		{Domain: "old.example.com", Resolvers: []string{"10.0.0.20"}},
	})
	if len(first.Upstream) != 3 {
		t.Fatalf("upstreams = %v", first.Upstream)
	}

	// The refresh path regenerates cfg from the API response rather than
	// mutating the previous one.
	second := internalDomainsTestConfig()
	summary := applyInternalDomains(second, []controld.SplitDNS{
		{Domain: "aws.example.com", Resolvers: []string{"10.0.0.99"}},
	})
	if summary.domains != 1 || summary.resolvers != 1 {
		t.Fatalf("summary = %+v", summary)
	}
	if _, ok := ruleTargets(t, second, "old.example.com"); ok {
		t.Error("removed domain left a stale rule")
	}
	if len(second.Upstream) != 2 {
		t.Errorf("upstreams = %v, want the Control D upstream plus one internal", second.Upstream)
	}
	if second.Upstream["internal_0"].Endpoint != "10.0.0.99:53" {
		t.Errorf("resolver change not applied: %+v", second.Upstream["internal_0"])
	}
}

func TestApplyInternalDomainsEmpty(t *testing.T) {
	for _, entries := range [][]controld.SplitDNS{nil, {}} {
		cfg := internalDomainsTestConfig()
		summary := applyInternalDomains(cfg, entries)
		if !summary.empty() {
			t.Errorf("summary = %+v, want empty", summary)
		}
		if len(cfg.Listener["0"].Policy.Rules) != 0 || len(cfg.Upstream) != 1 {
			t.Errorf("absent split_dns changed the config: rules=%v upstreams=%v",
				cfg.Listener["0"].Policy.Rules, cfg.Upstream)
		}
	}
}

func TestInternalDomainsEqual(t *testing.T) {
	base := []controld.SplitDNS{
		{Domain: "aws.example.com", Resolvers: []string{"10.0.0.10", "10.0.0.11"}},
		{Domain: "corp.example.com"},
	}
	for _, tc := range []struct {
		name string
		next []controld.SplitDNS
		want bool
	}{
		{"unchanged", base, true},
		{"reordered domains", []controld.SplitDNS{
			{Domain: "corp.example.com"},
			{Domain: "aws.example.com", Resolvers: []string{"10.0.0.10", "10.0.0.11"}},
		}, true},
		{"equivalent spelling", []controld.SplitDNS{
			{Domain: "AWS.Example.com.", Resolvers: []string{" 10.0.0.10 ", "10.0.0.11:53"}},
			{Domain: "*.corp.example.com"},
		}, true},
		{"resolver order changed", []controld.SplitDNS{
			{Domain: "aws.example.com", Resolvers: []string{"10.0.0.11", "10.0.0.10"}},
			{Domain: "corp.example.com"},
		}, false},
		{"resolver changed", []controld.SplitDNS{
			{Domain: "aws.example.com", Resolvers: []string{"10.0.0.10", "10.0.0.99"}},
			{Domain: "corp.example.com"},
		}, false},
		{"domain removed", base[:1], false},
		{"domain added", append(append([]controld.SplitDNS{}, base...), controld.SplitDNS{Domain: "new.example.com"}), false},
		{"mode changed to explicit", []controld.SplitDNS{
			{Domain: "aws.example.com", Resolvers: []string{"10.0.0.10", "10.0.0.11"}},
			{Domain: "corp.example.com", Resolvers: []string{"10.0.0.30"}},
		}, false},
		{"emptied", nil, false},
	} {
		if got := internalDomainsEqual(base, tc.next); got != tc.want {
			t.Errorf("%s: internalDomainsEqual = %v, want %v", tc.name, got, tc.want)
		}
	}
	if !internalDomainsEqual(nil, []controld.SplitDNS{}) {
		t.Error("nil and empty lists must compare equal")
	}
}

func TestInternalDomainExplicitUpstreams(t *testing.T) {
	for _, tc := range []struct {
		in   []string
		want bool
	}{
		{[]string{"upstream.internal_0"}, true},
		{[]string{"upstream.internal_0", "upstream.internal_1"}, true},
		{[]string{"upstream.internal_0", "upstream.0"}, false},
		{[]string{"upstream.0"}, false},
		{[]string{upstreamOS}, false},
		{nil, false},
		{[]string{}, false},
	} {
		if got := internalDomainExplicitUpstreams(tc.in); got != tc.want {
			t.Errorf("internalDomainExplicitUpstreams(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// Info and warning logs must not carry organization domain names or resolver
// addresses; those stay at debug level.
func TestInternalDomainsSummaryLogsCountsOnly(t *testing.T) {
	buf := captureInternalDomainsLogs(t)
	logger := mainLog.Load()
	logInternalDomainsSummary(logger, internalDomainsSummary{
		domains: 2, osMode: 1, explicit: 1, resolvers: 3, skipped: 1,
	})
	out := buf.String()
	for _, want := range []string{`"domains":2`, `"os_resolver":1`, `"explicit_resolver":1`, `"resolvers":3`, `"skipped":1`} {
		if !strings.Contains(out, want) {
			t.Errorf("log %q missing %q", out, want)
		}
	}
	if !strings.Contains(out, `"level":"warn"`) {
		t.Errorf("a summary with skipped entries must warn: %q", out)
	}

	mark := len(buf.String())
	logInternalDomainsSummary(logger, internalDomainsSummary{domains: 1, osMode: 1})
	if !strings.Contains(buf.String()[mark:], `"level":"info"`) {
		t.Errorf("a clean summary must be info: %q", buf.String())
	}
}

// An explicit-resolver Internal Domain must not be handed to VPN DNS split
// routing: the administrator named those resolvers, and VPN suffixes are
// auto-detected. When the named resolvers are unreachable the query fails
// instead of reaching the OS resolver.
func TestInternalDomainsBeatVPNSplitRoutingAndDoNotLeak(t *testing.T) {
	buf := captureInternalDomainsLogs(t)
	cfg := internalDomainsTestConfig()
	cfg.Service.LeakOnUpstreamFailure = func(v bool) *bool { return &v }(true)
	applyInternalDomains(cfg, []controld.SplitDNS{
		{Domain: "aws.example.com", Resolvers: []string{"127.0.0.1:1"}},
	})

	p := newInternalDomainsProg(t, cfg)
	p.vpnDNS = &vpnDNSManager{routes: map[string][]string{"example.com": {"127.0.0.1:1"}}}

	prevIntercept := dnsIntercept
	dnsIntercept = true
	t.Cleanup(func() { dnsIntercept = prevIntercept })

	addr, err := net.ResolveUDPAddr("udp", "192.168.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(ctrld.LoggerCtx(context.Background(), p.logger.Load()), ctrld.ReqIdCtxKey{}, requestID())
	ufr := p.upstreamFor(ctx, "0", cfg.Listener["0"], addr, "", "host.aws.example.com")
	if !internalDomainExplicitUpstreams(ufr.upstreams) {
		t.Fatalf("upstreams = %v, want only internal resolvers", ufr.upstreams)
	}

	// Only this call's tail describes what proxy() did here.
	before := len(buf.String())
	// A trailing dot: without it the name is not a valid wire question, and the
	// failure would prove nothing about whether a resolver was contacted.
	res := p.proxy(ctx, &proxyRequest{msg: newDnsMsgWithHostname("host.aws.example.com.", dns.TypeA), ufr: ufr})
	out := buf.String()[before:]

	if strings.Contains(out, "VPN DNS route matched") {
		t.Errorf("VPN split routing overrode an explicit Internal Domain: %s", out)
	}
	if strings.Contains(out, "Attempting query to OS resolver as a retry catch all") {
		t.Errorf("unreachable internal resolvers leaked to the OS resolver: %s", out)
	}
	if res == nil || res.answer == nil || res.answer.Rcode != dns.RcodeServerFailure {
		t.Errorf("answer = %v, want SERVFAIL", res)
	}
}

// A domain that produces no rule must produce no upstream either, or the
// generated config would carry an internal_* upstream nothing refers to.
func TestApplyInternalDomainsLeaveNoOrphanUpstreams(t *testing.T) {
	cfg := internalDomainsTestConfig()
	cfg.Listener["0"].Policy.Rules = []ctrld.Rule{
		{"aws.example.com": []string{"upstream.0"}},
		{"*.aws.example.com": []string{"upstream.0"}},
	}
	summary := applyInternalDomains(cfg, []controld.SplitDNS{
		{Domain: "aws.example.com", Resolvers: []string{"10.0.0.10", "10.0.0.11"}},
		{Domain: "ok.example.com", Resolvers: []string{"10.0.0.20"}},
	})
	if summary.preempted != 1 || summary.domains != 1 || summary.resolvers != 1 {
		t.Fatalf("summary = %+v", summary)
	}
	for key, uc := range cfg.Upstream {
		if !strings.HasPrefix(key, internalDomainUpstreamPrefix) {
			continue
		}
		if uc.Endpoint != "10.0.0.20:53" {
			t.Errorf("orphan upstream %s = %+v", key, uc)
		}
	}
	if len(cfg.Upstream) != 2 {
		t.Errorf("upstreams = %v, want the Control D upstream plus one internal", cfg.Upstream)
	}
}

// Mode is what the administrator selected, so it decides the routing. The list
// of resolvers is only read when the mode calls for it.
func TestApplyInternalDomainsModeIsAuthoritative(t *testing.T) {
	for _, tc := range []struct {
		name          string
		entry         controld.SplitDNS
		wantTargets   []string
		wantRule      bool
		wantUpstreams int
	}{
		{
			// The administrator switched back to the OS resolver; addresses the
			// previous selection left behind must not resurrect themselves.
			name:          "os mode ignores leftover resolvers",
			entry:         controld.SplitDNS{Domain: "a.example.com", Mode: controld.SplitDNSModeOS, Resolvers: []string{"10.0.0.53"}},
			wantTargets:   []string{},
			wantRule:      true,
			wantUpstreams: 1,
		},
		{
			// Explicit with nothing to be explicit about is not OS resolution.
			name:          "resolvers mode with an empty list is dropped",
			entry:         controld.SplitDNS{Domain: "a.example.com", Mode: controld.SplitDNSModeResolvers},
			wantRule:      false,
			wantUpstreams: 1,
		},
		{
			name:          "resolvers mode with only malformed addresses is dropped",
			entry:         controld.SplitDNS{Domain: "a.example.com", Mode: controld.SplitDNSModeResolvers, Resolvers: []string{"nope"}},
			wantRule:      false,
			wantUpstreams: 1,
		},
		{
			name:          "resolvers mode routes explicitly",
			entry:         controld.SplitDNS{Domain: "a.example.com", Mode: controld.SplitDNSModeResolvers, Resolvers: []string{"10.0.0.53"}},
			wantTargets:   []string{"upstream.internal_0"},
			wantRule:      true,
			wantUpstreams: 2,
		},
		{
			name:          "mode is matched case and space insensitively",
			entry:         controld.SplitDNS{Domain: "a.example.com", Mode: "  OS  ", Resolvers: []string{"10.0.0.53"}},
			wantTargets:   []string{},
			wantRule:      true,
			wantUpstreams: 1,
		},
		{
			// A mode ctrld does not know is not guessed at.
			name:          "unknown mode is dropped",
			entry:         controld.SplitDNS{Domain: "a.example.com", Mode: "forward-someday", Resolvers: []string{"10.0.0.53"}},
			wantRule:      false,
			wantUpstreams: 1,
		},
		{
			// A deployment that predates the field: the list is the only signal.
			name:          "absent mode infers explicit",
			entry:         controld.SplitDNS{Domain: "a.example.com", Resolvers: []string{"10.0.0.53"}},
			wantTargets:   []string{"upstream.internal_0"},
			wantRule:      true,
			wantUpstreams: 2,
		},
		{
			name:          "absent mode infers os",
			entry:         controld.SplitDNS{Domain: "a.example.com"},
			wantTargets:   []string{},
			wantRule:      true,
			wantUpstreams: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := internalDomainsTestConfig()
			applyInternalDomains(cfg, []controld.SplitDNS{tc.entry})
			targets, ok := ruleTargets(t, cfg, "a.example.com")
			if ok != tc.wantRule {
				t.Fatalf("rule present = %v, want %v", ok, tc.wantRule)
			}
			if ok && strings.Join(targets, ",") != strings.Join(tc.wantTargets, ",") {
				t.Errorf("targets = %v, want %v", targets, tc.wantTargets)
			}
			if len(cfg.Upstream) != tc.wantUpstreams {
				t.Errorf("upstreams = %v, want %d", cfg.Upstream, tc.wantUpstreams)
			}
		})
	}
}

// A mode change is a routing change even when the resolver list is untouched,
// so it has to reach the endpoint on the next refresh.
func TestInternalDomainsEqualTracksMode(t *testing.T) {
	explicit := []controld.SplitDNS{{Domain: "a.example.com", Mode: controld.SplitDNSModeResolvers, Resolvers: []string{"10.0.0.53"}}}
	os := []controld.SplitDNS{{Domain: "a.example.com", Mode: controld.SplitDNSModeOS, Resolvers: []string{"10.0.0.53"}}}
	if internalDomainsEqual(explicit, os) {
		t.Error("switching to the OS resolver must be detected as a change")
	}
	if internalDomainsEqual(os, explicit) {
		t.Error("switching to explicit resolvers must be detected as a change")
	}
	// An unusable entry routes nothing, so it must not look like a change.
	unusable := []controld.SplitDNS{
		{Domain: "a.example.com", Mode: controld.SplitDNSModeOS, Resolvers: []string{"10.0.0.53"}},
		{Domain: "b.example.com", Mode: "forward-someday"},
	}
	if !internalDomainsEqual(os, unusable) {
		t.Error("an entry ctrld cannot use must not read as a configuration change")
	}
}
