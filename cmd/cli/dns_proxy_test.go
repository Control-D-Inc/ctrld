package cli

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/dnscache"
	"github.com/Control-D-Inc/ctrld/testhelper"
)

func Test_wildcardMatches(t *testing.T) {
	tests := []struct {
		name     string
		wildcard string
		domain   string
		match    bool
	}{
		{"domain - prefix parent should not match", "*.windscribe.com", "windscribe.com", false},
		{"domain - prefix", "*.windscribe.com", "anything.windscribe.com", true},
		{"domain - prefix not match other s", "*.windscribe.com", "example.com", false},
		{"domain - prefix not match s in name", "*.windscribe.com", "wwindscribe.com", false},
		{"domain - suffix", "suffix.*", "suffix.windscribe.com", true},
		{"domain - suffix not match other", "suffix.*", "suffix1.windscribe.com", false},
		{"domain - both", "suffix.*.windscribe.com", "suffix.anything.windscribe.com", true},
		{"domain - both not match", "suffix.*.windscribe.com", "suffix1.suffix.windscribe.com", false},
		{"domain - case-insensitive", "*.WINDSCRIBE.com", "anything.windscribe.com", true},
		{"mac - prefix", "*:98:05:b4:2b", "d4:67:98:05:b4:2b", true},
		{"mac - prefix not match other s", "*:98:05:b4:2b", "0d:ba:54:09:94:2c", false},
		{"mac - prefix not match s in name", "*:98:05:b4:2b", "e4:67:97:05:b4:2b", false},
		{"mac - suffix", "d4:67:98:*", "d4:67:98:05:b4:2b", true},
		{"mac - suffix not match other", "d4:67:98:*", "d4:67:97:15:b4:2b", false},
		{"mac - both", "d4:67:98:*:b4:2b", "d4:67:98:05:b4:2b", true},
		{"mac - both not match", "d4:67:98:*:b4:2b", "d4:67:97:05:c4:2b", false},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := wildcardMatches(tc.wildcard, tc.domain); got != tc.match {
				t.Errorf("unexpected result, wildcard: %s, domain: %s, want: %v, got: %v", tc.wildcard, tc.domain, tc.match, got)
			}
		})
	}
}

func Test_canonicalName(t *testing.T) {
	tests := []struct {
		name      string
		domain    string
		canonical string
	}{
		{"fqdn to canonical", "windscribe.com.", "windscribe.com"},
		{"already canonical", "windscribe.com", "windscribe.com"},
		{"case insensitive", "Windscribe.Com.", "windscribe.com"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := canonicalName(tc.domain); got != tc.canonical {
				t.Errorf("unexpected result, want: %s, got: %s", tc.canonical, got)
			}
		})
	}
}

func Test_prog_upstreamFor(t *testing.T) {
	cfg := testhelper.SampleConfig(t)
	cfg.Service.LeakOnUpstreamFailure = func(v bool) *bool { return &v }(false)
	p := &prog{cfg: cfg}
	p.logger.Store(mainLog.Load())
	p.um = newUpstreamMonitor(p.cfg, mainLog.Load())
	p.lanLoopGuard = newLoopGuard()
	p.ptrLoopGuard = newLoopGuard()
	for _, nc := range p.cfg.Network {
		for _, cidr := range nc.Cidrs {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				t.Fatal(err)
			}
			nc.IPNets = append(nc.IPNets, ipNet)
		}
	}

	tests := []struct {
		name               string
		ip                 string
		mac                string
		defaultUpstreamNum string
		lc                 *ctrld.ListenerConfig
		domain             string
		upstreams          []string
		matched            bool
		testLogMsg         string
	}{
		{"Policy map matches", "192.168.0.1:0", "", "0", p.cfg.Listener["0"], "abc.xyz", []string{"upstream.1", "upstream.0"}, true, ""},
		{"Policy split matches", "192.168.0.1:0", "", "0", p.cfg.Listener["0"], "abc.ru", []string{"upstream.1"}, true, ""},
		{"Policy map for other network matches", "192.168.1.2:0", "", "0", p.cfg.Listener["0"], "abc.xyz", []string{"upstream.0"}, true, ""},
		{"No policy map for listener", "192.168.1.2:0", "", "1", p.cfg.Listener["1"], "abc.ru", []string{"upstream.1"}, false, ""},
		{"unenforced loging", "192.168.1.2:0", "", "0", p.cfg.Listener["0"], "abc.ru", []string{"upstream.1"}, true, "My Policy, network.1 (unenforced), *.ru -> [upstream.1]"},
		{"Policy Macs matches upper", "192.168.0.1:0", "14:45:A0:67:83:0A", "0", p.cfg.Listener["0"], "abc.xyz", []string{"upstream.2"}, true, "14:45:a0:67:83:0a"},
		{"Policy Macs matches lower", "192.168.0.1:0", "14:54:4a:8e:08:2d", "0", p.cfg.Listener["0"], "abc.xyz", []string{"upstream.2"}, true, "14:54:4a:8e:08:2d"},
		{"Policy Macs matches case-insensitive", "192.168.0.1:0", "14:54:4A:8E:08:2D", "0", p.cfg.Listener["0"], "abc.xyz", []string{"upstream.2"}, true, "14:54:4a:8e:08:2d"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, network := range []string{"udp", "tcp"} {
				var (
					addr net.Addr
					err  error
				)
				switch network {
				case "udp":
					addr, err = net.ResolveUDPAddr(network, tc.ip)
				case "tcp":
					addr, err = net.ResolveTCPAddr(network, tc.ip)
				}
				require.NoError(t, err)
				require.NotNil(t, addr)
				ctx := context.WithValue(context.Background(), ctrld.ReqIdCtxKey{}, requestID())
				ufr := p.upstreamFor(ctx, tc.defaultUpstreamNum, tc.lc, addr, tc.mac, tc.domain)
				p.proxy(ctx, &proxyRequest{
					msg: newDnsMsgWithHostname("foo", dns.TypeA),
					ufr: ufr,
				})
				assert.Equal(t, tc.matched, ufr.matched)
				assert.Equal(t, tc.upstreams, ufr.upstreams)
				if tc.testLogMsg != "" {
					assert.Contains(t, logOutput.String(), tc.testLogMsg)
				}
			}
		})
	}
}

func TestCache(t *testing.T) {
	cfg := testhelper.SampleConfig(t)
	prog := &prog{cfg: cfg}
	prog.logger.Store(mainLog.Load())
	for _, nc := range prog.cfg.Network {
		for _, cidr := range nc.Cidrs {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				t.Fatal(err)
			}
			nc.IPNets = append(nc.IPNets, ipNet)
		}
	}
	cacher, err := dnscache.NewLRUCache(4096)
	require.NoError(t, err)
	prog.cache = cacher

	msg := new(dns.Msg)
	msg.SetQuestion("example.com", dns.TypeA)
	msg.MsgHdr.RecursionDesired = true
	answer1 := new(dns.Msg)
	answer1.SetRcode(msg, dns.RcodeSuccess)

	prog.cache.Add(dnscache.NewKey(msg, "upstream.1"), dnscache.NewValue(answer1, time.Now().Add(time.Minute)))
	answer2 := new(dns.Msg)
	answer2.SetRcode(msg, dns.RcodeRefused)
	prog.cache.Add(dnscache.NewKey(msg, "upstream.0"), dnscache.NewValue(answer2, time.Now().Add(time.Minute)))

	req1 := &proxyRequest{
		msg:            msg,
		ci:             nil,
		failoverRcodes: nil,
		ufr: &upstreamForResult{
			upstreams:      []string{"upstream.1"},
			matchedPolicy:  "",
			matchedNetwork: "",
			matchedRule:    "",
			matched:        false,
		},
	}
	req2 := &proxyRequest{
		msg:            msg,
		ci:             nil,
		failoverRcodes: nil,
		ufr: &upstreamForResult{
			upstreams:      []string{"upstream.0"},
			matchedPolicy:  "",
			matchedNetwork: "",
			matchedRule:    "",
			matched:        false,
		},
	}
	got1 := prog.proxy(context.Background(), req1)
	got2 := prog.proxy(context.Background(), req2)
	assert.NotSame(t, got1, got2)
	assert.Equal(t, answer1.Rcode, got1.answer.Rcode)
	assert.Equal(t, answer2.Rcode, got2.answer.Rcode)
}

func Test_ipAndMacFromMsg(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		wantIp  bool
		mac     string
		wantMac bool
	}{
		{"has ip v4 and mac", "1.2.3.4", true, "4c:20:b8:ab:87:1b", true},
		{"has ip v6 and mac", "2606:1a40:3::1", true, "4c:20:b8:ab:87:1b", true},
		{"no ip", "1.2.3.4", false, "4c:20:b8:ab:87:1b", false},
		{"no mac", "1.2.3.4", false, "4c:20:b8:ab:87:1b", false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatal("missing IP")
			}
			hw, err := net.ParseMAC(tc.mac)
			if err != nil {
				t.Fatal(err)
			}
			m := new(dns.Msg)
			m.SetQuestion("example.com.", dns.TypeA)
			o := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
			if tc.wantMac {
				ec1 := &dns.EDNS0_LOCAL{Code: EDNS0_OPTION_MAC, Data: hw}
				o.Option = append(o.Option, ec1)
			}
			if tc.wantIp {
				ec2 := &dns.EDNS0_SUBNET{Address: ip}
				o.Option = append(o.Option, ec2)
			}
			m.Extra = append(m.Extra, o)
			gotIP, gotMac := ipAndMacFromMsg(m)
			if tc.wantMac && gotMac != tc.mac {
				t.Errorf("mismatch, want: %q, got: %q", tc.mac, gotMac)
			}
			if !tc.wantMac && gotMac != "" {
				t.Errorf("unexpected mac: %q", gotMac)
			}
			if tc.wantIp && gotIP != tc.ip {
				t.Errorf("mismatch, want: %q, got: %q", tc.ip, gotIP)
			}
			if !tc.wantIp && gotIP != "" {
				t.Errorf("unexpected ip: %q", gotIP)
			}
		})
	}
}

func Test_remoteAddrFromMsg(t *testing.T) {
	loopbackIP := net.ParseIP("127.0.0.1")
	tests := []struct {
		name string
		addr net.Addr
		ci   *ctrld.ClientInfo
		want string
	}{
		{"tcp", &net.TCPAddr{IP: loopbackIP, Port: 12345}, &ctrld.ClientInfo{IP: "192.168.1.10"}, "192.168.1.10:12345"},
		{"udp", &net.UDPAddr{IP: loopbackIP, Port: 12345}, &ctrld.ClientInfo{IP: "192.168.1.11"}, "192.168.1.11:12345"},
		{"nil client info", &net.UDPAddr{IP: loopbackIP, Port: 12345}, nil, "127.0.0.1:12345"},
		{"empty ip", &net.UDPAddr{IP: loopbackIP, Port: 12345}, &ctrld.ClientInfo{}, "127.0.0.1:12345"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			addr := spoofRemoteAddr(tc.addr, tc.ci)
			if addr.String() != tc.want {
				t.Errorf("unexpected result, want: %q, got: %q", tc.want, addr.String())
			}
		})
	}
}

func Test_ipFromARPA(t *testing.T) {
	tests := []struct {
		IP   string
		ARPA string
	}{
		{"1.2.3.4", "4.3.2.1.in-addr.arpa."},
		{"245.110.36.114", "114.36.110.245.in-addr.arpa."},
		{"::ffff:12.34.56.78", "78.56.34.12.in-addr.arpa."},
		{"::1", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa."},
		{"1::", "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.ip6.arpa."},
		{"1234:567::89a:bcde", "e.d.c.b.a.9.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.6.5.0.4.3.2.1.ip6.arpa."},
		{"1234:567:fefe:bcbc:adad:9e4a:89a:bcde", "e.d.c.b.a.9.8.0.a.4.e.9.d.a.d.a.c.b.c.b.e.f.e.f.7.6.5.0.4.3.2.1.ip6.arpa."},
		{"", "asd.in-addr.arpa."},
		{"", "asd.ip6.arpa."},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.IP, func(t *testing.T) {
			t.Parallel()
			if got := ipFromARPA(tc.ARPA); !got.Equal(net.ParseIP(tc.IP)) {
				t.Errorf("unexpected ip, want: %s, got: %s", tc.IP, got)
			}
		})
	}
}

func newDnsMsgWithClientIP(ip string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	o := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	o.Option = append(o.Option, &dns.EDNS0_SUBNET{Address: net.ParseIP(ip)})
	m.Extra = append(m.Extra, o)
	return m
}

func Test_stripClientSubnet(t *testing.T) {
	tests := []struct {
		name       string
		msg        *dns.Msg
		wantSubnet bool
	}{
		{"no edns0", new(dns.Msg), false},
		{"loopback IP v4", newDnsMsgWithClientIP("127.0.0.1"), false},
		{"loopback IP v6", newDnsMsgWithClientIP("::1"), false},
		{"private IP v4", newDnsMsgWithClientIP("192.168.1.123"), false},
		{"private IP v6", newDnsMsgWithClientIP("fd12:3456:789a:1::1"), false},
		{"public IP", newDnsMsgWithClientIP("1.1.1.1"), true},
		{"invalid IP", newDnsMsgWithClientIP(""), true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			stripClientSubnet(tc.msg)
			hasSubnet := false
			if opt := tc.msg.IsEdns0(); opt != nil {
				for _, s := range opt.Option {
					if _, ok := s.(*dns.EDNS0_SUBNET); ok {
						hasSubnet = true
					}
				}
			}
			if tc.wantSubnet != hasSubnet {
				t.Errorf("unexpected result, want: %v, got: %v", tc.wantSubnet, hasSubnet)
			}
		})
	}
}

func newDnsMsgWithHostname(hostname string, typ uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(hostname, typ)
	return m
}

func Test_isLanHostnameQuery(t *testing.T) {
	tests := []struct {
		name               string
		msg                *dns.Msg
		isLanHostnameQuery bool
	}{
		{"A", newDnsMsgWithHostname("foo", dns.TypeA), true},
		{"AAAA", newDnsMsgWithHostname("foo", dns.TypeAAAA), true},
		{"A not LAN", newDnsMsgWithHostname("example.com", dns.TypeA), false},
		{"AAAA not LAN", newDnsMsgWithHostname("example.com", dns.TypeAAAA), false},
		{"Not A or AAAA", newDnsMsgWithHostname("foo", dns.TypeTXT), false},
		{".domain", newDnsMsgWithHostname("foo.domain", dns.TypeA), true},
		{".lan", newDnsMsgWithHostname("foo.lan", dns.TypeA), true},
		{".local", newDnsMsgWithHostname("foo.local", dns.TypeA), true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isLanHostnameQuery(tc.msg); tc.isLanHostnameQuery != got {
				t.Errorf("unexpected result, want: %v, got: %v", tc.isLanHostnameQuery, got)
			}
		})
	}
}

func newDnsMsgPtr(ip string, t *testing.T) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	ptr, err := dns.ReverseAddr(ip)
	if err != nil {
		t.Fatal(err)
	}
	m.SetQuestion(ptr, dns.TypePTR)
	return m
}

func Test_isPrivatePtrLookup(t *testing.T) {
	tests := []struct {
		name               string
		msg                *dns.Msg
		isPrivatePtrLookup bool
	}{
		// RFC 1918 allocates 10.0.0.0/8, 172.16.0.0/12, and 192.168.0.0/16 as
		{"10.0.0.0/8", newDnsMsgPtr("10.0.0.123", t), true},
		{"172.16.0.0/12", newDnsMsgPtr("172.16.0.123", t), true},
		{"192.168.0.0/16", newDnsMsgPtr("192.168.1.123", t), true},
		{"CGNAT", newDnsMsgPtr("100.66.27.28", t), true},
		{"Loopback", newDnsMsgPtr("127.0.0.1", t), true},
		{"Link Local Unicast", newDnsMsgPtr("fe80::69f6:e16e:8bdb:433f", t), true},
		{"Public IP", newDnsMsgPtr("8.8.8.8", t), false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isPrivatePtrLookup(tc.msg); tc.isPrivatePtrLookup != got {
				t.Errorf("unexpected result, want: %v, got: %v", tc.isPrivatePtrLookup, got)
			}
		})
	}
}

func Test_isSrvLanLookup(t *testing.T) {
	tests := []struct {
		name        string
		msg         *dns.Msg
		isSrvLookup bool
	}{
		{"SRV LAN", newDnsMsgWithHostname("foo", dns.TypeSRV), true},
		{"Not SRV", newDnsMsgWithHostname("foo", dns.TypeNone), false},
		{"Not SRV LAN", newDnsMsgWithHostname("controld.com", dns.TypeSRV), false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isSrvLanLookup(tc.msg); tc.isSrvLookup != got {
				t.Errorf("unexpected result, want: %v, got: %v", tc.isSrvLookup, got)
			}
		})
	}
}

func Test_isWanClient(t *testing.T) {
	tests := []struct {
		name        string
		addr        net.Addr
		isWanClient bool
	}{
		// RFC 1918 allocates 10.0.0.0/8, 172.16.0.0/12, and 192.168.0.0/16 as
		{"10.0.0.0/8", &net.UDPAddr{IP: net.ParseIP("10.0.0.123")}, false},
		{"172.16.0.0/12", &net.UDPAddr{IP: net.ParseIP("172.16.0.123")}, false},
		{"192.168.0.0/16", &net.UDPAddr{IP: net.ParseIP("192.168.1.123")}, false},
		{"CGNAT", &net.UDPAddr{IP: net.ParseIP("100.66.27.28")}, false},
		{"Loopback", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")}, false},
		{"Link Local Unicast", &net.UDPAddr{IP: net.ParseIP("fe80::69f6:e16e:8bdb:433f")}, false},
		{"Public", &net.UDPAddr{IP: net.ParseIP("8.8.8.8")}, true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isWanClient(tc.addr); tc.isWanClient != got {
				t.Errorf("unexpected result, want: %v, got: %v", tc.isWanClient, got)
			}
		})
	}
}

func Test_shouldStartRecovery(t *testing.T) {
	tests := []struct {
		name                string
		reason              RecoveryReason
		hasExistingRecovery bool
		expectedResult      bool
		description         string
	}{
		{
			name:                "network change with existing recovery",
			reason:              RecoveryReasonNetworkChange,
			hasExistingRecovery: true,
			expectedResult:      true,
			description:         "should cancel existing recovery and start new one for network change",
		},
		{
			name:                "network change without existing recovery",
			reason:              RecoveryReasonNetworkChange,
			hasExistingRecovery: false,
			expectedResult:      true,
			description:         "should start new recovery for network change",
		},
		{
			name:                "regular failure with existing recovery",
			reason:              RecoveryReasonRegularFailure,
			hasExistingRecovery: true,
			expectedResult:      false,
			description:         "should skip duplicate recovery for regular failure",
		},
		{
			name:                "regular failure without existing recovery",
			reason:              RecoveryReasonRegularFailure,
			hasExistingRecovery: false,
			expectedResult:      true,
			description:         "should start new recovery for regular failure",
		},
		{
			name:                "OS failure with existing recovery",
			reason:              RecoveryReasonOSFailure,
			hasExistingRecovery: true,
			expectedResult:      false,
			description:         "should skip duplicate recovery for OS failure",
		},
		{
			name:                "OS failure without existing recovery",
			reason:              RecoveryReasonOSFailure,
			hasExistingRecovery: false,
			expectedResult:      true,
			description:         "should start new recovery for OS failure",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			p := newTestProg(t)

			// Setup existing recovery if needed
			if tc.hasExistingRecovery {
				p.recoveryCancelMu.Lock()
				p.recoveryCancel = func() {} // Mock cancel function
				p.recoveryCancelMu.Unlock()
			}

			result := p.shouldStartRecovery(tc.reason)
			assert.Equal(t, tc.expectedResult, result, tc.description)
		})
	}
}

func Test_createRecoveryContext(t *testing.T) {
	p := newTestProg(t)

	ctx, cleanup := p.createRecoveryContext()

	// Verify context is created
	assert.NotNil(t, ctx)
	assert.NotNil(t, cleanup)

	// Verify recoveryCancel is set
	p.recoveryCancelMu.Lock()
	assert.NotNil(t, p.recoveryCancel)
	p.recoveryCancelMu.Unlock()

	// Test cleanup function
	cleanup()

	// Verify recoveryCancel is cleared
	p.recoveryCancelMu.Lock()
	assert.Nil(t, p.recoveryCancel)
	p.recoveryCancelMu.Unlock()
}

func Test_prepareForRecovery(t *testing.T) {
	tests := []struct {
		name    string
		reason  RecoveryReason
		wantErr bool
	}{
		{
			name:    "regular failure",
			reason:  RecoveryReasonRegularFailure,
			wantErr: false,
		},
		{
			name:    "network change",
			reason:  RecoveryReasonNetworkChange,
			wantErr: false,
		},
		{
			name:    "OS failure",
			reason:  RecoveryReasonOSFailure,
			wantErr: false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			p := newTestProg(t)

			err := p.prepareForRecovery(tc.reason)

			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			// Verify recoveryRunning is set to true
			assert.True(t, p.recoveryRunning.Load())
		})
	}
}

func Test_completeRecovery(t *testing.T) {
	tests := []struct {
		name      string
		reason    RecoveryReason
		recovered string
		wantErr   bool
	}{
		{
			name:      "regular failure recovery",
			reason:    RecoveryReasonRegularFailure,
			recovered: "upstream1",
			wantErr:   false,
		},
		{
			name:      "network change recovery",
			reason:    RecoveryReasonNetworkChange,
			recovered: "upstream2",
			wantErr:   false,
		},
		{
			name:      "OS failure recovery",
			reason:    RecoveryReasonOSFailure,
			recovered: "upstream3",
			wantErr:   false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			p := newTestProg(t)

			err := p.completeRecovery(tc.reason, tc.recovered)

			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			// Verify recoveryRunning is set to false
			assert.False(t, p.recoveryRunning.Load())
		})
	}
}

func Test_reinitializeOSResolver(t *testing.T) {
	p := newTestProg(t)

	err := p.reinitializeOSResolver("Test message")

	// This function should not return an error under normal circumstances
	// The actual behavior depends on the OS resolver implementation
	assert.NoError(t, err)
}

func Test_handleRecovery_Integration(t *testing.T) {
	tests := []struct {
		name    string
		reason  RecoveryReason
		wantErr bool
	}{
		{
			name:    "network change recovery",
			reason:  RecoveryReasonNetworkChange,
			wantErr: false,
		},
		{
			name:    "regular failure recovery",
			reason:  RecoveryReasonRegularFailure,
			wantErr: false,
		},
		{
			name:    "OS failure recovery",
			reason:  RecoveryReasonOSFailure,
			wantErr: false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			p := newTestProg(t)

			// This is an integration test that exercises the full recovery flow
			// In a real test environment, you would mock the dependencies
			// For now, we're just testing that the method doesn't panic
			// and that the recovery logic flows correctly
			assert.NotPanics(t, func() {
				// Test only the preparation phase to avoid actual upstream checking
				if !p.shouldStartRecovery(tc.reason) {
					return
				}

				_, cleanup := p.createRecoveryContext()
				defer cleanup()

				if err := p.prepareForRecovery(tc.reason); err != nil {
					return
				}

				// Skip the actual upstream recovery check for this test
				// as it requires properly configured upstreams
			})
		})
	}
}

// newTestProg creates a properly initialized *prog for testing.
func newTestProg(t *testing.T) *prog {
	p := &prog{cfg: testhelper.SampleConfig(t)}
	p.logger.Store(mainLog.Load())
	p.um = newUpstreamMonitor(p.cfg, mainLog.Load())
	return p
}
