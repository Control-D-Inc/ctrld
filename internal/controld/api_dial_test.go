package controld

import (
	"errors"
	"net"
	"slices"
	"strings"
	"syscall"
	"testing"
)

// TestJoinAttemptErrorsKeepsEveryAttempt pins the diagnosis the incident lost.
//
// The transport dials several address families in turn. The IPv4 attempt is the
// one that says "the host is blocking ctrld"; the last attempt is usually an IPv6
// address that is simply unroutable and reports "no route to host". Returning only
// the last error is what turned a self-inflicted block into a phantom routing
// problem in the logs, and sent the investigation after a network fault that did
// not exist.
func TestJoinAttemptErrorsKeepsEveryAttempt(t *testing.T) {
	blocked := &net.OpError{Op: "dial", Net: "tcp4", Err: wsaEACCES}
	unroutable := &net.OpError{Op: "dial", Net: "tcp6", Err: syscall.EHOSTUNREACH}

	err := joinAttemptErrors([]error{
		wrapAttempt("resolved ipv4", blocked),
		wrapAttempt("direct ipv6", unroutable),
	})
	if err == nil {
		t.Fatal("joinAttemptErrors() = nil for two failed attempts")
	}

	msg := err.Error()
	for _, want := range []string{"resolved ipv4", "direct ipv6"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error text does not name the %q attempt: %s", want, msg)
		}
	}
	if !errors.Is(err, wsaEACCES) {
		t.Errorf("the IPv4 socket denial did not survive; a caller can no longer tell a local block from a routing failure: %s", msg)
	}
	if !errors.Is(err, syscall.EHOSTUNREACH) {
		t.Errorf("the last attempt's error did not survive: %s", msg)
	}
	if strings.Contains(msg, "\n") {
		t.Errorf("the joined error spans lines, which breaks one-record-per-failure logging: %q", msg)
	}
}

// TestJoinAttemptErrorsSingleAndEmpty covers the degenerate inputs: one attempt is
// returned untouched, and no attempt at all still has to be an error rather than a
// nil the dialer would hand back as a successful connection.
func TestJoinAttemptErrorsSingleAndEmpty(t *testing.T) {
	only := errors.New("only attempt")
	if got := joinAttemptErrors([]error{only}); !errors.Is(got, only) {
		t.Errorf("joinAttemptErrors() = %v, want the single attempt unwrapped", got)
	}
	if got := joinAttemptErrors(nil); got == nil {
		t.Error("joinAttemptErrors(nil) = nil; the dialer would report success with no connection")
	}
}

// TestAPIDialStagesAlwaysDialTheDirectIPs is the guarantee the direct addresses
// exist for: when DNS is unusable, ctrld must still reach the API.
//
// Whatever resolution returns - nothing, stale addresses, one family only - every
// direct address is dialed. The only thing the duplicate trim removes is a second
// dial of an address an earlier stage already covers.
func TestAPIDialStagesAlwaysDialTheDirectIPs(t *testing.T) {
	const (
		directV4 = apiDomainComIPv4
		directV6 = apiDomainComIPv6
	)
	v4, v6 := []string{directV4}, []string{directV6}

	tests := []struct {
		name     string
		resolved []string
	}{
		{"resolution returned nothing", nil},
		{"resolution returned the direct ips", []string{directV4, directV6}},
		{"resolution returned stale ips", []string{"203.0.113.10", "2001:db8::1"}},
		{"resolution returned ipv4 only", []string{"203.0.113.10"}},
		{"resolution returned ipv6 only", []string{"2001:db8::1"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stages := apiDialStages(tt.resolved, v4, v6)

			var dialed []string
			for _, stage := range stages {
				if len(stage.ips) == 0 {
					t.Errorf("stage %q has no address; it would dial nothing", stage.what)
				}
				dialed = append(dialed, stage.ips...)
			}
			for _, direct := range []string{directV4, directV6} {
				if !slices.Contains(dialed, direct) {
					t.Errorf("the direct address %s is never dialed; the API is unreachable without DNS", direct)
				}
				if n := count(dialed, direct); n != 1 {
					t.Errorf("the direct address %s is dialed %d times, want exactly 1", direct, n)
				}
			}
			for _, ip := range tt.resolved {
				if !slices.Contains(dialed, ip) {
					t.Errorf("the resolved address %s is never dialed", ip)
				}
			}
		})
	}
}

// TestAPIDialStagesTryIPv4First pins the order: the IPv4 stages come before the
// IPv6 ones. IPv6 at these hosts is commonly unroutable, and its "no route to
// host" is what used to be the only error a failure reported.
func TestAPIDialStagesTryIPv4First(t *testing.T) {
	stages := apiDialStages([]string{"203.0.113.10", "2001:db8::1"},
		[]string{apiDomainComIPv4}, []string{apiDomainComIPv6})

	var order []string
	for _, stage := range stages {
		order = append(order, stage.network)
	}
	want := []string{"tcp4", "tcp4", "tcp6", "tcp6"}
	if len(order) != len(want) {
		t.Fatalf("stage networks = %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("stage networks = %v, want %v", order, want)
		}
	}
}

func count(haystack []string, needle string) int {
	var n int
	for _, s := range haystack {
		if s == needle {
			n++
		}
	}
	return n
}

// TestNotInSkipsAlreadyDialedAddresses covers the duplicate-dial trim: LookupIP
// normally answers with the direct addresses, so dialing both lists doubles every
// failure for no added chance of success.
func TestNotInSkipsAlreadyDialedAddresses(t *testing.T) {
	if got := notIn([]string{apiDomainComIPv4}, []string{apiDomainComIPv4}); len(got) != 0 {
		t.Errorf("notIn() = %v, want empty: the address was already dialed", got)
	}
	if got := notIn([]string{apiDomainComIPv4}, []string{"203.0.113.10"}); len(got) != 1 {
		t.Errorf("notIn() = %v, want the direct address kept when it was not dialed", got)
	}
	if got := notIn([]string{apiDomainComIPv4}, nil); len(got) != 1 {
		t.Errorf("notIn() = %v, want the direct address kept when nothing resolved", got)
	}
}

// TestAPIEndpointIPsCoverEveryDialedAddress ties the Firewall Mode allowlist to the
// transport. Firewall Mode permits APIEndpointIPs; the transport dials
// apiDirectIPs. If one grows an address the other does not, ctrld starts blocking
// its own control plane again, which is precisely the 38-hour outage.
func TestAPIEndpointIPsCoverEveryDialedAddress(t *testing.T) {
	for _, dev := range []bool{false, true} {
		permitted := APIEndpointIPs(dev)
		v4, v6 := apiDirectIPs(dev)
		for _, ip := range append(append([]string{}, v4...), v6...) {
			if !slices.Contains(permitted, ip) {
				t.Errorf("cdDev=%v: the transport dials %s but APIEndpointIPs does not report it, so Firewall Mode will not permit it", dev, ip)
			}
		}
		if len(permitted) != len(v4)+len(v6) {
			t.Errorf("cdDev=%v: APIEndpointIPs = %v, but the split halves are %v/%v", dev, permitted, v4, v6)
		}
	}
}
