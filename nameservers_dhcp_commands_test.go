package ctrld

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"slices"
	"testing"
	"time"
)

func TestDHCPNameserversCommandFallback(t *testing.T) {
	for _, tc := range []struct {
		name, option, packet string
		optionErr, packetErr error
		want                 []string
		calls                int
		wantErr              bool
	}{
		{name: "option", option: "192.0.2.53\n", want: []string{"192.0.2.53"}, calls: 1},
		{name: "empty option", calls: 1},
		{name: "packet", optionErr: errors.New("exit 1"), packet: "domain_name_server (ip_mult): {192.0.2.53, 192.0.2.54}", want: []string{"192.0.2.53", "192.0.2.54"}, calls: 2},
		{name: "empty packet", optionErr: errors.New("exit 1"), calls: 2},
		{name: "both fail", optionErr: errors.New("exit 1"), packetErr: errors.New("exit 1"), calls: 2, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			got, err := dhcpNameserversFromCommands(context.Background(), "en0", func(_ context.Context, args ...string) ([]byte, error) {
				calls++
				if calls == 1 {
					if !slices.Equal(args, []string{"getoption", "en0", "domain_name_server"}) {
						t.Fatal(args)
					}
					return []byte(tc.option), tc.optionErr
				}
				if !slices.Equal(args, []string{"getpacket", "en0"}) {
					t.Fatal(args)
				}
				return []byte(tc.packet), tc.packetErr
			})
			if calls != tc.calls || (err != nil) != tc.wantErr || !slices.Equal(got, tc.want) {
				t.Fatalf("calls=%d got=%v err=%v", calls, got, err)
			}
		})
	}
}

func TestDHCPNameserversRetainsCommandCauses(t *testing.T) {
	option, packet := &exec.ExitError{}, &exec.ExitError{}
	calls := 0
	_, err := dhcpNameserversFromCommands(context.Background(), "en0", func(context.Context, ...string) ([]byte, error) {
		calls++
		if calls == 1 {
			return nil, option
		}
		return nil, packet
	})
	var exit *exec.ExitError
	if !errors.As(err, &exit) || !errors.Is(err, option) || !errors.Is(err, packet) {
		t.Fatalf("DHCP command causes were flattened: %T: %v", err, err)
	}
}

func TestDHCPNameserversCancellation(t *testing.T) {
	for _, cancelAt := range []int{0, 1, 2} {
		ctx, cancel := context.WithCancel(context.Background())
		calls := 0
		if cancelAt == 0 {
			cancel()
		}
		got, err := dhcpNameserversFromCommands(ctx, "en0", func(received context.Context, _ ...string) ([]byte, error) {
			if received != ctx {
				t.Fatal("discovery renewed the context")
			}
			calls++
			if calls == cancelAt {
				cancel()
			}
			return nil, errors.New("unavailable")
		})
		cancel()
		if !errors.Is(err, context.Canceled) || got != nil || calls != cancelAt {
			t.Fatalf("cancel at %d: got=%v err=%v calls=%d", cancelAt, got, err, calls)
		}
	}
}

func TestDHCPCommandDeadlineHelper(t *testing.T) {
	if os.Getenv("CTRLD_DHCP_DEADLINE_HELPER") != "1" {
		return
	}
	time.Sleep(4 * time.Second)
}

func TestDHCPCommandDeadline(t *testing.T) {
	t.Setenv("CTRLD_DHCP_DEADLINE_HELPER", "1")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 750*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err = dhcpCommandOutput(ctx, exe, "-test.run=^TestDHCPCommandDeadlineHelper$")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err=%v", err)
	}
	if elapsed := time.Since(started); elapsed >= 3*time.Second {
		t.Fatalf("command ignored deadline: %v", elapsed)
	}
}
