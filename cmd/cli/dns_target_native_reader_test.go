package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const nativeTargetTestServiceID = "22222222-2222-2222-2222-222222222222"
const nativeTargetOtherServiceID = "11111111-1111-1111-1111-111111111111"

func nativeTargetTestGlobal(id, device string) string {
	return fmt.Sprintf("<dictionary> {\n  PrimaryInterface : %s\n  PrimaryService : %s\n  Router : 192.0.0.1\n}", device, id)
}

func nativeTargetTestState() string {
	return "<dictionary> {\n  CLAT46 : TRUE\n  InterfaceName : en1\n  Router : 192.0.0.1\n  Addresses : <array> {\n    0 : 192.0.0.2\n  }\n}"
}

func nativeTargetTestAddrs(ips ...string) []net.Addr {
	var out []net.Addr
	for _, s := range ips {
		ip, n, err := net.ParseCIDR(s)
		if err != nil {
			panic(err)
		}
		n.IP = ip
		out = append(out, n)
	}
	return out
}

func nativeTargetTestReader(t *testing.T, outputs []string, calls *[]string) nativeTargetReader {
	t.Helper()
	return nativeTargetReader{
		run: func(ctx context.Context, input, path string, args ...string) ([]byte, error) {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if path == "/usr/sbin/networksetup" && slices.Equal(args, []string{"-listnetworkserviceorder"}) && input == "" {
				input = "networksetup -listnetworkserviceorder"
			} else if path != "/usr/sbin/scutil" || len(args) != 0 {
				t.Fatalf("unexpected command %q %v", path, args)
			}
			*calls = append(*calls, input)
			if len(*calls) > len(outputs) {
				t.Fatalf("unexpected read: %q", input)
			}
			return []byte(outputs[len(*calls)-1]), nil
		},
		interfaceByName: func(name string) (*net.Interface, error) { return &net.Interface{Name: name, Flags: net.FlagUp}, nil },
		interfaceAddrs: func(*net.Interface) ([]net.Addr, error) {
			return nativeTargetTestAddrs("192.0.0.2/32", "2001:db8::1/64"), nil
		},
	}
}

func nativeTargetTestOutputs() []string {
	global := nativeTargetTestGlobal(nativeTargetTestServiceID, "en1")
	return []string{global, nativeTargetTestState(), "<dictionary> {\n  UserDefinedName : Primary Wi-Fi\n}", nativeTargetTestServiceOrder("Primary Wi-Fi", "en1"), global}
}

func TestNativeTargetReaderIdentityAndEvidence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*nativeTargetReader, []string)
		want   bool
	}{
		{name: "primary UUID exact service", want: true},
		{name: "matching native name does not disambiguate another service on same device", want: false, change: func(_ *nativeTargetReader, out []string) {
			out[3] += "(2) Secondary Wi-Fi\n(Hardware Port: Wi-Fi, Device: en1)\n"
		}},
		{name: "ULA with native proof", want: true, change: func(r *nativeTargetReader, _ []string) {
			r.interfaceAddrs = func(*net.Interface) ([]net.Addr, error) {
				return nativeTargetTestAddrs("192.0.0.2/32", "fd12:3456::1/64"), nil
			}
		}},
		{name: "ULA without native proof", change: func(_ *nativeTargetReader, out []string) { out[1] = strings.Replace(out[1], "TRUE", "FALSE", 1) }},
		{name: "down interface", change: func(r *nativeTargetReader, _ []string) {
			r.interfaceByName = func(name string) (*net.Interface, error) { return &net.Interface{Name: name}, nil }
		}},
		{name: "missing interface", change: func(r *nativeTargetReader, _ []string) {
			r.interfaceByName = func(string) (*net.Interface, error) { return nil, errors.New("gone") }
		}},
		{name: "address error", change: func(r *nativeTargetReader, _ []string) {
			r.interfaceAddrs = func(*net.Interface) ([]net.Addr, error) { return nil, errors.New("gone") }
		}},
		{name: "ordinary IPv4", change: func(r *nativeTargetReader, _ []string) {
			r.interfaceAddrs = func(*net.Interface) ([]net.Addr, error) {
				return nativeTargetTestAddrs("192.0.0.2/32", "2001:db8::1/64", "10.0.0.2/24"), nil
			}
		}},
		{name: "published address mismatch", change: func(_ *nativeTargetReader, out []string) {
			out[1] = strings.Replace(out[1], "192.0.0.2", "192.0.0.5", 1)
		}},
		{name: "wrong device", change: func(_ *nativeTargetReader, out []string) {
			out[0] = nativeTargetTestGlobal(nativeTargetTestServiceID, "en9")
		}},
		{name: "wrong service device", change: func(_ *nativeTargetReader, out []string) { out[1] = strings.Replace(out[1], "en1", "en9", 1) }},
		{name: "invalid UUID", change: func(_ *nativeTargetReader, out []string) { out[0] = nativeTargetTestGlobal("untrusted", "en1") }},
		{name: "primary changed", change: func(_ *nativeTargetReader, out []string) {
			out[4] = nativeTargetTestGlobal(nativeTargetOtherServiceID, "en1")
		}},
		{name: "missing name", change: func(_ *nativeTargetReader, out []string) { out[2] = "No such key" }},
		{name: "DHCP embedded dictionary", change: func(_ *nativeTargetReader, out []string) { out[1] = "DHCPPacket : " + out[1] }},
		{name: "SSID embedded name", change: func(_ *nativeTargetReader, out []string) {
			out[2] = "<dictionary> {\n  SSID : network\n  UserDefinedName : Primary Wi-Fi\n}"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := nativeTargetTestOutputs()
			var calls []string
			r := nativeTargetTestReader(t, out, &calls)
			if tc.change != nil {
				tc.change(&r, out)
			}
			got, err := r.defaultService(context.Background(), "en1")
			if (got.ID != "" && err == nil) != tc.want {
				t.Fatalf("service=%+v err=%v calls=%v", got, err, calls)
			}
			if tc.want {
				want := nativeTargetService{ID: nativeTargetTestServiceID, Name: "Primary Wi-Fi", Device: "en1"}
				if got != want {
					t.Fatalf("got %+v want %+v", got, want)
				}
				wantCalls := []string{"show State:/Network/Global/IPv4\nquit\n", "show State:/Network/Service/" + nativeTargetTestServiceID + "/IPv4\nquit\n", "show Setup:/Network/Service/" + nativeTargetTestServiceID + "\nquit\n", "networksetup -listnetworkserviceorder", "show State:/Network/Global/IPv4\nquit\n"}
				if !slices.Equal(calls, wantCalls) {
					t.Fatalf("calls=%v", calls)
				}
			}
		})
	}
}

func TestNativeTargetReaderFailuresAndSharedBudget(t *testing.T) {
	for failAt := 1; failAt <= 5; failAt++ {
		t.Run(fmt.Sprint(failAt), func(t *testing.T) {
			var calls []string
			r := nativeTargetTestReader(t, nativeTargetTestOutputs(), &calls)
			run := r.run
			count := 0
			r.run = func(ctx context.Context, input, path string, args ...string) ([]byte, error) {
				count++
				if count == failAt {
					return nil, errors.New("read failed")
				}
				return run(ctx, input, path, args...)
			}
			if got, err := r.defaultService(context.Background(), "en1"); got.ID != "" || err == nil || count != failAt {
				t.Fatalf("got=%v err=%v count=%d", got, err, count)
			}
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var calls []string
	r := nativeTargetTestReader(t, nativeTargetTestOutputs(), &calls)
	run := r.run
	r.run = func(actual context.Context, input, path string, args ...string) ([]byte, error) {
		if actual != ctx {
			t.Fatal("reader renewed the shared context")
		}
		out, err := run(actual, input, path, args...)
		if len(calls) == 2 {
			cancel()
		}
		return out, err
	}
	if got, err := r.defaultService(ctx, "en1"); got.ID != "" || !errors.Is(err, context.Canceled) {
		t.Fatalf("got=%v err=%v", got, err)
	}
	if len(calls) != 2 {
		t.Fatalf("reads after cancellation: %v", calls)
	}
}

func TestNativeServiceNameStrict(t *testing.T) {
	for _, name := range []string{"Wi-Fi", "iPhone USB", "Office : Wi-Fi", "Téléphone", "Wi-Fi ", " Wi-Fi"} {
		got, err := parseNativeServiceName("<dictionary> {\n  UserDefinedName : " + name + "\n}")
		if err != nil || got != name {
			t.Fatalf("%q: %q %v", name, got, err)
		}
	}
	for _, out := range []string{"", "No such key", "<dictionary> {\n  UserDefinedName : \n}", "<dictionary> {\n  UserDefinedName : Wi-Fi\n  UserDefinedName : Evil\n}", "<dictionary> {\n  DHCPPacket : <dictionary> {\n  UserDefinedName : Evil\n}\n}", "<dictionary> {\n  UserDefinedName : ../bad\n}"} {
		if _, err := parseNativeServiceName(out); err == nil {
			t.Fatalf("accepted %q", out)
		}
	}
}

// Exercise the real exec runner without macOS tools or host network effects.
func TestNativeTargetCommandHelper(t *testing.T) {
	i := slices.Index(os.Args, "--native-target-helper")
	if i < 0 {
		return
	}
	switch os.Args[i+1] {
	case "large":
		_, _ = os.Stdout.Write([]byte(strings.Repeat("x", nativeTargetMaxOutput+1)))
	case "exact":
		_, _ = os.Stdout.Write([]byte(strings.Repeat("x", nativeTargetMaxOutput)))
	case "slow":
		time.Sleep(10 * time.Second)
	case "fail":
		fmt.Print("<dictionary> {}")
		os.Exit(1)
	default:
		fmt.Print("ok")
	}
	os.Exit(0)
}

func TestNativeTargetCommandBounds(t *testing.T) {
	for _, mode := range []string{"ok", "exact", "large", "slow", "fail"} {
		t.Run(mode, func(t *testing.T) {
			budget := 3 * time.Second
			if mode == "slow" {
				budget = 100 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), budget)
			defer cancel()
			start := time.Now()
			out, err := runNativeTargetCommand(ctx, "", os.Args[0], "-test.run=^TestNativeTargetCommandHelper$", "--", "--native-target-helper", mode)
			if mode == "ok" || mode == "exact" {
				want := 2
				if mode == "exact" {
					want = nativeTargetMaxOutput
				}
				if err != nil || len(out) != want {
					t.Fatalf("len=%d err=%v", len(out), err)
				}
			} else if err == nil || out != nil {
				t.Fatalf("accepted incomplete evidence len=%d err=%v", len(out), err)
			}
			if time.Since(start) > budget+2*time.Second {
				t.Fatal("command exceeded deadline slack")
			}
		})
	}
	var out nativeTargetOutput
	if _, err := out.Write([]byte(strings.Repeat("x", nativeTargetMaxOutput))); err != nil {
		t.Fatal(err)
	}
	if _, err := out.Write([]byte("x")); !errors.Is(err, errNativeTargetOutputLimit) || out.buf.Len() != nativeTargetMaxOutput {
		t.Fatalf("unbounded writer: %d %v", out.buf.Len(), err)
	}
}

func TestSaveTargetStaticDNSSnapshotRetainedBackup(t *testing.T) {
	for _, content := range []string{"", "2001:db8::53", "corrupt", "10.0.0.53"} {
		t.Run(content, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "backup")
			if err := os.WriteFile(path, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			err := saveTargetStaticDNSSnapshot(path, []string{"10.0.0.53"}, "10.0.0.53")
			wantErr := content == "corrupt" || content == "10.0.0.53"
			if (err != nil) != wantErr {
				t.Fatalf("retained %q: %v", content, err)
			}
			if got, readErr := os.ReadFile(path); readErr != nil || string(got) != content {
				t.Fatalf("retained backup changed: %q %v", got, readErr)
			}
		})
	}
	if err := saveTargetStaticDNSSnapshot(t.TempDir(), []string{"10.0.0.53"}, "10.0.0.53"); err == nil {
		t.Fatal("unreadable retained backup accepted")
	}
	if err := saveTargetStaticDNSSnapshot(filepath.Join(t.TempDir(), "missing"), []string{"10.0.0.53"}, "10.0.0.53"); err != nil {
		t.Fatal("original automatic DNS rejected", err)
	}
}

func TestSaveTargetStaticDNSSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "backup")
	original := "2001:db8::53"
	if err := saveTargetStaticDNSSnapshot(path, []string{original}, ""); err != nil {
		t.Fatal(err)
	}
	if err := saveTargetStaticDNSSnapshot(path, []string{"10.0.0.53"}, "10.0.0.53"); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != original {
		t.Fatalf("owned value replaced original: %q %v", got, err)
	}
	if err := saveTargetStaticDNSSnapshot(path, []string{"bad"}, ""); err == nil {
		t.Fatal("invalid snapshot accepted")
	}
	if err := saveTargetStaticDNSSnapshot(path, nil, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("empty snapshot left stale backup")
	}
	if err := saveTargetStaticDNSSnapshot(path, nil, ""); err != nil {
		t.Fatal("missing backup removal should succeed", err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "block"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := saveTargetStaticDNSSnapshot(path, nil, ""); err == nil {
		t.Fatal("remove failure swallowed")
	}
	if err := saveTargetStaticDNSSnapshot(path, []string{original}, ""); err == nil {
		t.Fatal("write failure swallowed")
	}
}
