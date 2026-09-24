package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

const (
	// One budget covers the entire native evidence transaction, including
	// both identity/static rechecks; it is not renewed for each subprocess.
	nativeTargetReadBudget = 2 * time.Second
	nativeTargetMaxOutput  = 64 * 1024
)

var errNativeTargetOutputLimit = errors.New("native DNS evidence output exceeds limit")

type nativeTargetOutput struct{ buf bytes.Buffer }

func (w *nativeTargetOutput) Write(p []byte) (int, error) {
	if len(p) > nativeTargetMaxOutput-w.buf.Len() {
		return 0, errNativeTargetOutputLimit
	}
	return w.buf.Write(p)
}

func runNativeTargetCommand(ctx context.Context, input, path string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdin = strings.NewReader(input)
	var out nativeTargetOutput
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	// Also bound waiting for inherited pipes if a child outlives the command.
	cmd.WaitDelay = 100 * time.Millisecond
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out.buf.Bytes(), nil
}

type nativeTargetService struct {
	ID, Name, Device string
}

type nativeTargetReader struct {
	run             func(context.Context, string, string, ...string) ([]byte, error)
	interfaceByName func(string) (*net.Interface, error)
	interfaceAddrs  func(*net.Interface) ([]net.Addr, error)
}

func (r nativeTargetReader) store(ctx context.Context, key string) (map[string]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out, err := r.run(ctx, "show "+key+"\nquit\n", "/usr/sbin/scutil")
	if err != nil {
		return nil, err
	}
	return parseNativeIPv4Store(string(out))
}

// The service root contains only the configured name. Reject multiline or
// unfamiliar layouts rather than searching arbitrary DHCP/SSID/packet text.
// The UUID in the key comes exclusively from the validated Global dictionary.
func parseNativeServiceName(out string) (string, error) {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 || lines[0] != "<dictionary> {" || lines[2] != "}" {
		return "", errors.New("invalid native service dictionary")
	}
	name, ok := strings.CutPrefix(strings.TrimLeft(lines[1], " \t"), "UserDefinedName : ")
	if !ok || name == "" || strings.ContainsAny(name, "\r\n\x00/{}") {
		return "", errors.New("invalid native service name")
	}
	return name, nil
}

// defaultService returns the actual primary service, not the first service
// networksetup happens to list for the device. Unknown or changing state is
// never absence evidence. The caller must carry and recheck the whole tuple.
func (r nativeTargetReader) defaultService(ctx context.Context, device string) (nativeTargetService, error) {
	unknown := nativeTargetService{}
	before, err := r.store(ctx, "State:/Network/Global/IPv4")
	if err != nil {
		return unknown, err
	}
	id := before["PrimaryService"]
	if !nativeServiceID.MatchString(id) || before["PrimaryInterface"] != device {
		return unknown, nil
	}
	state, err := r.store(ctx, "State:/Network/Service/"+id+"/IPv4")
	if err != nil {
		return unknown, err
	}
	if state["CLAT46"] != "TRUE" || state["InterfaceName"] != device || state["Router"] != "192.0.0.1" {
		return unknown, nil
	}
	iface, err := r.interfaceByName(device)
	if err != nil {
		return unknown, err
	}
	if iface == nil || iface.Name != device || iface.Flags&net.FlagUp == 0 {
		return unknown, nil
	}
	addrs, err := r.interfaceAddrs(iface)
	if err != nil || !nativeCLATAddresses(addrs) {
		return unknown, err
	}
	published := strings.Fields(state["AddressList"])
	if len(published) != 1 {
		return unknown, nil
	}
	matched := false
	for _, addr := range addrs {
		ip, _, parseErr := net.ParseCIDR(addr.String())
		if parseErr == nil && ip.String() == published[0] {
			matched = true
		}
	}
	if !matched {
		return unknown, nil
	}
	out, err := r.run(ctx, "show Setup:/Network/Service/"+id+"\nquit\n", "/usr/sbin/scutil")
	if err != nil {
		return unknown, err
	}
	_, err = parseNativeServiceName(string(out))
	if err != nil {
		return unknown, err
	}
	out, err = r.run(ctx, "", "/usr/sbin/networksetup", "-listnetworkserviceorder")
	if err != nil {
		return unknown, err
	}
	name, err := targetNetworkServiceName(string(out), device)
	if err != nil {
		return unknown, err
	}
	after, err := r.store(ctx, "State:/Network/Global/IPv4")
	if err != nil {
		return unknown, err
	}
	if after["PrimaryService"] != id || after["PrimaryInterface"] != device {
		return unknown, errors.New("default service changed during CLAT discovery")
	}
	return nativeTargetService{ID: id, Name: name, Device: device}, nil
}

// saveTargetStaticDNSSnapshot saves only the already validated/rechecked
// snapshot. Never re-read via the legacy permissive static DNS reader, and
// never replace the original backup with ctrld's own (possibly non-loopback)
// target when a listener changes after restart.
func saveTargetStaticDNSSnapshot(path string, snapshot []string, owned string) error {
	if isInterceptDNSTargetOnly(snapshot, owned) {
		// Missing means the original service used automatic DNS. A present
		// but unreadable/corrupt backup must not authorize a listener change.
		data, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if len(data) == 0 {
			return nil
		}
		for _, s := range strings.Split(string(data), ",") {
			if net.ParseIP(s) == nil || s == owned {
				return errors.New("invalid retained static DNS backup")
			}
		}
		return nil
	}
	var dns []string
	for _, s := range snapshot {
		ip := net.ParseIP(s)
		if ip == nil {
			return errors.New("invalid static DNS snapshot")
		}
		if s == owned {
			continue
		}
		// The restore reader filters loopbacks. Refuse an unrestorable
		// user snapshot rather than silently discarding a local resolver.
		if ip.IsLoopback() {
			return errors.New("non-owned loopback in static DNS snapshot")
		}
		dns = append(dns, ip.String())
	}
	if len(dns) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return os.WriteFile(path, []byte(strings.Join(dns, ",")), 0600)
}

var nativeServiceID = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)

// parseNativeIPv4Store reads only the two native IPv4 dictionaries, never
// ipconfig getsummary (which embeds unescaped, network-controlled DHCP text).
// Unknown layouts fail closed. These fields are generated by configd from
// interface names, service UUIDs, booleans and binary IP addresses.
func parseNativeIPv4Store(out string) (map[string]string, error) {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) < 2 || lines[0] != "<dictionary> {" || lines[len(lines)-1] != "}" {
		return nil, errors.New("invalid native IPv4 dictionary")
	}
	values := make(map[string]string)
	depth := 1
	arrayKey := ""
	for _, line := range lines[1 : len(lines)-1] {
		s := strings.TrimSpace(line)
		if s == "}" {
			depth--
			if depth < 1 {
				return nil, errors.New("unbalanced native IPv4 dictionary")
			}
			continue
		}
		key, value, ok := strings.Cut(s, " : ")
		if !ok {
			return nil, errors.New("invalid native IPv4 field")
		}
		if depth == 1 {
			if _, exists := values[key]; exists {
				return nil, errors.New("duplicate native IPv4 field")
			}
			switch key {
			case "PrimaryService":
				if !nativeServiceID.MatchString(value) {
					return nil, errors.New("invalid service ID")
				}
			case "PrimaryInterface", "InterfaceName":
				if value == "" || strings.ContainsAny(value, " \t\r\n{}") {
					return nil, errors.New("invalid interface")
				}
			case "CLAT46":
				if value != "TRUE" && value != "FALSE" {
					return nil, errors.New("invalid CLAT flag")
				}
			case "Router":
				if net.ParseIP(value).To4() == nil {
					return nil, errors.New("invalid router")
				}
			case "Addresses", "SubnetMasks", "DestinationAddresses", "AdditionalRoutes", "ExcludedRoutes":
				if value != "<array> {" {
					return nil, errors.New("invalid IPv4 array")
				}
			default:
				return nil, errors.New("unknown native IPv4 field")
			}
			values[key] = value
			arrayKey = key
		} else if depth == 2 && arrayKey == "Addresses" {
			ip := net.ParseIP(value)
			if ip.To4() == nil {
				return nil, errors.New("invalid native IPv4 address")
			}
			values["AddressList"] += ip.String() + " "
		}
		if strings.HasSuffix(value, "{") {
			depth++
		}
	}
	if depth != 1 {
		return nil, errors.New("unbalanced native IPv4 dictionary")
	}
	return values, nil
}

// A successful networksetup exit alone is not absence evidence: reject all
// text except IP literals and its exact no-static-DNS response.
func parseTargetStaticDNS(out, service string) ([]string, error) {
	out = strings.TrimSpace(out)
	if out == "There aren't any DNS Servers set on "+service+"." {
		return nil, nil
	}
	if out == "" {
		return nil, errors.New("empty static DNS response")
	}
	var dns []string
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		ip := net.ParseIP(strings.TrimSpace(scanner.Text()))
		if ip == nil {
			return nil, errors.New("invalid static DNS response")
		}
		dns = append(dns, ip.String())
	}
	return dns, scanner.Err()
}

func nativeCLATAddresses(addrs []net.Addr) bool {
	clat, ipv6 := false, false
	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err != nil {
			return false
		}
		if v4 := ip.To4(); v4 != nil {
			// Apple allocates one of these four CLAT addresses, not only 192.0.0.2.
			if v4[0] != 192 || v4[1] != 0 || v4[2] != 0 || v4[3] < 2 || v4[3] > 5 {
				return false
			}
			clat = true
		} else if ip.IsGlobalUnicast() {
			// ULA is legitimate IPv6 connectivity. Addresses alone never
			// authorize a target: configd must independently publish CLAT.
			ipv6 = true
		}
	}
	return clat && ipv6
}
