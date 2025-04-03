package clientinfo

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"tailscale.com/logtail/backoff"

	"github.com/Control-D-Inc/ctrld"
	ctrldnet "github.com/Control-D-Inc/ctrld/internal/net"
)

var (
	mdnsV4Addr = &net.UDPAddr{
		IP:   net.ParseIP("224.0.0.251"),
		Port: 5353,
	}
	mdnsV6Addr = &net.UDPAddr{
		IP:   net.ParseIP("ff02::fb"),
		Port: 5353,
	}
)

type mdns struct {
	name   sync.Map // ip => hostname
	logger *ctrld.Logger
}

func (m *mdns) LookupHostnameByIP(ip string) string {
	val, ok := m.name.Load(ip)
	if !ok {
		return ""
	}
	return val.(string)
}

func (m *mdns) LookupHostnameByMac(mac string) string {
	return ""
}

func (m *mdns) String() string {
	return "mdns"
}

func (m *mdns) List() []string {
	if m == nil {
		return nil
	}
	var ips []string
	m.name.Range(func(key, value any) bool {
		ips = append(ips, key.(string))
		return true
	})
	return ips
}

func (m *mdns) lookupIPByHostname(name string, v6 bool) string {
	if m == nil {
		return ""
	}
	var ip string
	m.name.Range(func(key, value any) bool {
		if value == name {
			if addr, err := netip.ParseAddr(key.(string)); err == nil && addr.Is6() == v6 {
				ip = addr.String()
				//lint:ignore S1008 This is used for readable.
				if addr.IsLoopback() { // Continue searching if this is loopback address.
					return true
				}
				return false
			}
		}
		return true
	})
	return ip
}

func (m *mdns) init(quitCh chan struct{}) error {
	ifaces, err := multicastInterfaces()
	if err != nil {
		return err
	}

	// Check if IPv6 is available once and use the result for the rest of the function.
	m.logger.Debug().Msgf("checking for IPv6 availability in mdns init")
	ipv6 := ctrldnet.IPv6Available(context.Background())
	m.logger.Debug().Msgf("IPv6 is %v in mdns init", ipv6)

	v4ConnList := make([]*net.UDPConn, 0, len(ifaces))
	v6ConnList := make([]*net.UDPConn, 0, len(ifaces))
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if conn, err := net.ListenMulticastUDP("udp4", &iface, mdnsV4Addr); err == nil {
			v4ConnList = append(v4ConnList, conn)
			go m.readLoop(conn)
		}

		if ipv6 {
			if conn, err := net.ListenMulticastUDP("udp6", &iface, mdnsV6Addr); err == nil {
				v6ConnList = append(v6ConnList, conn)
				go m.readLoop(conn)
			}
		}
	}

	go m.probeLoop(v4ConnList, mdnsV4Addr, quitCh)
	go m.probeLoop(v6ConnList, mdnsV6Addr, quitCh)
	go m.getDataFromAvahiDaemonCache()

	return nil
}

// probeLoop performs mdns probe actively to get hostname updates.
func (m *mdns) probeLoop(conns []*net.UDPConn, remoteAddr net.Addr, quitCh chan struct{}) {
	bo := backoff.NewBackoff("mdns probe", func(format string, args ...any) {}, time.Second*30)
	for {
		err := m.probe(conns, remoteAddr)
		if shouldStopProbing(err) {
			m.logger.Warn().Msgf("stop probing %q: %v", remoteAddr, err)
			break
		}
		if err != nil {
			m.logger.Warn().Err(err).Msg("error while probing mdns")
			bo.BackOff(context.Background(), errors.New("mdns probe backoff"))
			continue
		}
		break
	}
	<-quitCh
	for _, conn := range conns {
		_ = conn.Close()
	}
}

// readLoop reads from mdns connection, save/update any hostnames found.
func (m *mdns) readLoop(conn *net.UDPConn) {
	defer conn.Close()
	buf := make([]byte, dns.MaxMsgSize)

	for {
		_ = conn.SetReadDeadline(time.Now().Add(time.Second * 30))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if err, ok := err.(*net.OpError); ok && (err.Timeout() || err.Temporary()) {
				continue
			}
			// Do not complain about use of closed network connection.
			if errors.Is(err, net.ErrClosed) {
				return
			}
			m.logger.Debug().Err(err).Msg("mdns readLoop error")
			return
		}

		var msg dns.Msg
		if err := msg.Unpack(buf[:n]); err != nil {
			continue
		}

		var ip, name string
		var rrs []dns.RR
		rrs = append(rrs, msg.Answer...)
		rrs = append(rrs, msg.Extra...)
		for _, rr := range rrs {
			switch ar := rr.(type) {
			case *dns.A:
				ip, name = ar.A.String(), ar.Hdr.Name
			case *dns.AAAA:
				ip, name = ar.AAAA.String(), ar.Hdr.Name
			}
			if ip != "" && name != "" {
				name = normalizeHostname(name)
				if val, loaded := m.name.LoadOrStore(ip, name); !loaded {
					m.logger.Debug().Msgf("found hostname: %q, ip: %q via mdns", name, ip)
				} else {
					old := val.(string)
					if old != name {
						m.logger.Debug().Msgf("update hostname: %q, ip: %q, old: %q via mdns", name, ip, old)
						m.name.Store(ip, name)
					}
				}
				ip, name = "", ""
			}
		}
	}
}

// probe performs mdns queries with known services.
func (m *mdns) probe(conns []*net.UDPConn, remoteAddr net.Addr) error {
	msg := new(dns.Msg)
	msg.Question = make([]dns.Question, len(services))
	msg.Compress = true
	for i, service := range services {
		msg.Question[i] = dns.Question{
			Name:   dns.CanonicalName(service),
			Qtype:  dns.TypePTR,
			Qclass: dns.ClassINET,
		}
	}

	buf, err := msg.Pack()
	if err != nil {
		return err
	}
	for _, conn := range conns {
		_ = conn.SetWriteDeadline(time.Now().Add(time.Second * 30))
		if _, werr := conn.WriteTo(buf, remoteAddr); werr != nil {
			err = werr
		}
	}
	return err
}

// getDataFromAvahiDaemonCache reads entries from avahi-daemon cache to update mdns data.
func (m *mdns) getDataFromAvahiDaemonCache() {
	if _, err := exec.LookPath("avahi-browse"); err != nil {
		m.logger.Debug().Err(err).Msg("could not find avahi-browse binary, skipping.")
		return
	}
	// Run avahi-browse to discover services from cache:
	//  - "-a" -> all services.
	//  - "-r" -> resolve found services.
	//  - "-p" -> parseable format.
	//  - "-c" -> read from cache.
	out, err := exec.Command("avahi-browse", "-a", "-r", "-p", "-c").Output()
	if err != nil {
		m.logger.Debug().Err(err).Msg("could not browse services from avahi cache")
		return
	}
	m.storeDataFromAvahiBrowseOutput(bytes.NewReader(out))
}

// storeDataFromAvahiBrowseOutput parses avahi-browse output from reader, then updating found data to mdns table.
func (m *mdns) storeDataFromAvahiBrowseOutput(r io.Reader) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.FieldsFunc(scanner.Text(), func(r rune) bool {
			return r == ';'
		})
		if len(fields) < 8 || fields[0] != "=" {
			continue
		}
		ip := fields[7]
		name := normalizeHostname(fields[6])
		// Only using cache value if we don't have existed one.
		if _, loaded := m.name.LoadOrStore(ip, name); !loaded {
			m.logger.Debug().Msgf("found hostname: %q, ip: %q via avahi cache", name, ip)
		}
	}
}

func multicastInterfaces() ([]net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	interfaces := make([]net.Interface, 0, len(ifaces))
	for _, ifi := range ifaces {
		if (ifi.Flags & net.FlagUp) == 0 {
			continue
		}
		if (ifi.Flags & net.FlagMulticast) > 0 {
			interfaces = append(interfaces, ifi)
		}
	}
	return interfaces, nil
}

// shouldStopProbing reports whether ctrld should stop probing mdns.
func shouldStopProbing(err error) bool {
	var se *os.SyscallError
	if errors.As(err, &se) {
		switch se.Err {
		case syscall.ENETUNREACH, syscall.EINVAL, syscall.EPERM:
			return true
		}
	}
	return false
}
