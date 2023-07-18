package clientinfo

import (
	"context"
	"errors"
	"net"
	"os"
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
	name sync.Map // ip => hostname
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

func (m *mdns) init(quitCh chan struct{}) error {
	ifaces, err := multicastInterfaces()
	if err != nil {
		return err
	}

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
		if ctrldnet.IPv6Available(context.Background()) {
			if conn, err := net.ListenMulticastUDP("udp6", &iface, mdnsV6Addr); err == nil {
				v6ConnList = append(v6ConnList, conn)
				go m.readLoop(conn)
			}
		}
	}

	go m.probeLoop(v4ConnList, mdnsV4Addr, quitCh)
	go m.probeLoop(v6ConnList, mdnsV6Addr, quitCh)

	return nil
}

func (m *mdns) probeLoop(conns []*net.UDPConn, remoteAddr net.Addr, quitCh chan struct{}) {
	bo := backoff.NewBackoff("mdns probe", func(format string, args ...any) {}, time.Second*30)
	for {
		err := m.probe(conns, remoteAddr, quitCh)
		if isErrNetUnreachableOrInvalid(err) {
			ctrld.ProxyLog.Warn().Msgf("stop probing %q: network unreachable or invalid", remoteAddr)
			break
		}
		if err != nil {
			ctrld.ProxyLog.Warn().Err(err).Msg("error while probing mdns")
			bo.BackOff(context.Background(), errors.New("mdns probe backoff"))
		}
		select {
		case <-quitCh:
			break
		}
	}
	<-quitCh
	for _, conn := range conns {
		_ = conn.Close()
	}
}

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
			ctrld.ProxyLog.Debug().Err(err).Msg("mdns readLoop error")
			return
		}

		var msg dns.Msg
		if err := msg.Unpack(buf[:n]); err != nil {
			continue
		}

		var ip, name string
		for _, answer := range msg.Answer {
			switch ar := answer.(type) {
			case *dns.A:
				ip, name = ar.A.String(), ar.Hdr.Name
			case *dns.AAAA:
				ip, name = ar.AAAA.String(), ar.Hdr.Name
			}
			if ip != "" && name != "" {
				name = normalizeHostname(name)
				if val, loaded := m.name.LoadOrStore(ip, name); !loaded {
					ctrld.ProxyLog.Debug().Msgf("found hostname: %q, ip: %q via mdns", name, ip)
				} else {
					old := val.(string)
					if old != name {
						ctrld.ProxyLog.Debug().Msgf("update hostname: %q, ip: %q, old: %q via mdns", name, ip, old)
						m.name.Store(ip, name)
					}
				}
				ip, name = "", ""
			}
		}
	}
}

func (m *mdns) probe(conns []*net.UDPConn, remoteAddr net.Addr, quitCh chan struct{}) error {
	msg := new(dns.Msg)
	msg.Question = make([]dns.Question, len(services))
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

func isErrNetUnreachableOrInvalid(err error) bool {
	var se *os.SyscallError
	if errors.As(err, &se) {
		return se.Err == syscall.ENETUNREACH || se.Err == syscall.EINVAL
	}
	return false
}
