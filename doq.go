package ctrld

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/miekg/dns"
)

type doqResolver struct {
	uc *UpstreamConfig
}

func (r *doqResolver) Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	endpoint := r.uc.Endpoint
	tlsConfig := &tls.Config{NextProtos: []string{"doq"}}
	if r.uc.BootstrapIP != "" {
		tlsConfig.ServerName = r.uc.Domain
		_, port, _ := net.SplitHostPort(endpoint)
		endpoint = net.JoinHostPort(r.uc.BootstrapIP, port)
	}
	return resolve(ctx, msg, endpoint, tlsConfig)
}

func resolve(ctx context.Context, msg *dns.Msg, endpoint string, tlsConfig *tls.Config) (*dns.Msg, error) {
	session, err := quic.DialAddr(endpoint, tlsConfig, nil)
	if err != nil {
		return nil, err
	}
	defer session.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "")

	msgBytes, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	stream, err := session.OpenStream()
	if err != nil {
		return nil, err
	}

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(5 * time.Second)
	}
	_ = stream.SetDeadline(deadline)

	var msgLen = uint16(len(msgBytes))
	var msgLenBytes = []byte{byte(msgLen >> 8), byte(msgLen & 0xFF)}
	if _, err := stream.Write(msgLenBytes); err != nil {
		return nil, err
	}

	if _, err := stream.Write(msgBytes); err != nil {
		return nil, err
	}

	buf, err := io.ReadAll(stream)
	if err != nil {
		return nil, err
	}

	_ = stream.Close()

	answer := new(dns.Msg)
	if err := answer.Unpack(buf[2:]); err != nil {
		return nil, err
	}
	answer.SetReply(msg)
	return answer, nil
}
