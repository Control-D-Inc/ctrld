//go:build !qf

package ctrld

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
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
	// DoQ quic-go server returns io.EOF error after running for a long time,
	// even for a good stream. So retrying the query for 5 times before giving up.
	for i := 0; i < 5; i++ {
		answer, err := doResolve(ctx, msg, endpoint, tlsConfig)
		if err == io.EOF {
			continue
		}
		if err != nil {
			return nil, err
		}
		return answer, nil
	}
	return nil, &quic.ApplicationError{ErrorCode: quic.ApplicationErrorCode(quic.InternalError), ErrorMessage: quic.InternalError.Message()}
}

func doResolve(ctx context.Context, msg *dns.Msg, endpoint string, tlsConfig *tls.Config) (*dns.Msg, error) {
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

	// io.ReadAll hide the io.EOF error returned by quic-go server.
	// Once we figure out why quic-go server sends io.EOF after running
	// for a long time, we can have a better way to handle this. For now,
	// make sure io.EOF error returned, so the caller can handle it cleanly.
	if len(buf) == 0 {
		return nil, io.EOF
	}

	answer := new(dns.Msg)
	if err := answer.Unpack(buf[2:]); err != nil {
		return nil, err
	}
	answer.SetReply(msg)
	return answer, nil
}
