//go:build darwin || linux

package cli

import (
	"context"
	"net"
	"net/http"
	"sync"
	"syscall"
	"time"
)

// Unlike netutil.LimitListener, this wrapper preserves syscall.Conn so the
// HTTP server can authenticate the actual Unix peer after accepting it.
type logSendListener struct {
	net.Listener
	slots chan struct{}
	done  chan struct{}
	once  sync.Once
}

type logSendConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *logSendConn) SyscallConn() (syscall.RawConn, error) {
	sc, ok := c.Conn.(syscall.Conn)
	if !ok {
		return nil, net.ErrClosed
	}
	return sc.SyscallConn()
}

func (c *logSendConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

func (l *logSendListener) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	return &logSendConn{Conn: c, release: func() { <-l.slots }}, nil
}

func (l *logSendListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.Listener.Close()
}

func (s *logSendServer) serve(l net.Listener, peer func(net.Conn) (uint32, error)) {
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.server = &http.Server{
		Handler: s, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second,
		WriteTimeout: delegatedSendTimeout + 5*time.Second, MaxHeaderBytes: 1024,
		BaseContext: func(net.Listener) context.Context { return ctx },
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			uid, err := peer(c)
			if err != nil {
				_ = c.Close()
				return ctx
			}
			return context.WithValue(ctx, logSendPeerKey{}, uid)
		},
	}
	s.server.SetKeepAlivesEnabled(false)
	go s.server.Serve(&logSendListener{Listener: l, slots: make(chan struct{}, 8), done: make(chan struct{})})
}
