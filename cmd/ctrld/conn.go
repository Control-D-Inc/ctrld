package main

import (
	"net"
	"time"
)

// logConn wraps a net.Conn, override the Write behavior.
// runCmd uses this wrapper, so as long as startCmd finished,
// ctrld log won't be flushed with un-necessary write errors.
type logConn struct {
	conn net.Conn
}

func (lc *logConn) Read(b []byte) (n int, err error) {
	return lc.conn.Read(b)
}

func (lc *logConn) Close() error {
	return lc.conn.Close()
}

func (lc *logConn) LocalAddr() net.Addr {
	return lc.conn.LocalAddr()
}

func (lc *logConn) RemoteAddr() net.Addr {
	return lc.conn.RemoteAddr()
}

func (lc *logConn) SetDeadline(t time.Time) error {
	return lc.conn.SetDeadline(t)
}

func (lc *logConn) SetReadDeadline(t time.Time) error {
	return lc.conn.SetReadDeadline(t)
}

func (lc *logConn) SetWriteDeadline(t time.Time) error {
	return lc.conn.SetWriteDeadline(t)
}

func (lc *logConn) Write(b []byte) (int, error) {
	// Write performs writes with underlying net.Conn, ignore any errors happen.
	// "ctrld run" command use this wrapper to report errors to "ctrld start".
	// If no error occurred, "ctrld start" may finish before "ctrld run" attempt
	// to close the connection, so ignore errors conservatively here, prevent
	// un-necessary error "write to closed connection" flushed to ctrld log.
	_, _ = lc.conn.Write(b)
	return len(b), nil
}
