package cli

import (
	"net"
	"time"
)

// logConn wraps a net.Conn, override the Write behavior.
// runCmd uses this wrapper, so as long as startCmd finished,
// ctrld log won't be flushed with un-necessary write errors.
// This prevents log pollution when the parent process closes the connection
type logConn struct {
	conn net.Conn
}

// Read delegates to the underlying connection
// This maintains normal read behavior for the wrapped connection
func (lc *logConn) Read(b []byte) (n int, err error) {
	return lc.conn.Read(b)
}

// Close delegates to the underlying connection
// This ensures proper cleanup of the wrapped connection
func (lc *logConn) Close() error {
	return lc.conn.Close()
}

// LocalAddr delegates to the underlying connection
// This provides access to local address information
func (lc *logConn) LocalAddr() net.Addr {
	return lc.conn.LocalAddr()
}

// RemoteAddr delegates to the underlying connection
// This provides access to remote address information
func (lc *logConn) RemoteAddr() net.Addr {
	return lc.conn.RemoteAddr()
}

// SetDeadline delegates to the underlying connection
// This maintains timeout functionality for the wrapped connection
func (lc *logConn) SetDeadline(t time.Time) error {
	return lc.conn.SetDeadline(t)
}

// SetReadDeadline delegates to the underlying connection
// This maintains read timeout functionality for the wrapped connection
func (lc *logConn) SetReadDeadline(t time.Time) error {
	return lc.conn.SetReadDeadline(t)
}

// SetWriteDeadline delegates to the underlying connection
// This maintains write timeout functionality for the wrapped connection
func (lc *logConn) SetWriteDeadline(t time.Time) error {
	return lc.conn.SetWriteDeadline(t)
}

// Write performs writes with underlying net.Conn, ignore any errors happen.
// "ctrld run" command use this wrapper to report errors to "ctrld start".
// If no error occurred, "ctrld start" may finish before "ctrld run" attempt
// to close the connection, so ignore errors conservatively here, prevent
// un-necessary error "write to closed connection" flushed to ctrld log.
// This prevents log pollution when the parent process closes the connection prematurely
func (lc *logConn) Write(b []byte) (int, error) {
	_, _ = lc.conn.Write(b)
	return len(b), nil
}
