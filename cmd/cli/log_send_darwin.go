package cli

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/controld"
	"golang.org/x/sys/unix"
)

// /private/var/run is group-writable on macOS and fails the trust walk.
const logSendSocketDir = "/private/var/ctrld-log-send"
const logSendSocketPath = logSendSocketDir + "/send.sock"
const delegatedJournalBytes int64 = 6 << 20

func logSendPeerUID(fd int) (uint32, error) {
	cred, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return 0, err
	}
	// XNU bsd/sys/ucred.h defines XUCRED_VERSION as 0; this version of
	// x/sys/unix exposes Xucred but does not export that constant.
	if cred.Version != 0 {
		return 0, errLogSendTrust
	}
	return cred.Uid, nil
}

// A POSIX mode alone cannot exclude a macOS ACL grant. Conservatively refuse
// extended ACLs (even deny-only ACLs), and fail closed if the kernel cannot report
// them. fgetattrlist returns a length and an attrreference; absent ACL => length 0.
// See XNU vfs_attrlist.c, ATTR_CMN_EXTENDED_SECURITY packing. Using the open fd
// avoids a pathname race and does not need cgo or a privileged helper process.
func logSendCheckACL(fd int) error {
	attrs := unix.Attrlist{Bitmapcount: 5, Commonattr: unix.ATTR_CMN_EXTENDED_SECURITY}
	var buf [12]byte
	//lint:ignore SA1019 x/sys has no fgetattrlist libSystem wrapper; preserve descriptor-relative ACL checks in CGO_ENABLED=0 builds.
	_, _, errno := syscall.Syscall6(unix.SYS_FGETATTRLIST, uintptr(fd), uintptr(unsafe.Pointer(&attrs)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0, 0)
	if errno != 0 {
		return errno
	}
	if binary.LittleEndian.Uint32(buf[:4]) != 12 || binary.LittleEndian.Uint32(buf[8:]) != 0 {
		return errLogSendTrust
	}
	return nil
}

func delegatedLogSendCLI() bool { return os.Geteuid() != 0 }
func runDelegatedLogSend(ctx context.Context, full bool) error {
	err := requestDelegatedLogSend(ctx, full, func(ctx context.Context) (net.Conn, error) {
		return dialLogSend(ctx, trustedLogTree{root: "/", uid: 0}, logSendSocketPath)
	})
	if err != nil {
		return fmt.Errorf("failed to send logs: %w", err)
	}
	mainLog.Load().Notice().Msg("Runtime logs sent successfully")
	return nil
}

func (p *prog) startLogSendServer() {
	p.logSendMu.Lock()
	defer p.logSendMu.Unlock()
	if p.logSendStopped || p.logSend != nil {
		return
	}
	p.mu.Lock()
	enabled := p.cfg.Service.AllowUnprivilegedLogSend
	p.mu.Unlock()
	if !enabled {
		return
	}
	s, err := p.newDelegatedLogSendServer()
	if err != nil {
		p.Error().Err(err).Msg("Unprivileged log send disabled: unsafe or unavailable configuration, logs or socket; correct as administrator and restart")
		return
	}
	p.logSend = s
	ctrld.Journal(p.Info()).Msg("Unprivileged log send enabled for all local users until service stop")
}

func (p *prog) newDelegatedLogSendServer() (*logSendServer, error) {
	if os.Geteuid() != 0 || cdUID == "" || configBase64 != "" {
		return nil, errLogSendTrust
	}
	tree := trustedLogTree{root: "/", uid: 0}
	collector := delegatedLogCollector{tree: tree, config: canonicalLogSendPath(v.ConfigFileUsed())}
	// Capture source paths and budgets once. A reload cannot redirect this socket
	// to new files, identities, or destinations, nor enable an initially off socket.
	var files []*rotatingFile
	if p.needInternalLogging() {
		lw, jw := p.internalWriters()
		if lw == nil || jw == nil {
			return nil, errLogSendTrust
		}
		files = []*rotatingFile{lw.rotating(), jw.rotating()}
	} else {
		files = []*rotatingFile{logPathFile.Load()}
	}
	for i, rf := range files {
		if rf == nil {
			return nil, errLogSendTrust
		}
		rf.mu.Lock()
		source := delegatedLogSource{path: canonicalLogSendPath(rf.path), backups: rf.budget.backups, budget: delegatedDebugBytes}
		rf.mu.Unlock()
		if i == 1 {
			source.budget = delegatedJournalBytes
		}
		collector.sources = append(collector.sources, source)
	}
	listener, err := collector.listen(logSendSocketDir)
	if err != nil {
		return nil, err
	}
	uid, dev := cdUID, cdDev
	s := &logSendServer{gate: &p.logUpload, collect: collector.collect,
		upload: func(ctx context.Context, body io.ReadCloser) error {
			return controld.SendLogs(ctrld.LoggerCtx(ctx, p.logger.Load()), &controld.LogsRequest{UID: uid, Data: body}, dev)
		},
		audit: func(uid int64, code int) {
			ctrld.Journal(p.Info()).Int64("caller_uid", uid).Int("status", code).Msg("Unprivileged log send outcome")
		},
	}
	s.serve(listener, logSendPeer)
	return s, nil
}

func (c delegatedLogCollector) listen(dir string) (net.Listener, error) {
	// Validate before exposing any capability; repeat the same checks per upload.
	if err := c.validate(context.Background()); err != nil {
		return nil, err
	}
	return listenDelegatedLogSend(c.tree, dir)
}

func listenDelegatedLogSend(tree trustedLogTree, dir string) (net.Listener, error) {
	parent, err := tree.open(filepath.Dir(dir), true)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	if err := unix.Mkdirat(int(parent.Fd()), filepath.Base(dir), 0755); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, err
	}
	protected, err := tree.open(dir, true)
	if err != nil {
		return nil, err
	}
	protected.Close()
	path := filepath.Join(dir, "send.sock")
	if st, err := os.Lstat(path); err == nil {
		stat, ok := st.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != tree.uid || st.Mode()&os.ModeSocket == 0 {
			return nil, errLogSendTrust
		}
		c, err := net.DialTimeout("unix", path, time.Second)
		if err == nil {
			c.Close()
			return nil, errors.New("log-send socket already active")
		}
		// Only an unequivocally stale endpoint may be removed, not timeout/permission errors.
		if !errors.Is(err, syscall.ECONNREFUSED) {
			return nil, err
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	// No handler is serving until chmod succeeds. Parent ownership prevents
	// replacement. The administrative control socket remains 0600.
	if err := os.Chmod(path, 0666); err != nil {
		l.Close()
		return nil, err
	}
	l.SetUnlinkOnClose(true)
	return l, nil
}
