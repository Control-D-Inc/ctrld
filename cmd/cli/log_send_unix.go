//go:build darwin || linux

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/pelletier/go-toml/v2"
	"golang.org/x/sys/unix"
)

const delegatedDebugBytes int64 = 10 << 20

var errLogSendTrust = errors.New("unsafe log-send location")

// trustedLogTree walks from a trusted anchor using descriptor-relative opens.
// Production always uses / and uid 0; tests anchor at their own private temp
// directory and uid, without needing root or touching system locations.
type trustedLogTree struct {
	root string
	uid  uint32
}

func canonicalLogSendPath(path string) string {
	path = filepath.Clean(path)
	// macOS's system aliases. Do not resolve arbitrary symlinks in user-selected
	// config/log paths: that could turn an attacker-controlled path into a trusted one.
	for _, alias := range []string{"/var", "/etc", "/tmp"} {
		if path == alias || strings.HasPrefix(path, alias+"/") {
			return "/private" + path
		}
	}
	return path
}

func (t trustedLogTree) check(fd int, dir bool) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	kind := uint32(unix.S_IFREG)
	if dir {
		kind = unix.S_IFDIR
	}
	if st.Uid != t.uid || uint32(st.Mode)&unix.S_IFMT != kind || st.Mode&0022 != 0 || (!dir && st.Nlink != 1) {
		return errLogSendTrust
	}
	return logSendCheckACL(fd)
}

func (t trustedLogTree) open(path string, dir bool) (*os.File, error) {
	if !filepath.IsAbs(path) {
		return nil, errLogSendTrust
	}
	rel, err := filepath.Rel(t.root, filepath.Clean(path))
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return nil, errLogSendTrust
	}
	fd, err := unix.Open(t.root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	if err = t.check(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if rel != "." {
		parts := strings.Split(rel, string(os.PathSeparator))
		for i, part := range parts {
			isDir := i < len(parts)-1 || dir
			flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
			if isDir {
				flags |= unix.O_DIRECTORY
			}
			next, openErr := unix.Openat(fd, part, flags, 0)
			unix.Close(fd)
			if openErr != nil {
				return nil, openErr
			}
			fd = next
			if err = t.check(fd, isDir); err != nil {
				unix.Close(fd)
				return nil, err
			}
		}
	} else if !dir {
		unix.Close(fd)
		return nil, errLogSendTrust
	}
	return os.NewFile(uintptr(fd), path), nil
}

type delegatedLogSource struct {
	path    string
	backups int
	budget  int64
}
type delegatedLogCollector struct {
	tree    trustedLogTree
	config  string
	sources []delegatedLogSource
}

// collect opens only immutable daemon-selected paths. It never calls the legacy
// reader (which tolerates untrusted homes and skips errors), never shells out for
// a network snapshot, and never reads an unbounded journal or memory fallback.
// Like the administrative upload, the body is stripped of the color codes of the
// internal debug stream; the source budgets count the bytes before that removal.
func (c delegatedLogCollector) collect(ctx context.Context) (io.ReadCloser, error) {
	upload, err := c.open(ctx)
	if err != nil {
		return nil, err
	}
	lr, err := upload.reader(errLogFileEmpty)
	if err != nil {
		return nil, err
	}
	return &multiCloser{Reader: newANSIStripReader(lr.r), closers: []io.Closer{lr.r}}, nil
}

// validate checks the same sources as an upload, but empty logs do not prevent
// startup. No log bytes are read, and every checked descriptor is closed.
func (c delegatedLogCollector) validate(ctx context.Context) error {
	upload, err := c.open(ctx)
	if err != nil {
		return err
	}
	upload.close()
	return nil
}

func (c delegatedLogCollector) open(ctx context.Context) (*logParts, error) {
	config, err := c.tree.open(c.config, false)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(config, (1<<20)+1))
	config.Close()
	if err != nil || len(data) > 1<<20 {
		return nil, errLogSendTrust
	}
	var permission struct {
		Service struct {
			Allow bool `toml:"allow_unprivileged_log_send"`
		} `toml:"service"`
	}
	if err := toml.Unmarshal(data, &permission); err != nil || !permission.Service.Allow {
		return nil, errLogSendTrust
	}
	var upload logParts
	fail := func(err error) (*logParts, error) { upload.close(); return nil, err }
	if len(c.sources) == 0 || len(c.sources) > 2 {
		return fail(errLogSendTrust)
	}
	for index, source := range c.sources {
		if source.backups < 0 || source.backups > 64 || source.budget <= 0 || source.budget > delegatedDebugBytes {
			return fail(errLogSendTrust)
		}
		// Check the directory even when every file is missing.
		dir, err := c.tree.open(filepath.Dir(source.path), true)
		if err != nil {
			return fail(err)
		}
		dir.Close()
		remaining := source.budget
		var parts []logFilePart
		// Open newest first; hold at most 65 descriptors per stream. Missing rotated
		// files are normal, but unsafe files are errors, not silently skipped.
		for i := 0; i <= source.backups; i++ {
			if err := ctx.Err(); err != nil {
				for _, p := range parts {
					p.f.Close()
				}
				return fail(err)
			}
			path := source.path
			if i > 0 {
				path = fmt.Sprintf("%s.%d", path, i)
			}
			f, err := c.tree.open(path, false)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				for _, p := range parts {
					p.f.Close()
				}
				return fail(err)
			}
			st, err := f.Stat()
			if err != nil {
				f.Close()
				for _, p := range parts {
					p.f.Close()
				}
				return fail(err)
			}
			size := st.Size()
			offset := int64(0)
			if size > remaining {
				offset = size - remaining
			}
			remaining -= size - offset
			parts = append(parts, logFilePart{f: f, size: size, offset: offset})
		}
		// Tail sections are bounded even for a single enormous line. Unlike the
		// admin reader, delegated collection deliberately does no line-boundary scan.
		for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
			parts[i], parts[j] = parts[j], parts[i]
		}
		if index != 0 && (upload.size > 0 || remaining < source.budget) {
			upload.addBytes([]byte(logWriterLogEndMarker))
		}
		upload.addFiles(parts)
	}
	return &upload, nil
}

func logSendPeer(c net.Conn) (uint32, error) {
	u, ok := c.(syscall.Conn)
	if !ok {
		return 0, errLogSendTrust
	}
	raw, err := u.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var credErr error
	if err = raw.Control(func(fd uintptr) { uid, credErr = logSendPeerUID(int(fd)) }); err != nil {
		return 0, err
	}
	return uid, credErr
}

// dialLogSend verifies the protected namespace and the actual connected peer.
// Socket mode is deliberately world-connectable; its parent must not be writable.
func dialLogSend(ctx context.Context, tree trustedLogTree, path string) (net.Conn, error) {
	dir, err := tree.open(filepath.Dir(path), true)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	var st unix.Stat_t
	if err := unix.Fstatat(int(dir.Fd()), filepath.Base(path), &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, err
	}
	if st.Uid != tree.uid || uint32(st.Mode)&unix.S_IFMT != unix.S_IFSOCK {
		return nil, errLogSendTrust
	}
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	uid, err := logSendPeer(conn)
	if err != nil || uid != tree.uid {
		conn.Close()
		return nil, errLogSendTrust
	}
	return conn, nil
}

func requestDelegatedLogSend(ctx context.Context, full bool, dial func(context.Context) (net.Conn, error)) error {
	if full {
		return errors.New("log send --full requires administrator privileges")
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dial(ctx) }, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: delegatedSendTimeout + 10*time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix"+sendLogsPath, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("log send unavailable: ask an administrator to enable allow_unprivileged_log_send and restart ctrld, or use sudo")
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusServiceUnavailable:
		return errors.New("log send busy or cooling down; retry after one minute")
	case http.StatusPreconditionFailed:
		return errors.New("log send unavailable: administrator must check configuration and log permissions")
	default:
		return errors.New("log send failed; ask an administrator to check the daemon log")
	}
}
