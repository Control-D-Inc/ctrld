//go:build unix

package cli

import (
	"io/fs"
	"os"
	"syscall"
)

// copyFileOwner gives f the owner and group of old. A root process that
// rewrites the config file of a user must not take the file from that user.
func copyFileOwner(f *os.File, old fs.FileInfo) error {
	want, ok := old.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	cur, err := f.Stat()
	if err != nil {
		return err
	}
	if have, ok := cur.Sys().(*syscall.Stat_t); ok && have.Uid == want.Uid && have.Gid == want.Gid {
		return nil
	}
	return f.Chown(int(want.Uid), int(want.Gid))
}
