package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// renameFile is os.Rename. Tests replace it.
var renameFile = os.Rename

// staleTempFileAge is the age after which a temporary file of replaceFile
// belongs to a write that stopped. A write takes much less time.
const staleTempFileAge = time.Minute

// replaceFile writes data to a new file next to path, and then renames the
// new file to path. If the write stops early, the old file stays whole.
//
// If path is a symlink, the link stays and the file that it names gets the
// data. The new file keeps the mode and the owner of the old file. A new
// file gets perm, less the umask.
//
// Some files cannot be replaced, for example a file that is mounted on its
// own in a container, or a file in a folder that ctrld cannot write. For
// these, replaceFile writes the file in place, as ctrld did before.
func replaceFile(path string, data []byte, perm os.FileMode) error {
	path, err := resolveFinalSymlink(path)
	if err != nil {
		return err
	}
	old, err := os.Stat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		old = nil
	case err != nil:
		return err
	case !old.Mode().IsRegular():
		return writeFileInPlace(path, data, perm)
	}
	removeStaleTempFiles(path)

	tmp, err := createTempFile(path, perm)
	if err != nil {
		return writeInPlaceAfter(err, path, data, perm)
	}
	if err := writeAndSync(tmp, data); err != nil {
		discardTempFile(tmp)
		return err
	}
	if err := copyFileAttrs(tmp, old); err != nil {
		discardTempFile(tmp)
		return writeInPlaceAfter(err, path, data, perm)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := renameFile(tmp.Name(), path); err != nil {
		_ = os.Remove(tmp.Name())
		return writeInPlaceAfter(err, path, data, perm)
	}
	return nil
}

// resolveFinalSymlink follows the symlinks at the last element of path, also
// when the file at the end does not exist yet. A symlink in a parent folder
// needs nothing, because the rename goes through it.
func resolveFinalSymlink(path string) (string, error) {
	const maxLinks = 40
	for range maxLinks {
		fi, err := os.Lstat(path)
		if err != nil || fi.Mode()&fs.ModeSymlink == 0 {
			return path, nil
		}
		target, err := os.Readlink(path)
		if err != nil {
			return "", err
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(path), target)
		}
		path = target
	}
	return "", fmt.Errorf("too many symlinks at %s", path)
}

func tempFilePrefix(path string) string {
	return filepath.Base(path) + ".tmp"
}

// createTempFile makes a new, empty file next to path. The kernel applies the
// umask to perm.
func createTempFile(path string, perm os.FileMode) (*os.File, error) {
	prefix := filepath.Join(filepath.Dir(path), tempFilePrefix(path))
	for {
		f, err := os.OpenFile(prefix+strconv.FormatUint(rand.Uint64(), 36), os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		return f, err
	}
}

// removeStaleTempFiles removes the temporary files of writes that stopped,
// for example because iOS ended the app. A young file can belong to a write
// that runs now, so it stays.
func removeStaleTempFiles(path string) {
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		mainLog.Load().Debug().Err(err).Msg("could not list the config folder for old temporary files")
		return
	}
	prefix := tempFilePrefix(path)
	for _, e := range entries {
		if !e.Type().IsRegular() || !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		fi, err := e.Info()
		if err != nil || time.Since(fi.ModTime()) < staleTempFileAge {
			continue
		}
		name := filepath.Join(filepath.Dir(path), e.Name())
		if err := os.Remove(name); err != nil {
			mainLog.Load().Debug().Err(err).Msgf("could not remove old temporary file %s", name)
		}
	}
}

// writeAndSync writes data to f. The data must reach the disk before the
// rename, or a power loss can leave an empty file.
func writeAndSync(f *os.File, data []byte) error {
	if _, err := f.Write(data); err != nil {
		return err
	}
	return f.Sync()
}

// copyFileAttrs gives f the mode and the owner of old. A nil old means that
// there is no old file.
func copyFileAttrs(f *os.File, old fs.FileInfo) error {
	if old == nil {
		return nil
	}
	if err := f.Chmod(old.Mode().Perm()); err != nil {
		return err
	}
	return copyFileOwner(f, old)
}

func discardTempFile(f *os.File) {
	_ = f.Close()
	_ = os.Remove(f.Name())
}

// writeInPlaceAfter writes the file in place when the replacement cannot
// work. The reason goes to the log, because an in-place write can leave a
// cut-short file if it stops early.
func writeInPlaceAfter(reason error, path string, data []byte, perm os.FileMode) error {
	mainLog.Load().Warn().Err(reason).Msgf("could not replace %s, writing it in place", path)
	return writeFileInPlace(path, data, perm)
}

func writeFileInPlace(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
