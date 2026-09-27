//go:build !linux

package router

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func readExistingMerlinStartupScript(path string) ([]byte, bool, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() {
		return nil, true, fmt.Errorf("startup script is not a regular file: %s", path)
	}
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, true, err
	}
	return buf, true, nil
}

func prepareExistingMerlinStartupScript(path string, expected, legacy []byte) (exists bool, retErr error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return true, fmt.Errorf("startup script is not a regular file: %s", path)
	}

	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return true, err
	}
	defer func() {
		if err := f.Close(); retErr == nil && err != nil {
			retErr = err
		}
	}()

	info, err = f.Stat()
	if err != nil {
		return true, err
	}
	if !info.Mode().IsRegular() {
		return true, fmt.Errorf("startup script is not a regular file: %s", path)
	}
	got, err := io.ReadAll(f)
	if err != nil {
		return true, err
	}
	needsMigration := bytes.Equal(got, legacy) && !bytes.Equal(got, expected)
	if !bytes.Equal(got, expected) && !needsMigration {
		return true, fmt.Errorf("already installed with different startup script: %s", path)
	}
	if needsMigration {
		if err := replaceMerlinStartupScriptAtomically(path, expected, got, info); err != nil {
			return true, err
		}
		return true, nil
	}
	if err := f.Chmod(0755); err != nil {
		return true, err
	}
	return true, nil
}

func replaceMerlinStartupScriptAtomically(path string, expected, legacy []byte, originalInfo os.FileInfo) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".ctrld-migrate-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()

	if err := tmp.Chmod(0755); err != nil {
		return err
	}
	if _, err := tmp.Write(expected); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !os.SameFile(originalInfo, pathInfo) {
		return fmt.Errorf("startup script changed before migration publish: %s", path)
	}
	current, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(current, legacy) {
		return fmt.Errorf("startup script contents changed before migration publish: %s", path)
	}
	return os.Rename(tmpPath, path)
}
