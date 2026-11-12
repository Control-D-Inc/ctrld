//go:build !unix

package cli

import (
	"io/fs"
	"os"
)

// copyFileOwner does nothing: a new file on Windows gets its access rules
// from its folder.
func copyFileOwner(*os.File, fs.FileInfo) error {
	return nil
}
