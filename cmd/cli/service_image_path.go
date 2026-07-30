package cli

import "strings"

// serviceBinaryFromImagePath extracts the executable path from a Windows service
// ImagePath value, which carries the command line rather than a bare path: it may be
// quoted and is usually followed by arguments, e.g.
//
//	"C:\Program Files\Control D\ctrld.exe" run --config C:\...\ctrld.toml
//
// It returns "" when no path can be read, which callers must treat as "cannot tell"
// rather than "does not match".
func serviceBinaryFromImagePath(imagePath string) string {
	imagePath = strings.TrimSpace(imagePath)
	if imagePath == "" {
		return ""
	}
	if imagePath[0] == '"' {
		// Quoted form: everything up to the closing quote is the path, so a directory
		// containing spaces stays intact.
		if end := strings.IndexByte(imagePath[1:], '"'); end >= 0 {
			return strings.TrimSpace(imagePath[1 : 1+end])
		}
		return strings.TrimSpace(imagePath[1:])
	}
	// Unquoted form: the path cannot contain spaces, so the first field is it.
	if idx := strings.IndexByte(imagePath, ' '); idx >= 0 {
		return strings.TrimSpace(imagePath[:idx])
	}
	return imagePath
}

// sameExecutableDir reports whether two Windows executable paths live in the same
// directory, compared case-insensitively because Windows paths are.
//
// The separator handling is explicit rather than filepath's, because filepath follows the
// *host* rules: off Windows it does not treat "\\" as a separator, so every backslash path
// would reduce to the same directory and any two paths would compare equal. Doing it here
// keeps the comparison correct and testable on any host.
//
// A path with no directory part answers false, which callers read as "cannot tell".
func sameExecutableDir(a, b string) bool {
	dirA, dirB := windowsExecutableDir(a), windowsExecutableDir(b)
	if dirA == "" || dirB == "" {
		return false
	}
	return strings.EqualFold(dirA, dirB)
}

// windowsExecutableDir returns the directory part of a Windows path, accepting either
// separator and normalising to a backslash. It returns "" when there is no directory part.
func windowsExecutableDir(path string) string {
	path = strings.TrimSpace(path)
	idx := strings.LastIndexAny(path, `\/`)
	if idx <= 0 {
		return ""
	}
	return strings.ReplaceAll(path[:idx], "/", `\`)
}
