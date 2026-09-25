//go:build !windows

package cli

// installedServiceDirMatches is Windows-only: it exists because socketDir() there is
// relative to the running executable. Other platforms answer this question through
// hasElevatedPrivilege in readinessVerifiable.
func installedServiceDirMatches() bool { return true }
