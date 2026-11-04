//go:build !windows

package system

// GetActiveDirectoryDomain returns AD domain name of this computer.
func GetActiveDirectoryDomain() (string, error) {
	return "", nil
}
