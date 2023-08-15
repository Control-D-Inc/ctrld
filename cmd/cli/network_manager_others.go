//go:build !linux

package cli

func setupNetworkManager() error {
	reloadNetworkManager()
	return nil
}

func restoreNetworkManager() error {
	reloadNetworkManager()
	return nil
}

func reloadNetworkManager() {}
