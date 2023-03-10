//go:build !linux

package main

func setupNetworkManager() error {
	reloadNetworkManager()
	return nil
}

func restoreNetworkManager() error {
	reloadNetworkManager()
	return nil
}

func reloadNetworkManager() {}
