//go:build !linux

package main

func setupNetworkManager() error {
	return nil
}

func restoreNetworkManager() error {
	return nil
}

func reloadNetworkManager() {}
