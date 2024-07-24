//go:build !windows

package cli

var supportedSelfDelete = true

func selfDeleteExe() error { return nil }
