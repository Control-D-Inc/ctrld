//go:build !linux

package router

func withMerlinServiceLock(fn func() error) error {
	return fn()
}
