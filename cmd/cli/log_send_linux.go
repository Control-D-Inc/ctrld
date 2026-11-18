package cli

import (
	"errors"
	"golang.org/x/sys/unix"
)

// Linux supplies real peer credentials for the portable boundary tests; the
// production capability and CLI remain disabled on this platform.
func logSendPeerUID(fd int) (uint32, error) {
	cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return 0, err
	}
	return cred.Uid, nil
}
func logSendCheckACL(fd int) error {
	_, err := unix.Fgetxattr(fd, "system.posix_acl_access", nil)
	if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.ENOTSUP) {
		return nil
	}
	if err != nil {
		return err
	}
	return errLogSendTrust
}
