package cli

import (
	"errors"
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// hasElevatedPrivilege checks if the current process has elevated privileges on Windows
func hasElevatedPrivilege() (bool, error) {
	var sid *windows.SID
	if err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0,
		0,
		0,
		0,
		0,
		0,
		&sid,
	); err != nil {
		return false, err
	}
	token := windows.Token(0)
	return token.IsMember(sid)
}

// serviceLiveness is what could be established about the installed ctrld service. The
// three states are distinct because a caller that must not disturb a live service has to
// treat "could not tell" like "live", not like "stopped".
type serviceLiveness int

const (
	// serviceLivenessUnknown means the question could not be answered: the SCM was
	// unreachable, the caller lacked rights, or the query failed.
	serviceLivenessUnknown serviceLiveness = iota
	// serviceLivenessRunning means the service is running, starting, or paused - in every
	// case a process that owns state.
	serviceLivenessRunning
	// serviceLivenessStopped means the service is installed and stopped, or not installed
	// at all. Nothing of ctrld's is live.
	serviceLivenessStopped
)

// ctrldServiceLiveness reports what can be established about the installed ctrld service.
//
// Only serviceLivenessStopped is positive evidence that nothing is live. Every failure
// answers serviceLivenessUnknown rather than folding into "stopped": the SCM being
// unreachable says nothing about whether a service is running, and a caller that acts on
// that as absence would strip a live service's state.
//
// "Not installed" is deliberately stopped, not unknown: that is the answer, and it is
// exactly the host that needs stale state cleaned - an uninstall that left filters behind
// has no service left to protect.
func ctrldServiceLiveness() serviceLiveness {
	m, err := mgr.Connect()
	if err != nil {
		return serviceLivenessUnknown
	}
	defer m.Disconnect()

	s, err := m.OpenService(ctrldServiceName)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return serviceLivenessStopped
		}
		return serviceLivenessUnknown
	}
	defer s.Close()

	status, err := s.Query()
	if err != nil {
		return serviceLivenessUnknown
	}
	switch status.State {
	case svc.Running, svc.StartPending, svc.ContinuePending, svc.PausePending, svc.Paused:
		return serviceLivenessRunning
	case svc.Stopped:
		return serviceLivenessStopped
	default:
		// StopPending, and any state a later Windows adds: a process may still be
		// holding its state, so this is no answer.
		return serviceLivenessUnknown
	}
}

// ConfigureWindowsServiceFailureActions checks if the given service
// has the correct failure actions configured, and updates them if not.
func ConfigureWindowsServiceFailureActions(serviceName string) error {
	if runtime.GOOS != "windows" {
		return nil // no-op on non-Windows
	}

	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer s.Close()

	// 1. Retrieve the current config
	cfg, err := s.Config()
	if err != nil {
		return err
	}

	// 2. Update the Description
	cfg.Description = "A highly configurable, multi-protocol DNS forwarding proxy"

	// 3. Apply the updated config
	if err := s.UpdateConfig(cfg); err != nil {
		return err
	}

	// Recovery policy for a service that carries enforcement.
	//
	// ctrld's WFP session is dynamic, so Windows removes its filters when the process
	// dies - a host with no ctrld is unfiltered rather than locked out. That makes the
	// restart budget part of the enforcement story: three restarts five seconds apart
	// with a two-minute reset window could be spent inside fifteen seconds, after which
	// the service stays stopped and the host stays unfiltered until an operator acts.
	//
	// The delays back off instead, and the reset window is long enough that a burst
	// cannot exhaust the budget faster than the backoff allows. A genuine crash loop
	// still ends in a stopped service - that is the point of a bounded policy - but it
	// takes minutes rather than seconds, and the third restart survives a transient
	// failure that repeats.
	actions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: time.Second * 5},
		{Type: mgr.ServiceRestart, Delay: time.Second * 30},
		{Type: mgr.ServiceRestart, Delay: time.Minute * 2},
	}

	// Reset the failure count only after the service has stayed up longer than the whole
	// backoff schedule, so repeated failures keep escalating instead of restarting the
	// count from the first five-second delay.
	err = s.SetRecoveryActions(actions, uint32((10 * time.Minute).Seconds()))
	if err != nil {
		return err
	}

	// Ensure that failure actions are NOT triggered on user-initiated stops.
	var failureActionsFlag windows.SERVICE_FAILURE_ACTIONS_FLAG
	failureActionsFlag.FailureActionsOnNonCrashFailures = 0

	if err := windows.ChangeServiceConfig2(
		s.Handle,
		windows.SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
		(*byte)(unsafe.Pointer(&failureActionsFlag)),
	); err != nil {
		return err
	}

	return nil
}

// openLogFile opens a log file with the specified mode on Windows
func openLogFile(path string, mode int) (*os.File, error) {
	if len(path) == 0 {
		return nil, &os.PathError{Path: path, Op: "open", Err: syscall.ERROR_FILE_NOT_FOUND}
	}

	pathP, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	var access uint32
	switch mode & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR) {
	case os.O_RDONLY:
		access = windows.GENERIC_READ
	case os.O_WRONLY:
		access = windows.GENERIC_WRITE
	case os.O_RDWR:
		access = windows.GENERIC_READ | windows.GENERIC_WRITE
	}
	if mode&os.O_CREATE != 0 {
		access |= windows.GENERIC_WRITE
	}
	if mode&os.O_APPEND != 0 {
		access &^= windows.GENERIC_WRITE
		access |= windows.FILE_APPEND_DATA
	}

	shareMode := uint32(syscall.FILE_SHARE_READ | syscall.FILE_SHARE_WRITE | syscall.FILE_SHARE_DELETE)

	var sa *syscall.SecurityAttributes

	var createMode uint32
	switch {
	case mode&(os.O_CREATE|os.O_EXCL) == (os.O_CREATE | os.O_EXCL):
		createMode = windows.CREATE_NEW
	case mode&(os.O_CREATE|os.O_TRUNC) == (os.O_CREATE | os.O_TRUNC):
		createMode = windows.CREATE_ALWAYS
	case mode&os.O_CREATE == os.O_CREATE:
		createMode = windows.OPEN_ALWAYS
	case mode&os.O_TRUNC == os.O_TRUNC:
		createMode = windows.TRUNCATE_EXISTING
	default:
		createMode = windows.OPEN_EXISTING
	}

	handle, err := syscall.CreateFile(pathP, access, shareMode, sa, createMode, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Path: path, Op: "open", Err: err}
	}

	return os.NewFile(uintptr(handle), path), nil
}
