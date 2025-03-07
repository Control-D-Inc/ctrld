package cli

import (
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/microsoft/wmi/pkg/base/host"
	"github.com/microsoft/wmi/pkg/base/instance"
	"github.com/microsoft/wmi/pkg/base/query"
	"github.com/microsoft/wmi/pkg/constant"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

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

	// Then proceed with existing actions, e.g. setting failure actions
	actions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: time.Second * 5}, // 5 seconds
		{Type: mgr.ServiceRestart, Delay: time.Second * 5}, // 5 seconds
		{Type: mgr.ServiceRestart, Delay: time.Second * 5}, // 5 seconds
	}

	// Set the recovery actions (3 restarts, reset period = 120).
	err = s.SetRecoveryActions(actions, 120)
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

const processEntrySize = uint32(unsafe.Sizeof(windows.ProcessEntry32{}))

// hasLocalDnsServerRunning reports whether we are on Windows and having Dns server running.
func hasLocalDnsServerRunning() bool {
	h, e := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if e != nil {
		return false
	}
	p := windows.ProcessEntry32{Size: processEntrySize}
	for {
		e := windows.Process32Next(h, &p)
		if e != nil {
			return false
		}
		if strings.ToLower(windows.UTF16ToString(p.ExeFile[:])) == "dns.exe" {
			return true
		}
	}
}

func isRunningOnDomainControllerWindows() (bool, int) {
	whost := host.NewWmiLocalHost()
	q := query.NewWmiQuery("Win32_ComputerSystem")
	instances, err := instance.GetWmiInstancesFromHost(whost, string(constant.CimV2), q)
	if err != nil {
		mainLog.Load().Debug().Err(err).Msg("WMI query failed")
		return false, 0
	}
	if instances == nil {
		mainLog.Load().Debug().Msg("WMI query returned nil instances")
		return false, 0
	}
	defer instances.Close()

	if len(instances) == 0 {
		mainLog.Load().Debug().Msg("no rows returned from Win32_ComputerSystem")
		return false, 0
	}

	val, err := instances[0].GetProperty("DomainRole")
	if err != nil {
		mainLog.Load().Debug().Err(err).Msg("failed to get DomainRole property")
		return false, 0
	}
	if val == nil {
		mainLog.Load().Debug().Msg("DomainRole property is nil")
		return false, 0
	}

	// Safely handle varied types: string or integer
	var roleInt int
	switch v := val.(type) {
	case string:
		// "4", "5", etc.
		parsed, parseErr := strconv.Atoi(v)
		if parseErr != nil {
			mainLog.Load().Debug().Err(parseErr).Msgf("failed to parse DomainRole value %q", v)
			return false, 0
		}
		roleInt = parsed
	case int8, int16, int32, int64:
		roleInt = int(reflect.ValueOf(v).Int())
	case uint8, uint16, uint32, uint64:
		roleInt = int(reflect.ValueOf(v).Uint())
	default:
		mainLog.Load().Debug().Msgf("unexpected DomainRole type: %T value=%v", v, v)
		return false, 0
	}

	// Check if role indicates a domain controller
	isDC := roleInt == BackupDomainController || roleInt == PrimaryDomainController
	return isDC, roleInt
}
