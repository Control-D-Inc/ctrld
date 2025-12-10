package system

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"unsafe"

	"github.com/microsoft/wmi/pkg/base/host"
	hh "github.com/microsoft/wmi/pkg/hardware/host"
	"golang.org/x/sys/windows"
)

// GetActiveDirectoryDomain returns AD domain name of this computer.
func GetActiveDirectoryDomain() (string, error) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	// 1) Check environment variable
	envDomain := os.Getenv("USERDNSDOMAIN")
	if envDomain != "" {
		return strings.TrimSpace(envDomain), nil
	}

	// 2) Query WMI via the microsoft/wmi library
	whost := host.NewWmiLocalHost()
	cs, err := hh.GetComputerSystem(whost)
	if cs != nil {
		defer cs.Close()
	}
	if err != nil {
		return "", err
	}
	pod, err := cs.GetPropertyPartOfDomain()
	if err != nil {
		return "", err
	}
	if pod {
		domainVal, err := cs.GetPropertyDomain()
		if err != nil {
			return "", fmt.Errorf("failed to get domain property: %w", err)
		}
		domainName := strings.TrimSpace(fmt.Sprintf("%v", domainVal))
		if domainName == "" {
			return "", errors.New("machine does not appear to have a domain set")
		}
		return domainName, nil
	}
	return "", nil
}

// DomainJoinedStatus returns the domain joined status of the current computer.
//
// NETSETUP_JOIN_STATUS constants from Microsoft Windows API
// See: https://learn.microsoft.com/en-us/windows/win32/api/lmjoin/ne-lmjoin-netsetup_join_status
//
// NetSetupUnknownStatus         uint32 = 0 // The status is unknown
// NetSetupUnjoined              uint32 = 1 // The computer is not joined to a domain or workgroup
// NetSetupWorkgroupName         uint32 = 2 // The computer is joined to a workgroup
// NetSetupDomainName            uint32 = 3 // The computer is joined to a domain
func DomainJoinedStatus() (uint32, error) {
	var domain *uint16
	var status uint32

	if err := windows.NetGetJoinInformation(nil, &domain, &status); err != nil {
		return 0, fmt.Errorf("failed to get domain join status: %w", err)
	}
	defer windows.NetApiBufferFree((*byte)(unsafe.Pointer(domain)))

	return status, nil
}
