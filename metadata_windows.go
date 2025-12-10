package ctrld

import (
	"context"

	"github.com/Control-D-Inc/ctrld/internal/system"
)

// partOfDomainOrWorkgroup checks if the computer is part of a domain or workgroup and returns "true" or "false".
func partOfDomainOrWorkgroup(ctx context.Context) string {
	status, err := system.DomainJoinedStatus()
	if err != nil {
		ProxyLogger.Load().Debug().Err(err).Msg("Failed to get domain join status")
		return "false"
	}
	switch status {
	case 2, 3:
		return "true"
	default:
		return "false"
	}
}
