//go:build !windows

package ctrld

import "context"

// partOfDomainOrWorkgroup checks if the computer is part of a domain or workgroup and returns "true" or "false".
func partOfDomainOrWorkgroup(ctx context.Context) string {
	return "false"
}
