package cli

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// The macOS pf intercept exempts ctrld's own traffic by group: ctrld runs with
// the _ctrld group as its effective GID and the anchor passes that GID. The
// group is ctrld's, so its number must not be shared with, or wanted by, any
// other software.
//
// Older builds took the first free GID from 350. Nix installers (Lix,
// Determinate, the official installer and nix-darwin) create the nixbld group
// at exactly 350 on macOS and refuse to install when it is taken, and macOS's
// own daemon groups reach into the 300s and 400s. 600-699 sits above Apple's
// reserved system range (below 500) and the first local user (501, with UIDs
// and GIDs counting up from there), and below the 30000 legacy Nix range.
const (
	ctrldGroupGIDMin = 600
	ctrldGroupGIDMax = 699
)

// groupDirectory is the subset of macOS Directory Services the _ctrld group
// needs. It is an interface so the decisions below are testable off macOS.
type groupDirectory interface {
	// localGID returns the PrimaryGroupID of the named group in the local
	// node, and false if the group does not exist there.
	localGID(name string) (gid int, found bool, err error)
	// localGIDs returns every PrimaryGroupID in use in the local node.
	localGIDs() (map[int]bool, error)
	// groupsWithGID returns the names of all groups, in every directory node
	// macOS searches (local, LDAP, Active Directory), whose PrimaryGroupID is gid.
	groupsWithGID(gid int) ([]string, error)
	createGroup(name string, gid int) error
	setGID(name string, gid int) error
	deleteGroup(name string) error
}

// errNoFreeCtrldGID means every GID in ctrld's range is taken.
var errNoFreeCtrldGID = fmt.Errorf("no unused GID in %d-%d", ctrldGroupGIDMin, ctrldGroupGIDMax)

// ensureCtrldGroupIn makes sure the named group exists with a GID inside
// ctrld's range that no other group uses, and returns that GID.
//
// An existing group keeps its GID when it is in range and unshared, so a
// restart never changes it. A group outside the range (created by an older
// build, typically at 350) or sharing its GID with another group (something
// else took the number after ctrld did) moves to a free GID in the range.
// If the move fails, the old GID is kept: interception with the old number
// still works, and failing to start would take DNS protection away.
func ensureCtrldGroupIn(dir groupDirectory, name string) (int, error) {
	cur, found, err := dir.localGID(name)
	if err != nil {
		return 0, fmt.Errorf("could not read group %s: %w", name, err)
	}
	if !found {
		gid, err := freeCtrldGID(dir, name)
		if err != nil {
			return 0, err
		}
		if err := dir.createGroup(name, gid); err != nil {
			return 0, fmt.Errorf("could not create group %s: %w", name, err)
		}
		mainLog.Load().Info().Msgf("DNS intercept: created system group %s with GID %d", name, gid)
		return gid, nil
	}

	reason := ""
	if cur < ctrldGroupGIDMin || cur > ctrldGroupGIDMax {
		reason = fmt.Sprintf("GID %d is outside %d-%d", cur, ctrldGroupGIDMin, ctrldGroupGIDMax)
	} else if others, err := otherGroupsWithGID(dir, name, cur); err != nil {
		// Without the directory answer there is no evidence of a clash, and
		// moving on a guess would churn the GID on every start.
		mainLog.Load().Debug().Err(err).Msgf("DNS intercept: could not check whether GID %d is shared", cur)
	} else if len(others) > 0 {
		reason = fmt.Sprintf("GID %d is also used by %s", cur, strings.Join(others, ", "))
	}
	if reason == "" {
		mainLog.Load().Debug().Msgf("DNS intercept: group %s already exists with GID %d", name, cur)
		return cur, nil
	}

	gid, err := freeCtrldGID(dir, name)
	if err == nil {
		err = dir.setGID(name, gid)
	}
	if err != nil {
		mainLog.Load().Warn().Err(err).Msgf("DNS intercept: group %s needs a new GID (%s) but could not get one; keeping GID %d", name, reason, cur)
		return cur, nil
	}
	mainLog.Load().Info().Msgf("DNS intercept: moved system group %s from GID %d to %d (%s)", name, cur, gid, reason)
	return gid, nil
}

// freeCtrldGID returns the lowest GID in ctrld's range that no group uses,
// either locally or in any directory node macOS searches.
func freeCtrldGID(dir groupDirectory, name string) (int, error) {
	used, err := dir.localGIDs()
	if err != nil {
		return 0, fmt.Errorf("could not list groups: %w", err)
	}
	for gid := ctrldGroupGIDMin; gid <= ctrldGroupGIDMax; gid++ {
		if used[gid] {
			continue
		}
		others, err := otherGroupsWithGID(dir, name, gid)
		if err != nil {
			// A slow or unreachable directory node must not stop intercept from
			// starting. The local node is still checked, and a later start moves
			// the group if the directory turns out to use this GID.
			mainLog.Load().Debug().Err(err).Msg("DNS intercept: directory search unavailable; choosing a GID from local groups only")
			return gid, nil
		}
		if len(others) == 0 {
			return gid, nil
		}
	}
	return 0, errNoFreeCtrldGID
}

func otherGroupsWithGID(dir groupDirectory, name string, gid int) ([]string, error) {
	groups, err := dir.groupsWithGID(gid)
	if err != nil {
		return nil, err
	}
	var others []string
	for _, g := range groups {
		if g != name {
			others = append(others, g)
		}
	}
	return others, nil
}

// errDSRecordNotFound is how dscl reports a missing record or attribute.
var errDSRecordNotFound = errors.New("eDSRecordNotFound")

// parseDsclPrimaryGroupID parses `dscl . -read /Groups/<name> PrimaryGroupID`.
// dscl prints "PrimaryGroupID: 350", or the value on the next line when it is
// long, and reports a missing group with eDSRecordNotFound.
func parseDsclPrimaryGroupID(out string) (int, error) {
	if strings.Contains(out, "eDSRecordNotFound") || strings.Contains(out, "No such key: PrimaryGroupID") {
		return 0, errDSRecordNotFound
	}
	_, value, ok := strings.Cut(out, "PrimaryGroupID:")
	if !ok {
		return 0, fmt.Errorf("unexpected dscl output %q", strings.TrimSpace(out))
	}
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return 0, fmt.Errorf("unexpected dscl output %q", strings.TrimSpace(out))
	}
	gid, err := strconv.Atoi(fields[0])
	if err != nil {
		return 0, fmt.Errorf("unexpected dscl output %q: %w", strings.TrimSpace(out), err)
	}
	return gid, nil
}

// parseDsclGIDList parses `dscl . -list /Groups PrimaryGroupID`: one
// "<name> <gid>" line per group, separated by spaces.
func parseDsclGIDList(out string) map[int]bool {
	used := make(map[int]bool)
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if gid, err := strconv.Atoi(fields[len(fields)-1]); err == nil {
			used[gid] = true
		}
	}
	return used
}

// parseDsclSearch parses `dscl /Search -search /Groups PrimaryGroupID <gid>`,
// which prints each matching record as "<name>\t\tPrimaryGroupID = (" followed
// by indented values and ")". No output means no match.
func parseDsclSearch(out string) []string {
	var names []string
	for _, line := range strings.Split(out, "\n") {
		if line == "" || line[0] == ' ' || line[0] == '\t' || line[0] == ')' {
			continue
		}
		name, _, ok := strings.Cut(line, "\t")
		if !ok {
			continue
		}
		if name = strings.TrimSpace(name); name != "" {
			names = append(names, name)
		}
	}
	return names
}
