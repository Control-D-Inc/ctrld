package cli

import (
	"errors"
	"fmt"
	"slices"
	"testing"
)

// fakeGroupDirectory models the local node plus groups that only a bound
// directory (LDAP, Active Directory) shows through /Search.
type fakeGroupDirectory struct {
	local     map[string]int
	directory map[string]int
	searchErr error
	setErr    error
	calls     []string
}

func (f *fakeGroupDirectory) localGID(name string) (int, bool, error) {
	gid, ok := f.local[name]
	return gid, ok, nil
}

func (f *fakeGroupDirectory) localGIDs() (map[int]bool, error) {
	used := map[int]bool{}
	for _, gid := range f.local {
		used[gid] = true
	}
	return used, nil
}

func (f *fakeGroupDirectory) groupsWithGID(gid int) ([]string, error) {
	if f.searchErr != nil {
		return nil, f.searchErr
	}
	var names []string
	for _, m := range []map[string]int{f.local, f.directory} {
		for name, g := range m {
			if g == gid {
				names = append(names, name)
			}
		}
	}
	slices.Sort(names)
	return names, nil
}

func (f *fakeGroupDirectory) createGroup(name string, gid int) error {
	f.calls = append(f.calls, "create")
	f.local[name] = gid
	return nil
}

func (f *fakeGroupDirectory) setGID(name string, gid int) error {
	f.calls = append(f.calls, "set")
	if f.setErr != nil {
		return f.setErr
	}
	f.local[name] = gid
	return nil
}

func (f *fakeGroupDirectory) deleteGroup(name string) error {
	delete(f.local, name)
	return nil
}

// A stock Mac with nothing in ctrld's range gets the first GID of the range,
// never 350, which Nix installers need for nixbld.
func TestEnsureCtrldGroupCreatesOutsideNixGID(t *testing.T) {
	dir := &fakeGroupDirectory{local: map[string]int{"staff": 20, "admin": 80, "_oahd": 441}}
	gid, err := ensureCtrldGroupIn(dir, "_ctrld")
	if err != nil {
		t.Fatal(err)
	}
	if gid != ctrldGroupGIDMin || dir.local["_ctrld"] != ctrldGroupGIDMin {
		t.Fatalf("gid = %d, stored %d; want %d", gid, dir.local["_ctrld"], ctrldGroupGIDMin)
	}
	if gid == 350 {
		t.Fatal("ctrld took GID 350, the macOS Nix build group default")
	}
}

// An older build left _ctrld at 350; the next start moves it into ctrld's
// range so a Nix install that runs afterwards finds 350 free.
func TestEnsureCtrldGroupMovesLegacyGID(t *testing.T) {
	dir := &fakeGroupDirectory{local: map[string]int{"_ctrld": 350, "staff": 20}}
	gid, err := ensureCtrldGroupIn(dir, "_ctrld")
	if err != nil {
		t.Fatal(err)
	}
	if gid != ctrldGroupGIDMin || dir.local["_ctrld"] != ctrldGroupGIDMin {
		t.Fatalf("gid = %d, stored %d; want %d", gid, dir.local["_ctrld"], ctrldGroupGIDMin)
	}
}

// A group already in range and unshared keeps its GID and is not rewritten.
func TestEnsureCtrldGroupKeepsGoodGID(t *testing.T) {
	dir := &fakeGroupDirectory{local: map[string]int{"_ctrld": 612}}
	gid, err := ensureCtrldGroupIn(dir, "_ctrld")
	if err != nil {
		t.Fatal(err)
	}
	if gid != 612 || len(dir.calls) != 0 {
		t.Fatalf("gid = %d, calls %v; want 612 and no writes", gid, dir.calls)
	}
}

// Another product created a group with ctrld's GID after ctrld did. Sharing
// it would make pf exempt that product's DNS too, so ctrld moves.
func TestEnsureCtrldGroupMovesOffSharedGID(t *testing.T) {
	dir := &fakeGroupDirectory{local: map[string]int{"_ctrld": 600, "_vendor": 600}}
	gid, err := ensureCtrldGroupIn(dir, "_ctrld")
	if err != nil {
		t.Fatal(err)
	}
	if gid != 601 {
		t.Fatalf("gid = %d; want 601", gid)
	}
}

// A GID used only in a bound directory (Active Directory, LDAP) is not in the
// local list but still resolves on the Mac, so it is skipped too.
func TestEnsureCtrldGroupSkipsDirectoryGIDs(t *testing.T) {
	dir := &fakeGroupDirectory{
		local:     map[string]int{"staff": 20},
		directory: map[string]int{"corp-eng": 600, "corp-ops": 601},
	}
	gid, err := ensureCtrldGroupIn(dir, "_ctrld")
	if err != nil {
		t.Fatal(err)
	}
	if gid != 602 {
		t.Fatalf("gid = %d; want 602", gid)
	}
}

// If the group cannot move, ctrld keeps the old GID rather than refusing to
// start intercept: the exemption still works with it.
func TestEnsureCtrldGroupKeepsLegacyGIDWhenMoveFails(t *testing.T) {
	dir := &fakeGroupDirectory{local: map[string]int{"_ctrld": 350}, setErr: errors.New("dscl failed")}
	gid, err := ensureCtrldGroupIn(dir, "_ctrld")
	if err != nil {
		t.Fatal(err)
	}
	if gid != 350 || dir.local["_ctrld"] != 350 {
		t.Fatalf("gid = %d, stored %d; want 350 kept", gid, dir.local["_ctrld"])
	}
}

// An unreadable directory search is not evidence of a clash: a good GID stays
// put instead of moving on every start.
func TestEnsureCtrldGroupSearchErrorKeepsGoodGID(t *testing.T) {
	dir := &fakeGroupDirectory{local: map[string]int{"_ctrld": 605}, searchErr: errors.New("node offline")}
	gid, err := ensureCtrldGroupIn(dir, "_ctrld")
	if err != nil {
		t.Fatal(err)
	}
	if gid != 605 || len(dir.calls) != 0 {
		t.Fatalf("gid = %d, calls %v; want 605 and no writes", gid, dir.calls)
	}
}

// A fresh install on a Mac whose directory node is unreachable still gets a
// locally free GID, so intercept can start.
func TestEnsureCtrldGroupSearchErrorStillCreates(t *testing.T) {
	dir := &fakeGroupDirectory{local: map[string]int{"g600": 600}, searchErr: errors.New("node offline")}
	gid, err := ensureCtrldGroupIn(dir, "_ctrld")
	if err != nil {
		t.Fatal(err)
	}
	if gid != 601 {
		t.Fatalf("gid = %d; want 601", gid)
	}
}

func TestEnsureCtrldGroupRangeFull(t *testing.T) {
	local := map[string]int{}
	for gid := ctrldGroupGIDMin; gid <= ctrldGroupGIDMax; gid++ {
		local[fmt.Sprintf("g%d", gid)] = gid
	}
	dir := &fakeGroupDirectory{local: local}
	if _, err := ensureCtrldGroupIn(dir, "_ctrld"); !errors.Is(err, errNoFreeCtrldGID) {
		t.Fatalf("err = %v; want errNoFreeCtrldGID", err)
	}
}

// The single-line read, list, search and missing-group shapes are dscl output
// captured on macOS 27.0.1; the wrapped read is dscl's long-value layout.
func TestParseDscl(t *testing.T) {
	if gid, err := parseDsclPrimaryGroupID("PrimaryGroupID: 350\n"); err != nil || gid != 350 {
		t.Fatalf("read: %d %v", gid, err)
	}
	if gid, err := parseDsclPrimaryGroupID("PrimaryGroupID:\n 612\n"); err != nil || gid != 612 {
		t.Fatalf("read wrapped: %d %v", gid, err)
	}
	if _, err := parseDsclPrimaryGroupID("<dscl_cmd> DS Error: -14136 (eDSRecordNotFound)\n"); !errors.Is(err, errDSRecordNotFound) {
		t.Fatalf("missing: %v", err)
	}
	used := parseDsclGIDList("staff                    20\nadmin                    80\n_oahd                    441\n")
	if !used[20] || !used[80] || !used[441] || len(used) != 3 {
		t.Fatalf("list: %v", used)
	}
	names := parseDsclSearch("staff\t\tPrimaryGroupID = (\n    20\n)\n")
	if !slices.Equal(names, []string{"staff"}) {
		t.Fatalf("search: %v", names)
	}
	if names := parseDsclSearch(""); len(names) != 0 {
		t.Fatalf("empty search: %v", names)
	}
}
