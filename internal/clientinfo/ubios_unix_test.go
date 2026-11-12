//go:build unix

package clientinfo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func Test_ubiosDiscover_refreshDevices_usesExecutableMongo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mongo")
	const script = `#!/bin/sh
printf '%s\n' '{"mac":"00:00:00:00:00:01","name":"device 1"}'
`
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}

	ud := &ubiosDiscover{mongoPath: path, postgresSocket: filepath.Join(t.TempDir(), "missing-socket")}
	if err := ud.refreshDevices(); err != nil {
		t.Fatalf("refreshDevices() error = %v", err)
	}
	if got := ud.LookupHostnameByMac("00:00:00:00:00:01"); got != "device 1" {
		t.Fatalf("LookupHostnameByMac() = %q, want %q", got, "device 1")
	}
}

// writeExecutable writes a shell script and returns its path.
func writeExecutable(t *testing.T, dir, name, script string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func Test_ubiosDiscover_refreshDevices_prefersPostgres(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, ".s.PGSQL.5434")
	if err := os.WriteFile(socket, nil, 0600); err != nil {
		t.Fatal(err)
	}
	argsFile := filepath.Join(dir, "psql-args")
	envFile := filepath.Join(dir, "psql-env")
	psql := writeExecutable(t, dir, "psql", `
printf '%s\n' "$@" > '`+argsFile+`'
printf '%s\n' "$PGOPTIONS" > '`+envFile+`'
printf '%s\n' '{"mac" : "AA:BB:CC:00:00:01", "name" : "Living Room TV"}'
printf '%s\n' '{"mac" : "aa:bb:cc:00:00:02", "name" : "Thermostat"}'
`)
	// MongoDB still holds the pre-migration names; it must not be read.
	mongo := writeExecutable(t, dir, "mongo", `
printf '%s\n' '{"mac":"aa:bb:cc:00:00:01","name":"stale name"}'
`)

	ud := &ubiosDiscover{psqlPath: psql, mongoPath: mongo, postgresSocket: socket}
	if err := ud.refreshDevices(); err != nil {
		t.Fatalf("refreshDevices() error = %v", err)
	}
	for mac, want := range map[string]string{
		"aa:bb:cc:00:00:01": "Living Room TV",
		"aa:bb:cc:00:00:02": "Thermostat",
	} {
		if got := ud.LookupHostnameByMac(mac); got != want {
			t.Errorf("LookupHostnameByMac(%q) = %q, want %q", mac, got, want)
		}
	}

	args, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"-h\n/run/postgresql\n", "-p\n5434\n", "-U\nunifi_network_admin\n", "-d\nunifi-network\n", "-w\n", "config.user_client"} {
		if !strings.Contains(string(args), want) {
			t.Errorf("psql args missing %q:\n%s", want, args)
		}
	}
	env, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(env), "default_transaction_read_only=on") {
		t.Errorf("PGOPTIONS = %q, want read-only transactions", env)
	}
}

func Test_ubiosDiscover_refreshDevices_postgresErrors(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, ".s.PGSQL.5434")
	if err := os.WriteFile(socket, nil, 0600); err != nil {
		t.Fatal(err)
	}
	mongo := writeExecutable(t, dir, "mongo", `
printf '%s\n' '{"mac":"aa:bb:cc:00:00:01","name":"stale name"}'
`)

	t.Run("psql missing", func(t *testing.T) {
		ud := &ubiosDiscover{psqlPath: filepath.Join(dir, "no-psql"), mongoPath: mongo, postgresSocket: socket}
		if err := ud.refreshDevices(); err == nil {
			t.Fatal("refreshDevices() error = nil, want error")
		}
		if got := ud.LookupHostnameByMac("aa:bb:cc:00:00:01"); got != "" {
			t.Fatalf("fell back to MongoDB: got %q", got)
		}
	})

	t.Run("query fails", func(t *testing.T) {
		psql := writeExecutable(t, dir, "psql-fail", `
echo 'psql: error: connection refused' >&2
exit 2
`)
		ud := &ubiosDiscover{psqlPath: psql, mongoPath: mongo, postgresSocket: socket}
		err := ud.refreshDevices()
		if err == nil || !strings.Contains(err.Error(), "connection refused") {
			t.Fatalf("refreshDevices() error = %v, want psql stderr", err)
		}
	})
}

func Test_ubiosDiscover_storeDevices_freshRecord(t *testing.T) {
	ud := &ubiosDiscover{}
	r := strings.NewReader(`{"mac":"aa:bb:cc:00:00:01","name":"first"}
{"mac":"aa:bb:cc:00:00:02"}
{"name":"orphan"}
`)
	if err := ud.storeDevices(r); err != nil {
		t.Fatal(err)
	}
	if got := ud.LookupHostnameByMac("aa:bb:cc:00:00:02"); got != "" {
		t.Fatalf("record without a name got %q, want empty", got)
	}
	if got := ud.LookupHostnameByMac("aa:bb:cc:00:00:01"); got != "first" {
		t.Fatalf("got %q, want %q", got, "first")
	}
}
