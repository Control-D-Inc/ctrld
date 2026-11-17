package clientinfo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/Control-D-Inc/ctrld/internal/router"
	"github.com/Control-D-Inc/ctrld/internal/router/ubios"
)

const (
	defaultUbiosMongoPath = "/usr/bin/mongo"

	// UniFi Network 11 keeps its application data in PostgreSQL instead of MongoDB.
	defaultUbiosPsqlPath        = "/usr/bin/psql"
	defaultUbiosPostgresSocket  = "/run/postgresql/.s.PGSQL.5434"
	ubiosPostgresSocketDir      = "/run/postgresql"
	ubiosPostgresPort           = "5434"
	ubiosPostgresUser           = "unifi_network_admin"
	ubiosPostgresDatabase       = "unifi-network"
	ubiosPostgresQueryTimeout   = 10 * time.Second
	ubiosPostgresClientNameStmt = `SELECT json_build_object('mac', mac, 'name', name) FROM config.user_client WHERE name IS NOT NULL AND name <> ''`
)

// ubiosDiscover provides client discovery functionality on Ubios routers.
type ubiosDiscover struct {
	hostname       sync.Map // mac => hostname
	mongoPath      string
	psqlPath       string
	postgresSocket string
}

// refresh reloads unifi devices from database.
func (u *ubiosDiscover) refresh() error {
	if router.Name() != ubios.Name {
		return nil
	}
	return u.refreshDevices()
}

// LookupHostnameByIP returns hostname for given IP.
func (u *ubiosDiscover) LookupHostnameByIP(ip string) string {
	return ""
}

// LookupHostnameByMac returns unifi device custom hostname for the given MAC address.
func (u *ubiosDiscover) LookupHostnameByMac(mac string) string {
	val, ok := u.hostname.Load(mac)
	if !ok {
		return ""
	}
	return val.(string)
}

// refreshDevices updates unifi devices name from the UniFi Network database.
//
// UniFi Network 11 moved from MongoDB to PostgreSQL. When its PostgreSQL socket
// exists, PostgreSQL is the only source: the old MongoDB data stays on disk after
// the migration and would return stale names.
func (u *ubiosDiscover) refreshDevices() error {
	_, err := os.Stat(u.postgresSocketPath())
	switch {
	case err == nil:
		return u.refreshDevicesFromPostgres()
	case !errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("stat unifi postgres socket: %w", err)
	}
	return u.refreshDevicesFromMongo()
}

// refreshDevicesFromPostgres reads unifi devices name from the UniFi Network 11 PostgreSQL database.
func (u *ubiosDiscover) refreshDevicesFromPostgres() error {
	psqlPath := u.psqlExecutable()
	if !isExecutableFile(psqlPath) {
		return fmt.Errorf("unifi postgres socket found, but %s is not an executable file", psqlPath)
	}

	ctx, cancel := context.WithTimeout(context.Background(), ubiosPostgresQueryTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, psqlPath,
		"-h", ubiosPostgresSocketDir,
		"-p", ubiosPostgresPort,
		"-U", ubiosPostgresUser,
		"-d", ubiosPostgresDatabase,
		"-X",             // skip psqlrc
		"-w",             // never prompt for a password
		"-q", "-A", "-t", // one bare value per row
		"-v", "ON_ERROR_STOP=1",
		"-c", ubiosPostgresClientNameStmt,
	)
	cmd.Env = append(os.Environ(),
		"PGCONNECT_TIMEOUT=5",
		"PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=5000",
	)
	cmd.WaitDelay = time.Second
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return fmt.Errorf("query unifi postgres: %s: %w", strings.TrimSpace(stderr.String()), err)
	}
	return u.storeDevices(&stdout)
}

// refreshDevicesFromMongo reads unifi devices name from the local mongodb used before UniFi Network 11.
func (u *ubiosDiscover) refreshDevicesFromMongo() error {
	mongoPath := u.mongoExecutable()
	fi, err := os.Stat(mongoPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat mongo executable: %w", err)
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0111 == 0 {
		return nil
	}

	cmd := exec.Command(mongoPath, "localhost:27117/ace", "--quiet", "--eval", `
		DBQuery.shellBatchSize = 256;
		db.user.find({name: {$exists: true, $ne: ""}}, {_id:0, mac:1, name:1});`)
	b, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("out: %s, err: %w", string(b), err)
	}
	return u.storeDevices(bytes.NewReader(b))
}

func (u *ubiosDiscover) mongoExecutable() string {
	if u.mongoPath != "" {
		return u.mongoPath
	}
	return defaultUbiosMongoPath
}

func (u *ubiosDiscover) psqlExecutable() string {
	if u.psqlPath != "" {
		return u.psqlPath
	}
	return defaultUbiosPsqlPath
}

func (u *ubiosDiscover) postgresSocketPath() string {
	if u.postgresSocket != "" {
		return u.postgresSocket
	}
	return defaultUbiosPostgresSocket
}

func isExecutableFile(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0111 != 0
}

// storeDevices saves unifi devices name for caching.
func (u *ubiosDiscover) storeDevices(r io.Reader) error {
	decoder := json.NewDecoder(r)
	for {
		// A new value per record, so a missing field does not keep the previous record's value.
		var device struct {
			MAC  string
			Name string
		}
		err := decoder.Decode(&device)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if device.MAC == "" || device.Name == "" {
			continue
		}
		mac := strings.ToLower(device.MAC)
		u.hostname.Store(mac, normalizeHostname(device.Name))
	}
	return nil
}

// String returns human-readable format of ubiosDiscover.
func (u *ubiosDiscover) String() string {
	return "ubios"
}
