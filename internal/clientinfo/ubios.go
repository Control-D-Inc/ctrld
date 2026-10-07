package clientinfo

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/Control-D-Inc/ctrld/internal/router"
	"github.com/Control-D-Inc/ctrld/internal/router/ubios"
)

const defaultUbiosMongoPath = "/usr/bin/mongo"

// ubiosDiscover provides client discovery functionality on Ubios routers.
type ubiosDiscover struct {
	hostname  sync.Map // mac => hostname
	mongoPath string
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

// refreshDevices updates unifi devices name from local mongodb.
func (u *ubiosDiscover) refreshDevices() error {
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

// storeDevices saves unifi devices name for caching.
func (u *ubiosDiscover) storeDevices(r io.Reader) error {
	decoder := json.NewDecoder(r)
	device := struct {
		MAC  string
		Name string
	}{}
	for {
		err := decoder.Decode(&device)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
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
