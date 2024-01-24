package clientinfo

import (
	"bytes"
	"encoding/json"
	"io"
	"os/exec"
	"strings"
	"sync"

	"github.com/Control-D-Inc/ctrld/internal/router"
	"github.com/Control-D-Inc/ctrld/internal/router/ubios"
)

// ubiosDiscover provides client discovery functionality on Ubios routers.
type ubiosDiscover struct {
	hostname sync.Map // mac => hostname
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
	cmd := exec.Command("/usr/bin/mongo", "localhost:27117/ace", "--quiet", "--eval", `
		DBQuery.shellBatchSize = 256;
		db.user.find({name: {$exists: true, $ne: ""}}, {_id:0, mac:1, name:1});`)
	b, err := cmd.Output()
	if err != nil {
		return err
	}
	return u.storeDevices(bytes.NewReader(b))
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
