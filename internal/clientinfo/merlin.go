package clientinfo

import (
	"strings"
	"sync"

	"github.com/Control-D-Inc/ctrld/internal/router"
	"github.com/Control-D-Inc/ctrld/internal/router/merlin"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/router/nvram"
)

const merlinNvramCustomClientListKey = "custom_clientlist"

type merlinDiscover struct {
	hostname sync.Map // mac => hostname
}

func (m *merlinDiscover) refresh() error {
	if router.Name() != merlin.Name {
		return nil
	}
	out, err := nvram.Run("get", merlinNvramCustomClientListKey)
	if err != nil {
		return err
	}
	ctrld.ProxyLog.Debug().Msg("reading Merlin custom client list")
	m.parseMerlinCustomClientList(out)
	return nil
}

func (m *merlinDiscover) LookupHostnameByIP(ip string) string {
	return ""
}

func (m *merlinDiscover) LookupHostnameByMac(mac string) string {
	val, ok := m.hostname.Load(mac)
	if !ok {
		return ""
	}
	return val.(string)
}

// "nvram get custom_clientlist" output:
//
// <client 1>00:00:00:00:00:01>0>4>><client 2>00:00:00:00:00:02>0>24>>...
//
// So to parse it, do the following steps:
//
//   - Split by "<"                 => entries
//   - For each entry, split by ">" => parts
//   - Empty parts                  => skip
//   - Empty parts[0]               => skip empty hostname
//   - Empty parts[1]               => skip empty MAC
func (m *merlinDiscover) parseMerlinCustomClientList(data string) {
	entries := strings.Split(data, "<")
	for _, entry := range entries {
		parts := strings.SplitN(string(entry), ">", 3)
		if len(parts) < 2 || len(parts[0]) == 0 || len(parts[1]) == 0 {
			continue
		}
		hostname := normalizeHostname(parts[0])
		mac := strings.ToLower(parts[1])
		m.hostname.Store(mac, hostname)
	}
}

func (m *merlinDiscover) String() string {
	return "merlin"
}
