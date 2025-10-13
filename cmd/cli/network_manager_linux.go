package cli

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/coreos/go-systemd/v22/dbus"
)

const (
	nmConfDir           = "/etc/NetworkManager/conf.d"
	nmCtrldConfFilename = "zz-ctrld.conf"
	nmCtrldConfContent  = `[main]
dns=none
systemd-resolved=false
`
	nmSystemdUnitName = "NetworkManager.service"
)

var networkManagerCtrldConfFile = filepath.Join(nmConfDir, nmCtrldConfFilename)

// hasNetworkManager reports whether NetworkManager executable found.
func hasNetworkManager() bool {
	exe, _ := exec.LookPath("NetworkManager")
	return exe != ""
}

func setupNetworkManager() error {
	if !hasNetworkManager() {
		return nil
	}
	if content, _ := os.ReadFile(nmCtrldConfContent); string(content) == nmCtrldConfContent {
		mainLog.Load().Debug().Msg("NetworkManager already setup, nothing to do")
		return nil
	}
	err := os.WriteFile(networkManagerCtrldConfFile, []byte(nmCtrldConfContent), os.FileMode(0644))
	if os.IsNotExist(err) {
		mainLog.Load().Debug().Msg("NetworkManager is not available")
		return nil
	}
	if err != nil {
		mainLog.Load().Debug().Err(err).Msg("could not write NetworkManager ctrld config file")
		return err
	}

	reloadNetworkManager()
	mainLog.Load().Debug().Msg("setup NetworkManager done")
	return nil
}

func restoreNetworkManager() error {
	if !hasNetworkManager() {
		return nil
	}
	err := os.Remove(networkManagerCtrldConfFile)
	if os.IsNotExist(err) {
		mainLog.Load().Debug().Msg("NetworkManager is not available")
		return nil
	}
	if err != nil {
		mainLog.Load().Debug().Err(err).Msg("could not remove NetworkManager ctrld config file")
		return err
	}

	reloadNetworkManager()
	mainLog.Load().Debug().Msg("restore NetworkManager done")
	return nil
}

func reloadNetworkManager() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	conn, err := dbus.NewSystemConnectionContext(ctx)
	if err != nil {
		mainLog.Load().Error().Err(err).Msg("could not create new system connection")
		return
	}
	defer conn.Close()

	waitCh := make(chan string)
	if _, err := conn.ReloadUnitContext(ctx, nmSystemdUnitName, "ignore-dependencies", waitCh); err != nil {
		mainLog.Load().Debug().Err(err).Msg("could not reload NetworkManager")
		return
	}
	<-waitCh
}
