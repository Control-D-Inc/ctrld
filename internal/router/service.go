package router

import (
	"bytes"
	"os"
	"os/exec"

	"github.com/kardianos/service"

	"github.com/Control-D-Inc/ctrld/internal/router/ddwrt"
	"github.com/Control-D-Inc/ctrld/internal/router/merlin"
	"github.com/Control-D-Inc/ctrld/internal/router/tomato"
	"github.com/Control-D-Inc/ctrld/internal/router/ubios"
)

func init() {
	systems := []service.System{
		&linuxSystemService{
			name:   "ddwrt",
			detect: func() bool { return Name() == ddwrt.Name },
			interactive: func() bool {
				is, _ := isInteractive()
				return is
			},
			new: newddwrtService,
		},
		&linuxSystemService{
			name:   "merlin",
			detect: func() bool { return Name() == merlin.Name },
			interactive: func() bool {
				is, _ := isInteractive()
				return is
			},
			new: newMerlinService,
		},
		&linuxSystemService{
			name: "ubios",
			detect: func() bool {
				if Name() != ubios.Name {
					return false
				}
				out, err := exec.Command("ubnt-device-info", "firmware").CombinedOutput()
				if err == nil {
					// For v2/v3, UbiOS use a Debian base with systemd, so it is not
					// necessary to use custom implementation for supporting init system.
					return bytes.HasPrefix(out, []byte("1."))
				}
				return true
			},
			interactive: func() bool {
				is, _ := isInteractive()
				return is
			},
			new: newUbiosService,
		},
		&linuxSystemService{
			name:   "tomato",
			detect: func() bool { return Name() == tomato.Name },
			interactive: func() bool {
				is, _ := isInteractive()
				return is
			},
			new: newTomatoService,
		},
	}
	systems = append(systems, service.AvailableSystems()...)
	service.ChooseSystem(systems...)
}

type linuxSystemService struct {
	name        string
	detect      func() bool
	interactive func() bool
	new         func(i service.Interface, platform string, c *service.Config) (service.Service, error)
}

func (sc linuxSystemService) String() string {
	return sc.name
}
func (sc linuxSystemService) Detect() bool {
	return sc.detect()
}
func (sc linuxSystemService) Interactive() bool {
	return sc.interactive()
}
func (sc linuxSystemService) New(i service.Interface, c *service.Config) (service.Service, error) {
	return sc.new(i, sc.String(), c)
}

func isInteractive() (bool, error) {
	ppid := os.Getppid()
	if ppid == 1 {
		return false, nil
	}
	return true, nil
}
