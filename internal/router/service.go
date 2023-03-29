package router

import (
	"os"

	"github.com/kardianos/service"
)

func init() {
	system := &linuxSystemService{
		name:   "ddwrt",
		detect: func() bool { return Name() == DDWrt },
		interactive: func() bool {
			is, _ := isInteractive()
			return is
		},
		new: newddwrtService,
	}
	systems := append([]service.System{system}, service.AvailableSystems()...)
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
