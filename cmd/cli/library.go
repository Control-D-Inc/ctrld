package cli

type AppCallback struct {
	HostName   func() string
	LanIp      func() string
	MacAddress func() string
	Exit       func(error string)
}

type AppConfig struct {
	CdUID   string
	HomeDir string
	Verbose int
	LogPath string
}
