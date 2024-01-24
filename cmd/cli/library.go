package cli

// AppCallback provides hooks for injecting certain functionalities
// from mobile platforms to main ctrld cli.
type AppCallback struct {
	HostName   func() string
	LanIp      func() string
	MacAddress func() string
	Exit       func(error string)
}

// AppConfig allows overwriting ctrld cli flags from mobile platforms.
type AppConfig struct {
	CdUID         string
	HomeDir       string
	UpstreamProto string
	Verbose       int
	LogPath       string
}
