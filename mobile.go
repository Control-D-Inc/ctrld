package ctrld

import "github.com/Control-D-Inc/ctrld/internal/mobile"

// isIOS reports whether ctrld runs in the process of an iOS app, where the
// sandbox does not let it start a process. Tests replace it.
var isIOS = func() bool { return mobile.IsIOS() }
