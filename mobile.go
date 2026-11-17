package ctrld

import "github.com/Control-D-Inc/ctrld/internal/mobile"

// isMobile reports whether ctrld runs in the process of an iOS app. Tests
// replace it.
var isMobile = func() bool { return mobile.IsIOS() }
