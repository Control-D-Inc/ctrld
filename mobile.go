package ctrld

import "gitlab.int.windscribe.com/controld/clients/ctrld.git/internal/mobile"

// isMobile reports whether ctrld runs in the process of an iOS app. Tests
// replace it.
var isMobile = func() bool { return mobile.IsIOS() }
