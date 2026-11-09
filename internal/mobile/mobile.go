// Package mobile reports whether ctrld runs in the process of an iOS app.
// Every package reads the same value, so one test stub covers all of them.
package mobile

import "runtime"

// IsIOS reports whether ctrld runs in an iOS app. The iOS sandbox does not
// let an app start a process, so ctrld must not start system tools there.
// Tests replace it.
var IsIOS = func() bool { return runtime.GOOS == "ios" }
