package ctrld

import "errors"

// errNoHostTools is the error of a system tool that ctrld does not start on
// mobile. The iOS sandbox does not let an app start a process.
var errNoHostTools = errors.New("system network tools are not available on mobile")
