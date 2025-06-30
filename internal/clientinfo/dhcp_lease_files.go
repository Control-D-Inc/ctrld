package clientinfo

import "github.com/Control-D-Inc/ctrld"

// clientInfoFiles specifies client info files and how to read them on supported platforms.
// TODO: cleanup this after server support removal.
var clientInfoFiles = map[string]ctrld.LeaseFileFormat{}
