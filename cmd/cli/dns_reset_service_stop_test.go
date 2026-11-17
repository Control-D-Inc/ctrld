package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"testing"
)

// newServiceStopProg is the prog a ctrld restart or upgrade CLI builds: the
// interface and intercept mode come from the running service, not from this
// process's flags.
func newServiceStopProg(running, serviceMode string) *prog {
	p := newStartResetProg("")
	p.setRunningIfaceFromService(&ifaceResponse{Name: running, All: true, OK: true, InterceptMode: serviceMode})
	return p
}

// TestResetDNSAfterServiceStopInterceptKeepsForeignDNS is the ctrld#740 field
// case on the CLI path: ctrld restart and every self-upgrade stop the service
// and clean up DNS from the CLI process, which has no intercept state. With a
// full-tunnel VPN holding the default route, that cleanup cleared the VPN's
// pushed DNS exactly as the old service start did.
func TestResetDNSAfterServiceStopInterceptKeepsForeignDNS(t *testing.T) {
	for _, mode := range []string{"dns", "hard"} {
		t.Run(mode, func(t *testing.T) {
			// The CLI's own --intercept-mode is unset; only the service's
			// report decides.
			h := stubStartResetHost(t, "", "Ethernet 2", "Wi-Fi", "Ethernet")
			h.static["Ethernet 2"] = []string{"10.131.18.144"}
			h.static["Wi-Fi"] = []string{"192.0.2.53"}

			newServiceStopProg("Ethernet 2", mode).resetDNSAfterServiceStop()

			if got := h.resets(); len(got) != 0 {
				t.Errorf("reset adapters %v, want none: no adapter carries ctrld's listener", got)
			}
			if h.fullReset != 0 {
				t.Error("the CLI cleanup ran the blanket interface-DNS reset for an intercepting service")
			}
			if got := h.static["Ethernet 2"]; !slices.Equal(got, []string{"10.131.18.144"}) {
				t.Errorf("VPN adapter DNS = %v, want the pushed resolver kept", got)
			}
			if got := h.static["Wi-Fi"]; !slices.Equal(got, []string{"192.0.2.53"}) {
				t.Errorf("Wi-Fi static DNS = %v, want the administrator's servers kept", got)
			}
		})
	}
}

// TestResetDNSAfterServiceStopClearsLeftoverListener: a service that fell back
// to interface DNS mode, or an earlier interface-DNS-mode run, can leave the
// listener on adapters. The CLI cleanup still clears those.
func TestResetDNSAfterServiceStopClearsLeftoverListener(t *testing.T) {
	h := stubStartResetHost(t, "", "Wi-Fi", "Ethernet", "Ethernet 3")
	h.static["Wi-Fi"] = []string{"127.0.0.1"}
	h.static["Ethernet"] = []string{"::1", "127.0.0.1"}
	h.static["Ethernet 3"] = []string{"192.0.2.53"}

	newServiceStopProg("Wi-Fi", "dns").resetDNSAfterServiceStop()

	got := h.resets()
	slices.Sort(got)
	if want := []string{"Ethernet", "Wi-Fi"}; !slices.Equal(got, want) {
		t.Errorf("reset adapters %v, want %v", got, want)
	}
	if _, ok := h.static["Ethernet 3"]; !ok {
		t.Error("an adapter with non-loopback static DNS was reset")
	}
	if h.forwarderCleanups != 1 {
		t.Errorf("domain controller forwarder cleanup ran %d times, want 1", h.forwarderCleanups)
	}
}

// TestResetDNSAfterServiceStopInterfaceModeUnchanged: a service in interface
// DNS mode, or one that could not report its mode (not running, too old to
// report it), keeps the full reset with saved static DNS restored, as before.
func TestResetDNSAfterServiceStopInterfaceModeUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    func() *prog
	}{
		{"interface DNS mode", func() *prog { return newServiceStopProg("Ethernet", "") }},
		{"no service report", func() *prog { return newStartResetProg("Ethernet") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A CLI flag selecting intercept mode does not describe the
			// stopped service.
			h := stubStartResetHost(t, "dns", "Ethernet")
			h.static["Ethernet"] = []string{"192.0.2.53"}

			tc.p().resetDNSAfterServiceStop()

			if h.fullReset != 1 || !h.fullResetRestoreStatic {
				t.Errorf("blanket reset ran %d times (restoreStatic=%t), want once with restoreStatic", h.fullReset, h.fullResetRestoreStatic)
			}
			if got := h.resets(); len(got) != 0 {
				t.Errorf("leftover reset touched %v alongside the blanket reset", got)
			}
		})
	}
}

// TestSetRunningIfaceFromServiceKeepsInterceptMode pins the field the CLI
// cleanup decides on.
func TestSetRunningIfaceFromServiceKeepsInterceptMode(t *testing.T) {
	p := &prog{}
	p.setRunningIfaceFromService(&ifaceResponse{Name: "Ethernet 2", All: true, InterceptMode: "hard"})
	if p.runningIface != "Ethernet 2" || !p.requiredMultiNICsConfig || p.serviceInterceptMode != "hard" {
		t.Errorf("got iface %q all %t mode %q", p.runningIface, p.requiredMultiNICsConfig, p.serviceInterceptMode)
	}
}

// TestServiceStopCleanupWiring checks that ctrld restart and the upgrade
// binary switch (restart and rollback) clean up through
// resetDNSAfterServiceStop and record the service's intercept mode, rather
// than calling the blanket resetDNS. It reads commands.go, so it runs where
// the package source is present.
func TestServiceStopCleanupWiring(t *testing.T) {
	path := packageSourcePath(t, "commands.go")
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	type calls struct{ blanket, afterStop, fromService int }
	count := func(n ast.Node) calls {
		var c calls
		ast.Inspect(n, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch sel.Sel.Name {
			case "resetDNS":
				c.blanket++
			case "resetDNSAfterServiceStop":
				c.afterStop++
			case "setRunningIfaceFromService":
				c.fromService++
			}
			return true
		})
		return c
	}
	want := map[string]calls{
		"initRestartCmd":  {afterStop: 1, fromService: 1},
		"newBinarySwitch": {fromService: 1},
		"install":         {afterStop: 2},
	}
	seen := map[string]bool{}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		w, ok := want[fn.Name.Name]
		if !ok {
			continue
		}
		seen[fn.Name.Name] = true
		if got := count(fn); got != w {
			t.Errorf("%s: resetDNS %d, resetDNSAfterServiceStop %d, setRunningIfaceFromService %d; want %d, %d, %d",
				fn.Name.Name, got.blanket, got.afterStop, got.fromService, w.blanket, w.afterStop, w.fromService)
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("function %s not found in commands.go", name)
		}
	}
}
