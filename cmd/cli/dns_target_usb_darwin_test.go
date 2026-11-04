//go:build darwin

package cli

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
)

func usbTargetTestReader(t *testing.T, listing string) nativeTargetReader {
	t.Helper()
	global := nativeTargetTestGlobal(nativeTargetTestServiceID, "en8")
	outputs := []string{global, strings.ReplaceAll(nativeTargetTestState(), "en1", "en8"), "<dictionary> {\n  UserDefinedName : iPhone\n}", listing, global}
	var calls []string
	return nativeTargetTestReader(t, outputs, &calls)
}

func TestUSBServiceReaderDrivesTargetLifecycle(t *testing.T) {
	for _, initial := range [][]string{nil, {"2001:db8::53"}} {
		for _, port := range []int{53, 5353, 5354} {
			t.Run(fmt.Sprintf("%d/%v", port, initial), func(t *testing.T) {
				h := newInterceptTargetHarness(t)
				h.serviceByDev["en8"] = "iPhone USB"
				h.dns["iPhone USB"] = slices.Clone(initial)
				interceptDefaultRouteInterfaceFn = func() (string, error) { return "en8", nil }
				interceptNativeCLATDefaultServiceFn = func(ctx context.Context, device string) (nativeTargetService, error) {
					return usbTargetTestReader(t, capturedUSBServiceOrder).defaultService(ctx, device)
				}
				interceptNativeStaticDNSFn = func(_ context.Context, iface *net.Interface) ([]string, error) {
					if iface.Name != "iPhone USB" {
						t.Fatalf("invalid command service %q", iface.Name)
					}
					return slices.Clone(h.dns[iface.Name]), nil
				}
				p := newInterceptTargetProg()
				p.cfg.Listener["0"].IP = "127.0.0.2"
				p.cfg.Listener["0"].Port = port
				p.ensureInterceptDNSTarget([]string{})
				p.ensureInterceptDNSTarget([]string{})
				if !slices.Equal(h.dns["iPhone USB"], []string{p.interceptDNSTargetValue()}) || len(h.setCalls) != 1 {
					t.Fatalf("USB target=%v writes=%v", h.dns, h.setCalls)
				}
				if _, ok := h.dns["iPhone"]; ok {
					t.Fatal("wrote display-name service")
				}
				p.removeInterceptDNSTarget("USB test cleanup")
				if !slices.Equal(h.dns["iPhone USB"], initial) || p.interceptDNSTargetService != "" {
					t.Fatal("USB DNS not restored")
				}
			})
		}
	}
}

func TestUSBServiceMappingChangeAndAmbiguityDoNotWrite(t *testing.T) {
	for _, scenario := range []string{"renamed on recheck", "ambiguous device"} {
		t.Run(scenario, func(t *testing.T) {
			h := newInterceptTargetHarness(t)
			h.serviceByDev["en8"] = "iPhone USB"
			original := []string{"2001:db8::53"}
			h.dns["iPhone USB"] = slices.Clone(original)
			interceptDefaultRouteInterfaceFn = func() (string, error) { return "en8", nil }
			reads := 0
			interceptNativeCLATDefaultServiceFn = func(ctx context.Context, device string) (nativeTargetService, error) {
				reads++
				listing := capturedUSBServiceOrder
				if scenario == "renamed on recheck" && reads == 2 {
					listing = strings.Replace(listing, "(4) iPhone USB", "(4) Renamed USB", 1)
				}
				if scenario == "ambiguous device" {
					listing += "(6) iPhone\n(Hardware Port: iPhone USB, Device: en8)\n"
				}
				return usbTargetTestReader(t, listing).defaultService(ctx, device)
			}
			p := newInterceptTargetProg()
			p.ensureInterceptDNSTarget([]string{})
			if len(h.setCalls) != 0 || len(h.resetCalls) != 0 || p.interceptDNSTargetService != "" || !slices.Equal(h.dns["iPhone USB"], original) {
				t.Fatalf("uncertain mapping changed DNS: %+v", h)
			}
			if scenario == "renamed on recheck" && reads != 2 {
				t.Fatal("did not exercise final mapping recheck")
			}
		})
	}
}
