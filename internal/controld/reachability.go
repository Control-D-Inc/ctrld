package controld

import (
	"context"
	"io"
	"net/http"
)

// ProbeReachability makes one lightweight request to the ControlD API host,
// reusing the same transport and IP-fallback logic real provisioning traffic
// takes. Any HTTP response, even an error status, counts as reachable: this
// checks the network path, not whether the endpoint accepts the request.
//
// The caller controls how long to wait via ctx; there is no timeout here
// beyond what ctx enforces.
func ProbeReachability(ctx context.Context, cdDev bool) error {
	apiURL := apiURLCom
	if cdDev {
		apiURL = apiURLDev
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Transport: apiTransport(ctx, cdDev)}
	resp, err := doWithFallback(ctx, client, req, apiServerIP(cdDev))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}
