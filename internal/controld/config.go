package controld

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/certs"
	ctrldnet "github.com/Control-D-Inc/ctrld/internal/net"
	"github.com/Control-D-Inc/ctrld/internal/router"
)

const (
	apiDomainCom       = "api.controld.com"
	apiDomainDev       = "api.controld.dev"
	resolverDataURLCom = "https://api.controld.com/utility"
	resolverDataURLDev = "https://api.controld.dev/utility"
	InvalidConfigCode  = 40401
)

// ResolverConfig represents Control D resolver data.
type ResolverConfig struct {
	DOH   string `json:"doh"`
	Ctrld struct {
		CustomConfig string `json:"custom_config"`
	} `json:"ctrld"`
	Exclude []string `json:"exclude"`
}

type utilityResponse struct {
	Success bool `json:"success"`
	Body    struct {
		Resolver ResolverConfig `json:"resolver"`
	} `json:"body"`
}

type UtilityErrorResponse struct {
	ErrorField struct {
		Message string `json:"message"`
		Code    int    `json:"code"`
	} `json:"error"`
}

func (u UtilityErrorResponse) Error() string {
	return u.ErrorField.Message
}

type utilityRequest struct {
	UID string `json:"uid"`
}

// FetchResolverConfig fetch Control D config for given uid.
func FetchResolverConfig(uid, version string, cdDev bool) (*ResolverConfig, error) {
	body, _ := json.Marshal(utilityRequest{UID: uid})
	apiUrl := resolverDataURLCom
	if cdDev {
		apiUrl = resolverDataURLDev
	}
	req, err := http.NewRequest("POST", apiUrl, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("http.NewRequest: %w", err)
	}
	q := req.URL.Query()
	q.Set("platform", "ctrld")
	q.Set("version", version)
	req.URL.RawQuery = q.Encode()
	req.Header.Add("Content-Type", "application/json")
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		apiDomain := apiDomainCom
		if cdDev {
			apiDomain = apiDomainDev
		}
		ips := ctrld.LookupIP(apiDomain)
		if len(ips) == 0 {
			ctrld.ProxyLog.Warn().Msgf("No IPs found for %s, connecting to %s", apiDomain, addr)
			return ctrldnet.Dialer.DialContext(ctx, network, addr)
		}
		ctrld.ProxyLog.Debug().Msgf("API IPs: %v", ips)
		_, port, _ := net.SplitHostPort(addr)
		addrs := make([]string, len(ips))
		for i := range ips {
			addrs[i] = net.JoinHostPort(ips[i], port)
		}
		d := &ctrldnet.ParallelDialer{}
		return d.DialContext(ctx, network, addrs)
	}

	if router.Name() == router.DDWrt {
		transport.TLSClientConfig = &tls.Config{RootCAs: certs.CACertPool()}
	}
	client := http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("client.Do: %w", err)
	}
	defer resp.Body.Close()
	d := json.NewDecoder(resp.Body)
	if resp.StatusCode != http.StatusOK {
		errResp := &UtilityErrorResponse{}
		if err := d.Decode(errResp); err != nil {
			return nil, err
		}
		return nil, errResp
	}

	ur := &utilityResponse{}
	if err := d.Decode(ur); err != nil {
		return nil, err
	}
	return &ur.Body.Resolver, nil
}
