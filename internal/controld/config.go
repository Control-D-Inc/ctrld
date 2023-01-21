package controld

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
)

const (
	resolverDataURL   = "https://api.controld.com/utility"
	InvalidConfigCode = 40401
)

const bootstrapDNS = "76.76.2.0:53"

var dialer = &net.Dialer{
	Resolver: &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: 10 * time.Second,
			}
			return d.DialContext(ctx, "udp", bootstrapDNS)
		},
	},
}

// ResolverConfig represents Control D resolver data.
type ResolverConfig struct {
	DOH     string   `json:"doh"`
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
func FetchResolverConfig(uid string) (*ResolverConfig, error) {
	body, _ := json.Marshal(utilityRequest{UID: uid})
	req, err := http.NewRequest("POST", resolverDataURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("http.NewRequest: %w", err)
	}
	q := req.URL.Query()
	q.Set("platform", "ctrld")
	req.URL.RawQuery = q.Encode()
	req.Header.Add("Content-Type", "application/json")
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, addr)
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
