package controld

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

const resolverDataURL = "https://api.controld.com/utility"

// ResolverConfig represents Control D resolver data.
type ResolverConfig struct {
	V4      []string `json:"v4"`
	V6      []string `json:"v6"`
	DOH     string   `json:"doh"`
	Exclude []string `json:"exclude"`
}

func (r *ResolverConfig) IP(v6 bool) string {
	ip4 := r.v4()
	ip6 := r.v6()
	if v6 && ip6 != "" {
		return ip6
	}
	return ip4
}

func (r *ResolverConfig) v4() string {
	for _, ip := range r.V4 {
		return ip
	}
	return ""
}

func (r *ResolverConfig) v6() string {
	for _, ip := range r.V6 {
		return ip
	}
	return ""
}

type utilityResponse struct {
	Success bool `json:"success"`
	Body    struct {
		Resolver ResolverConfig `json:"resolver"`
	} `json:"body"`
}

type utilityErrorResponse struct {
	Error struct {
		Message string `json:"message"`
	} `json:"error"`
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
	req.Header.Add("Content-Type", "application/json")
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("client.Do: %w", err)
	}
	defer resp.Body.Close()
	d := json.NewDecoder(resp.Body)
	if resp.StatusCode != http.StatusOK {
		errResp := &utilityErrorResponse{}
		if err := d.Decode(errResp); err != nil {
			return nil, err
		}
		return nil, errors.New(errResp.Error.Message)
	}

	ur := &utilityResponse{}
	if err := d.Decode(ur); err != nil {
		return nil, err
	}
	return &ur.Body.Resolver, nil
}