package ctrld

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"

	"github.com/miekg/dns"
)

const (
	DoHMacHeader  = "x-cd-mac"
	DoHIPHeader   = "x-cd-ip"
	DoHHostHeader = "x-cd-host"

	headerApplicationDNS = "application/dns-message"
)

func newDohResolver(uc *UpstreamConfig) *dohResolver {
	r := &dohResolver{
		endpoint:          uc.u,
		isDoH3:            uc.Type == ResolverTypeDOH3,
		transport:         uc.transport,
		http3RoundTripper: uc.http3RoundTripper,
		sendClientInfo:    uc.UpstreamSendClientInfo(),
		uc:                uc,
	}
	return r
}

type dohResolver struct {
	endpoint          *url.URL
	isDoH3            bool
	transport         *http.Transport
	http3RoundTripper http.RoundTripper
	sendClientInfo    bool
	uc                *UpstreamConfig
}

func (r *dohResolver) Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	data, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	enc := base64.RawURLEncoding.EncodeToString(data)
	query := r.endpoint.Query()
	query.Add("dns", enc)

	endpoint := *r.endpoint
	endpoint.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("could not create request: %w", err)
	}
	addHeader(ctx, req, r.sendClientInfo)

	var resp *http.Response
	if runtime.GOOS == "linux" {
		resp, err = r.doRequestWithFailover(req)
	} else {
		resp, err = r.doRequest(req)
	}
	if err != nil {
		if r.isDoH3 {
			if closer, ok := r.http3RoundTripper.(io.Closer); ok {
				closer.Close()
			}
		}
		return nil, fmt.Errorf("could not perform request: %w", err)
	}
	defer resp.Body.Close()

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("could not read message from response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wrong response from DOH server, got: %s, status: %d", string(buf), resp.StatusCode)
	}

	answer := new(dns.Msg)
	if err := answer.Unpack(buf); err != nil {
		return nil, fmt.Errorf("answer.Unpack: %w", err)
	}
	return answer, nil
}

func (r *dohResolver) doRequest(req *http.Request) (*http.Response, error) {
	c := http.Client{Transport: r.transport}
	if r.isDoH3 {
		if r.http3RoundTripper == nil {
			return nil, errors.New("DoH3 is not supported")
		}
		c.Transport = r.http3RoundTripper
	}
	return c.Do(req)
}

func (r *dohResolver) doRequestWithFailover(req *http.Request) (*http.Response, error) {
	// To deal with network changes, for example, connect/disconnect to VPN,
	// We use two clients:
	//
	//  - mainClient: use the current transport.
	//  - failoverClient: use a clone of the current transport.
	//
	// Two clients will perform the requests concurrently, but with mainClient
	// started first. So in normal condition, mainClient is likely to return first,
	// and we will use its result. In case of mainClient failed, we trigger the
	// re-bootstrapping process, and use the result from failover client.
	mainClient := http.Client{Transport: r.transport}
	failoverClient := http.Client{}
	if r.isDoH3 {
		if r.http3RoundTripper == nil {
			return nil, errors.New("DoH3 is not supported")
		}
		// TODO: figure out how to clone DOH3 round tripper?
		mainClient.Transport = r.http3RoundTripper
		failoverClient.Transport = r.http3RoundTripper
	} else {
		failoverClient.Transport = r.transport.Clone()
	}

	done := make(chan struct{})
	defer close(done)

	type result struct {
		resp *http.Response
		err  error
	}

	respCh := make(chan result)
	doRequest := func(client *http.Client) {
		resp, err := client.Do(req)
		select {
		case respCh <- result{resp: resp, err: err}:
		case <-done:
			if client == &mainClient && err != nil {
				r.uc.ReBootstrap()
			}
			if resp != nil {
				defer resp.Body.Close()
				_, _ = io.Copy(io.Discard, resp.Body)
			}
		}
	}

	mainClientStarted := make(chan struct{})
	go func() {
		// Notify failoverClient that mainClient started.
		close(mainClientStarted)
		doRequest(&mainClient)
	}()
	go func() {
		// Wait mainClient started first.
		<-mainClientStarted
		doRequest(&failoverClient)
	}()

	var (
		resp *http.Response
		err  error
	)
	for range []*http.Client{&mainClient, &failoverClient} {
		res := <-respCh
		if res.err == nil {
			resp = res.resp
			break
		}
		err = res.err
	}
	return resp, err
}

func addHeader(ctx context.Context, req *http.Request, sendClientInfo bool) {
	req.Header.Set("Content-Type", headerApplicationDNS)
	req.Header.Set("Accept", headerApplicationDNS)
	if sendClientInfo {
		if ci, ok := ctx.Value(ClientInfoCtxKey{}).(*ClientInfo); ok && ci != nil {
			if ci.Mac != "" {
				req.Header.Set(DoHMacHeader, ci.Mac)
			}
			if ci.IP != "" {
				req.Header.Set(DoHIPHeader, ci.IP)
			}
			if ci.Hostname != "" {
				req.Header.Set(DoHHostHeader, ci.Hostname)
			}
		}
	}
	Log(ctx, ProxyLog.Debug().Interface("header", req.Header), "sending request header")
}
