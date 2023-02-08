//go:build qf

package ctrld

import (
	"context"
	"errors"

	"github.com/miekg/dns"
)

type doqResolver struct {
	uc *UpstreamConfig
}

func (r *doqResolver) Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	return nil, errors.New("DoQ is not supported")
}
