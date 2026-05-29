package cli

import (
	"math/rand"

	"github.com/Control-D-Inc/ctrld"
)

func orderUpstreams(strategy string, upstreams []string, upstreamConfigs []*ctrld.UpstreamConfig) ([]string, []*ctrld.UpstreamConfig) {
	return orderUpstreamsWithShuffle(strategy, upstreams, upstreamConfigs, rand.Shuffle)
}

func orderUpstreamsWithShuffle(
	strategy string,
	upstreams []string,
	upstreamConfigs []*ctrld.UpstreamConfig,
	shuffle func(n int, swap func(i, j int)),
) ([]string, []*ctrld.UpstreamConfig) {
	orderedUpstreams := append([]string(nil), upstreams...)
	orderedUpstreamConfigs := append([]*ctrld.UpstreamConfig(nil), upstreamConfigs...)
	if strategy != ctrld.UpstreamStrategyRandom || len(orderedUpstreams) <= 1 || len(orderedUpstreams) != len(orderedUpstreamConfigs) {
		return orderedUpstreams, orderedUpstreamConfigs
	}
	shuffle(len(orderedUpstreams), func(i, j int) {
		orderedUpstreams[i], orderedUpstreams[j] = orderedUpstreams[j], orderedUpstreams[i]
		orderedUpstreamConfigs[i], orderedUpstreamConfigs[j] = orderedUpstreamConfigs[j], orderedUpstreamConfigs[i]
	})
	return orderedUpstreams, orderedUpstreamConfigs
}
