package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Control-D-Inc/ctrld"
)

func Test_orderUpstreamsSequentialPreservesOrderAndPairing(t *testing.T) {
	upstreams := []string{"upstream.0", "upstream.1", "upstream.2"}
	upstreamConfigs := []*ctrld.UpstreamConfig{
		{Name: "zero"},
		{Name: "one"},
		{Name: "two"},
	}

	gotUpstreams, gotUpstreamConfigs := orderUpstreams(ctrld.UpstreamStrategySequential, upstreams, upstreamConfigs)

	assert.Equal(t, upstreams, gotUpstreams)
	assert.Equal(t, []string{"zero", "one", "two"}, upstreamConfigNames(gotUpstreamConfigs))

	gotUpstreams[0] = "changed"
	gotUpstreamConfigs[0] = &ctrld.UpstreamConfig{Name: "changed"}
	assert.Equal(t, []string{"upstream.0", "upstream.1", "upstream.2"}, upstreams)
	assert.Equal(t, []string{"zero", "one", "two"}, upstreamConfigNames(upstreamConfigs))
}

func Test_orderUpstreamsRandomUsesShuffleAndPreservesPairing(t *testing.T) {
	upstreams := []string{"upstream.0", "upstream.1", "upstream.2"}
	upstreamConfigs := []*ctrld.UpstreamConfig{
		{Name: "zero"},
		{Name: "one"},
		{Name: "two"},
	}

	gotUpstreams, gotUpstreamConfigs := orderUpstreamsWithShuffle(
		ctrld.UpstreamStrategyRandom,
		upstreams,
		upstreamConfigs,
		func(n int, swap func(i, j int)) {
			require.Equal(t, 3, n)
			swap(0, 2)
			swap(1, 2)
		},
	)

	assert.Equal(t, []string{"upstream.2", "upstream.0", "upstream.1"}, gotUpstreams)
	assert.Equal(t, []string{"two", "zero", "one"}, upstreamConfigNames(gotUpstreamConfigs))
	assert.Equal(t, []string{"upstream.0", "upstream.1", "upstream.2"}, upstreams)
	assert.Equal(t, []string{"zero", "one", "two"}, upstreamConfigNames(upstreamConfigs))
}

func Test_orderUpstreamsUnknownStrategyBehavesAsSequential(t *testing.T) {
	upstreams := []string{"upstream.0", "upstream.1"}
	upstreamConfigs := []*ctrld.UpstreamConfig{
		{Name: "zero"},
		{Name: "one"},
	}
	called := false

	gotUpstreams, gotUpstreamConfigs := orderUpstreamsWithShuffle(
		"unknown",
		upstreams,
		upstreamConfigs,
		func(n int, swap func(i, j int)) {
			called = true
		},
	)

	assert.False(t, called)
	assert.Equal(t, upstreams, gotUpstreams)
	assert.Equal(t, []string{"zero", "one"}, upstreamConfigNames(gotUpstreamConfigs))
}

func Test_orderUpstreamsRandomLengthMismatchBehavesAsSequential(t *testing.T) {
	upstreams := []string{"upstream.0", "upstream.1"}
	upstreamConfigs := []*ctrld.UpstreamConfig{
		{Name: "zero"},
	}
	called := false

	gotUpstreams, gotUpstreamConfigs := orderUpstreamsWithShuffle(
		ctrld.UpstreamStrategyRandom,
		upstreams,
		upstreamConfigs,
		func(n int, swap func(i, j int)) {
			called = true
		},
	)

	assert.False(t, called)
	assert.Equal(t, upstreams, gotUpstreams)
	assert.Equal(t, []string{"zero"}, upstreamConfigNames(gotUpstreamConfigs))
}

func upstreamConfigNames(upstreamConfigs []*ctrld.UpstreamConfig) []string {
	names := make([]string, 0, len(upstreamConfigs))
	for _, upstreamConfig := range upstreamConfigs {
		if upstreamConfig == nil {
			names = append(names, "")
			continue
		}
		names = append(names, upstreamConfig.Name)
	}
	return names
}
