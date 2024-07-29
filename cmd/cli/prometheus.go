package cli

import "github.com/prometheus/client_golang/prometheus"

const (
	metricsLabelListener       = "listener"
	metricsLabelClientSourceIP = "client_source_ip"
	metricsLabelClientMac      = "client_mac"
	metricsLabelClientHostname = "client_hostname"
	metricsLabelUpstream       = "upstream"
	metricsLabelRRType         = "rr_type"
	metricsLabelRCode          = "rcode"
)

// statsVersion represent ctrld version.
var statsVersion = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "ctrld_build_info",
	Help: "Version of ctrld process.",
}, []string{"gitref", "goversion", "version"})

// statsTimeStart represents start time of ctrld service.
var statsTimeStart = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "ctrld_time_seconds",
	Help: "Start time of the ctrld process since unix epoch in seconds.",
})

var statsQueriesCountLabels = []string{
	metricsLabelListener,
	metricsLabelClientSourceIP,
	metricsLabelClientMac,
	metricsLabelClientHostname,
	metricsLabelUpstream,
	metricsLabelRRType,
	metricsLabelRCode,
}

// statsQueriesCount counts total number of queries.
var statsQueriesCount = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "ctrld_queries_count",
	Help: "Total number of queries.",
}, statsQueriesCountLabels)

// statsClientQueriesCount counts total number of queries of a client.
//
// The labels "client_source_ip", "client_mac", "client_hostname" are unbounded,
// thus this stat is highly inefficient if there are many devices.
var statsClientQueriesCount = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "ctrld_client_queries_count",
	Help: "Total number queries of a client.",
}, []string{metricsLabelClientSourceIP, metricsLabelClientMac, metricsLabelClientHostname})

// WithLabelValuesInc increases prometheus counter by 1 if query stats is enabled.
func (p *prog) WithLabelValuesInc(c *prometheus.CounterVec, lvs ...string) {
	if p.metricsQueryStats.Load() {
		c.WithLabelValues(lvs...).Inc()
	}
}
