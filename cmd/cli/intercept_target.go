package cli

// publishInterceptTarget mirrors the loopback DNS target that ctrld wrote into
// a network service. Callers hold interceptDNSTargetMu.
func (p *prog) publishInterceptTarget(target string) {
	p.interceptTargetMirror.Store(target)
}

// interceptTargetSnapshot reads the mirrored loopback DNS target. It takes no
// lock, so a report of the network never waits on the networksetup calls that
// the target mutex covers. The value is empty while ctrld holds no service.
func (p *prog) interceptTargetSnapshot() string {
	target, _ := p.interceptTargetMirror.Load().(string)
	return target
}
