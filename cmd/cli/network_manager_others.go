//go:build !linux

package cli

func (p *prog) setupNetworkManager() error {
	p.reloadNetworkManager()
	return nil
}

func (p *prog) restoreNetworkManager() error {
	p.reloadNetworkManager()
	return nil
}

func (p *prog) reloadNetworkManager() {}
