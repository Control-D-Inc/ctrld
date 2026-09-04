package cli

import "github.com/Control-D-Inc/ctrld"

// Debug starts a new message with debug level.
func (p *prog) Debug() *ctrld.LogEvent {
	return p.logger.Load().Debug()
}

// Warn starts a new message with warn level.
func (p *prog) Warn() *ctrld.LogEvent {
	return p.logger.Load().Warn()
}

// Info starts a new message with info level.
func (p *prog) Info() *ctrld.LogEvent {
	return p.logger.Load().Info()
}

// Fatal starts a new message with fatal level.
func (p *prog) Fatal() *ctrld.LogEvent {
	return p.logger.Load().Fatal()
}

// Error starts a new message with error level.
func (p *prog) Error() *ctrld.LogEvent {
	return p.logger.Load().Error()
}

// Notice starts a new message with notice level.
func (p *prog) Notice() *ctrld.LogEvent {
	return p.logger.Load().Notice()
}

// notifyExitToLogServer closes this run's connection to the HTTP log server,
// so a waiting "ctrld start" is not left waiting on it after this process
// exits. A nil connection (log server never started) is a no-op.
func (p *prog) notifyExitToLogServer() {
	if p.logConn != nil {
		_ = p.logConn.Close()
	}
}
