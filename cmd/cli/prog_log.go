package cli

import "github.com/rs/zerolog"

// Debug starts a new message with debug level.
func (p *prog) Debug() *zerolog.Event {
	return p.logger.Load().Debug()
}

// Warn starts a new message with warn level.
func (p *prog) Warn() *zerolog.Event {
	return p.logger.Load().Warn()
}

// Info starts a new message with info level.
func (p *prog) Info() *zerolog.Event {
	return p.logger.Load().Info()
}

// Fatal starts a new message with fatal level.
func (p *prog) Fatal() *zerolog.Event {
	return p.logger.Load().Fatal()
}

// Error starts a new message with error level.
func (p *prog) Error() *zerolog.Event {
	return p.logger.Load().Error()
}

// Notice starts a new message with notice level.
func (p *prog) Notice() *zerolog.Event {
	return p.logger.Load().Notice()
}
