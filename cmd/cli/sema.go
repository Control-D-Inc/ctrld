package cli

type semaphore interface {
	acquire()
	release()
}

type noopSemaphore struct{}

func (n noopSemaphore) acquire() {}

func (n noopSemaphore) release() {}

type chanSemaphore struct {
	ready chan struct{}
}

func (c *chanSemaphore) acquire() {
	c.ready <- struct{}{}
}

func (c *chanSemaphore) release() {
	<-c.ready
}
