package cli

// semaphore provides a simple synchronization mechanism
type semaphore interface {
	acquire()
	release()
}

// noopSemaphore is a no-operation implementation of semaphore
type noopSemaphore struct{}

// acquire performs a no-operation for the noop semaphore
func (n noopSemaphore) acquire() {}

// release performs a no-operation for the noop semaphore
func (n noopSemaphore) release() {}

// chanSemaphore is a channel-based implementation of semaphore
type chanSemaphore struct {
	ready chan struct{}
}

// acquire blocks until a slot is available in the semaphore
func (c *chanSemaphore) acquire() {
	c.ready <- struct{}{}
}

// release signals that a slot has been freed in the semaphore
func (c *chanSemaphore) release() {
	<-c.ready
}
