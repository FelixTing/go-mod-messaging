package messaging

import (
	"sync"
	"time"
)

// CriticalOperationSignaler provides methods to signal critical operations
// that should prevent the messaging client from disconnecting
type CriticalOperationSignaler interface {
	// Signal signals that a critical operation is starting
	// Returns a function that must be called when the operation completes
	Signal() func()

	// WaitForCriticalOperations waits for all critical operations to complete
	// Returns true if all operations completed, false if timeout occurred
	WaitForCriticalOperations(timeout time.Duration) bool
}

// criticalOperationSignaler implements the CriticalOperationSignaler interface
type criticalOperationSignaler struct {
	waitGroup sync.WaitGroup
	mu        sync.RWMutex
}

// NewCriticalOperationSignaler creates a new instance of CriticalOperationSignaler
func NewCriticalOperationSignaler() CriticalOperationSignaler {
	return &criticalOperationSignaler{}
}

// Signal signals that a critical operation is starting
// Returns a function that must be called when the operation completes
func (c *criticalOperationSignaler) Signal() func() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.waitGroup.Add(1)

	return func() {
		c.mu.Lock()
		defer c.mu.Unlock()

		c.waitGroup.Done()
	}
}

// WaitForCriticalOperations waits for all critical operations to complete
// Returns true if all operations completed, false if timeout occurred
func (c *criticalOperationSignaler) WaitForCriticalOperations(timeout time.Duration) bool {
	done := make(chan struct{})

	go func() {
		c.waitGroup.Wait()
		close(done)
	}()

	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}
