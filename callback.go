package stack

import (
	"fmt"
	"sync"
)

type CallbackMode string

const (
	CallbackModeAsync CallbackMode = "async"
	CallbackModeSync  CallbackMode = "sync"
	CallbackModeMixed CallbackMode = "mixed"
)

// ErrorCallback is a function type for error callbacks
type ErrorCallback func(record *ErrorRecord)

// ErrorCallbackManager manages error callbacks
type ErrorCallbackManager struct {
	mu        sync.RWMutex
	callbacks map[string]ErrorCallback
}

// NewErrorCallbackManager creates a new callback manager
func NewErrorCallbackManager() *ErrorCallbackManager {
	return &ErrorCallbackManager{
		callbacks: make(map[string]ErrorCallback),
	}
}

// RegisterCallback registers a new error callback with a unique name
func (m *ErrorCallbackManager) RegisterCallback(name string, callback ErrorCallback) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callbacks[name] = callback
}

// UnregisterCallback removes a callback by name
func (m *ErrorCallbackManager) UnregisterCallback(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.callbacks, name)
}

// ExecuteCallbacks executes all registered callbacks for an error
func (m *ErrorCallbackManager) ExecuteCallbacks(record *ErrorRecord) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, callback := range m.callbacks {
		// Execute callbacks in goroutines to avoid blocking error creation
		go func(cb ErrorCallback, rec *ErrorRecord) {
			defer func() {
				if r := recover(); r != nil {
					fmt.Printf("Error callback panicked: %v\n", r)
				}
			}()
			cb(rec)
		}(callback, record)
	}
}

// ExecuteCallbacksSync executes all registered callbacks synchronously (useful for testing/demos)
func (m *ErrorCallbackManager) ExecuteCallbacksSync(record *ErrorRecord) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, callback := range m.callbacks {
		func(cb ErrorCallback, rec *ErrorRecord) {
			defer func() {
				if r := recover(); r != nil {
					fmt.Printf("Error callback panicked: %v\n", r)
				}
			}()
			cb(rec)
		}(callback, record)
	}
} // ErrorRegistry is a global registry for storing and retrieving error details
