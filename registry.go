package stack

import (
	"encoding/json"
	"os"
	"sync"

	"github.com/oarkflow/stack/logs"
)

type ErrorRegistry struct {
	mu               sync.RWMutex
	file             string
	callbackManager  *ErrorCallbackManager
	domainManager    *DomainManager
	severityManager  *SeverityManager
	logger           logs.Logger
	config           *Config
	storage          Storage // Use Storage interface for error storage
	writeChannel     chan *ErrorRecord
	writerDone       chan bool
	callbackErrors   []error
	callbackErrorsMu sync.RWMutex
	idCounter        int64 // for timestamp-based IDs
}

// NewErrorRegistry creates a new error registry with persistent storage
func NewErrorRegistry(filename string) *ErrorRegistry {
	config := DefaultConfig()
	registry := &ErrorRegistry{
		file:            filename,
		callbackManager: NewErrorCallbackManager(),
		domainManager:   NewDomainManager(),
		severityManager: NewSeverityManager(),
		logger:          logs.NewStdLogger(nil), // Default to standard logger
		config:          config,
		storage:         NewErrorStore(), // Use MemoryIndex as the default implementation
		writeChannel:    make(chan *ErrorRecord, config.WriteBufferSize),
		writerDone:      make(chan bool),
		callbackErrors:  make([]error, 0),
	}

	// Start background writer
	go registry.backgroundWriter()

	// Load existing errors from file
	registry.loadFromFile()
	return registry
}

// NewErrorRegistryWithConfig creates a registry with custom configuration
func NewErrorRegistryWithConfig(filename string, config *Config) *ErrorRegistry {
	registry := &ErrorRegistry{
		file:            filename,
		callbackManager: NewErrorCallbackManager(),
		domainManager:   NewDomainManager(),
		severityManager: NewSeverityManager(),
		logger:          logs.NewStdLogger(nil),
		config:          config,
		storage:         NewErrorStore(), // Use MemoryIndex as the default implementation
		writeChannel:    make(chan *ErrorRecord, config.WriteBufferSize),
		writerDone:      make(chan bool),
		callbackErrors:  make([]error, 0),
	}

	// Start background writer
	go registry.backgroundWriter()

	// Load existing errors from file
	registry.loadFromFile()
	return registry
}

// backgroundWriter handles asynchronous writes to prevent goroutine explosion
func (r *ErrorRegistry) backgroundWriter() {
	for {
		select {
		case record := <-r.writeChannel:
			for _, sink := range r.config.OutputSinks {
				if err := sink.Write(record); err != nil {
					r.logger.Error("Failed to write to output sink", map[string]any{
						"error":    err.Error(),
						"error_id": record.ID,
					})
				}
			}
		case <-r.writerDone:
			return
		}
	}
}

// Close gracefully shuts down the registry
func (r *ErrorRegistry) Close() error {
	close(r.writerDone)

	// Close all output sinks
	for _, sink := range r.config.OutputSinks {
		if err := sink.Close(); err != nil {
			r.logger.Error("Failed to close output sink", map[string]any{
				"error": err.Error(),
			})
		}
	}

	return nil
}

// loadFromFile loads error records from persistent storage
func (r *ErrorRegistry) loadFromFile() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	data, err := os.ReadFile(r.file)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // File doesn't exist yet, that's okay
		}
		return err
	}

	var records []*ErrorRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return err
	}

	for _, record := range records {
		r.storage.Add(record)
	}
	return nil
}

// Register stores an error record in the registry
func (r *ErrorRegistry) Register(record *ErrorRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Validate domain and severity
	if !r.domainManager.HasDomain(record.Domain) {
		r.logger.Warn("Unknown domain used in error", map[string]any{
			"domain":   string(record.Domain),
			"error_id": record.ID,
		})
	}

	if !r.severityManager.HasSeverity(record.Severity) {
		r.logger.Warn("Unknown severity used in error", map[string]any{
			"severity": record.Severity.String(),
			"error_id": record.ID,
		})
	}

	r.storage.Add(record)

	// Log the error based on severity
	fields := map[string]any{
		"error_id": record.ID,
		"domain":   string(record.Domain),
		"code":     record.Code,
		"status":   record.Status,
		"file":     record.File,
		"line":     record.Line,
		"function": record.Function,
	}

	if record.UserID != "" {
		fields["user_id"] = record.UserID
	}
	if record.RequestID != "" {
		fields["request_id"] = record.RequestID
	}
	if record.TraceID != "" {
		fields["trace_id"] = record.TraceID
	}

	switch record.Severity {
	case SeverityCritical:
		r.logger.Fatal(record.Message, fields)
	case SeverityHigh:
		r.logger.Error(record.Message, fields)
	case SeverityMedium:
		r.logger.Warn(record.Message, fields)
	case SeverityLow:
		r.logger.Info(record.Message, fields)
	default:
		r.logger.Error(record.Message, fields)
	}

	// Execute callbacks based on configuration
	r.executeCallbacks(record)

	// Write to output sinks asynchronously
	select {
	case r.writeChannel <- record:
		// Successfully queued for writing
	default:
		// Buffer full, log warning but don't block
		r.logger.Warn("Write buffer full, dropping error record", map[string]any{
			"error_id": record.ID,
		})
	}

	return nil
}

// executeCallbacks handles callback execution based on configuration
func (r *ErrorRegistry) executeCallbacks(record *ErrorRecord) {
	switch r.config.CallbackMode {
	case CallbackModeSync:
		r.executeCallbacksSync(record)
	case CallbackModeAsync:
		r.executeCallbacksAsync(record)
	case CallbackModeMixed:
		// Sync for critical, async for others
		if record.Severity == SeverityCritical {
			r.executeCallbacksSync(record)
		} else {
			r.executeCallbacksAsync(record)
		}
	default:
		r.executeCallbacksAsync(record)
	}
}

func (r *ErrorRegistry) executeCallbacksSync(record *ErrorRecord) {
	globalCallbackMgr.ExecuteCallbacksSync(record)
}

func (r *ErrorRegistry) executeCallbacksAsync(record *ErrorRecord) {
	globalCallbackMgr.ExecuteCallbacks(record)
}

// SearchWithPagination searches for errors with pagination support
func (r *ErrorRegistry) SearchWithPagination(criteria SearchCriteria, pagination PaginationOptions) *SearchResult {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var allMatches []*ErrorRecord

	// Perform searches based on criteria
	if criteria.Domain != nil {
		allMatches = r.storage.SearchByDomain(*criteria.Domain)
	} else if criteria.Severity != nil {
		allMatches = r.storage.SearchBySeverity(*criteria.Severity)
	} else if criteria.Code != "" {
		allMatches = r.storage.SearchByCode(criteria.Code)
	} else if criteria.Status != nil {
		allMatches = r.storage.SearchByStatus(*criteria.Status)
	} else if criteria.UserID != "" {
		allMatches = r.storage.SearchByUserID(criteria.UserID)
	} else if criteria.RequestID != "" {
		allMatches = r.storage.SearchByRequestID(criteria.RequestID)
	} else {
		allMatches = r.storage.SearchByDomain("") // Retrieve all records
	}

	// Apply pagination
	total := len(allMatches)
	start := pagination.Offset
	end := start + pagination.Limit

	if start > total {
		return &SearchResult{
			Records: []*ErrorRecord{},
			Total:   total,
			Offset:  pagination.Offset,
			Limit:   pagination.Limit,
			HasMore: false,
		}
	}

	if end > total {
		end = total
	}

	return &SearchResult{
		Records: allMatches[start:end],
		Total:   total,
		Offset:  pagination.Offset,
		Limit:   pagination.Limit,
		HasMore: end < total,
	}
}

// Lookup retrieves an error record by ID
func (r *ErrorRegistry) Lookup(id string) (*ErrorRecord, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.storage.Get(id)
}

// GetCallbackErrors returns any errors from callback execution
func (r *ErrorRegistry) GetCallbackErrors() []error {
	r.callbackErrorsMu.RLock()
	defer r.callbackErrorsMu.RUnlock()

	result := make([]error, len(r.callbackErrors))
	copy(result, r.callbackErrors)
	return result
}

// ClearCallbackErrors clears the callback error list
func (r *ErrorRegistry) ClearCallbackErrors() {
	r.callbackErrorsMu.Lock()
	defer r.callbackErrorsMu.Unlock()
	r.callbackErrors = r.callbackErrors[:0]
}

// Domain management methods for ErrorRegistry
func (r *ErrorRegistry) AddDomain(domain Domain) {
	r.domainManager.AddDomain(domain)
	r.logger.Info("Domain added", map[string]any{
		"domain": string(domain),
	})
}

func (r *ErrorRegistry) RemoveDomain(domain Domain) bool {
	success := r.domainManager.RemoveDomain(domain)
	if success {
		r.logger.Info("Domain removed", map[string]any{
			"domain": string(domain),
		})
	} else {
		r.logger.Warn("Attempted to remove non-existent domain", map[string]any{
			"domain": string(domain),
		})
	}
	return success
}

func (r *ErrorRegistry) HasDomain(domain Domain) bool {
	return r.domainManager.HasDomain(domain)
}

func (r *ErrorRegistry) ListDomains() []Domain {
	return r.domainManager.ListDomains()
}

// Severity management methods for ErrorRegistry
func (r *ErrorRegistry) AddSeverity(severity Severity) {
	r.severityManager.AddSeverity(severity)
	r.logger.Info("Severity added", map[string]any{
		"severity": severity.String(),
	})
}

func (r *ErrorRegistry) RemoveSeverity(severity Severity) bool {
	success := r.severityManager.RemoveSeverity(severity)
	if success {
		r.logger.Info("Severity removed", map[string]any{
			"severity": severity.String(),
		})
	} else {
		r.logger.Warn("Attempted to remove non-existent severity", map[string]any{
			"severity": severity.String(),
		})
	}
	return success
}

func (r *ErrorRegistry) HasSeverity(severity Severity) bool {
	return r.severityManager.HasSeverity(severity)
}

func (r *ErrorRegistry) ListSeverities() []Severity {
	return r.severityManager.ListSeverities()
}

// Logger management methods for ErrorRegistry
func (r *ErrorRegistry) SetLogger(logger logs.Logger) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.logger = logger
}
