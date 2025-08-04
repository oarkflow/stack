package stack

import "sync"

// Configuration types
type Config struct {
	CaptureStack         bool         `json:"capture_stack"`
	StackSeverityLevel   Severity     `json:"stack_severity_level"`
	MaxRetryWrites       int          `json:"max_retry_writes"`
	WriteBufferSize      int          `json:"write_buffer_size"`
	IDFormat             IDFormat     `json:"id_format"`
	CallbackMode         CallbackMode `json:"callback_mode"`
	PaginationLimit      int          `json:"pagination_limit"`
	Environment          string       `json:"environment"`
	DebugMode            bool         `json:"debug_mode"`
	OutputSinks          []OutputSink `json:"-"` // Don't serialize functions
	IndexingEnabled      bool         `json:"indexing_enabled"`
	FilterInternalStack  bool
	CorrelationIDEnabled bool `json:"correlation_id_enabled"`
}

// DomainManager manages dynamic domains
type DomainManager struct {
	mu      sync.RWMutex
	domains map[Domain]bool
}

// SeverityManager manages dynamic severities
type SeverityManager struct {
	mu         sync.RWMutex
	severities map[Severity]bool
}

// NewDomainManager creates a new domain manager
func NewDomainManager() *DomainManager {
	dm := &DomainManager{
		domains: make(map[Domain]bool),
	}

	// Initialize with predefined domains
	predefinedDomains := []Domain{
		DomainAuth, DomainDB, DomainAPI, DomainNetwork, DomainSystem, DomainUser,
	}

	for _, domain := range predefinedDomains {
		dm.domains[domain] = true
	}

	return dm
}

// NewSeverityManager creates a new severity manager
func NewSeverityManager() *SeverityManager {
	sm := &SeverityManager{
		severities: make(map[Severity]bool),
	}

	// Initialize with predefined severities
	predefinedSeverities := []Severity{
		SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical,
	}

	for _, severity := range predefinedSeverities {
		sm.severities[severity] = true
	}

	return sm
}

// Domain management methods
func (dm *DomainManager) AddDomain(domain Domain) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	dm.domains[domain] = true
}

func (dm *DomainManager) RemoveDomain(domain Domain) bool {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if _, exists := dm.domains[domain]; exists {
		delete(dm.domains, domain)
		return true
	}
	return false
}

func (dm *DomainManager) HasDomain(domain Domain) bool {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	_, exists := dm.domains[domain]
	return exists
}

func (dm *DomainManager) ListDomains() []Domain {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	domains := make([]Domain, 0, len(dm.domains))
	for domain := range dm.domains {
		domains = append(domains, domain)
	}
	return domains
}

// Severity management methods
func (sm *SeverityManager) AddSeverity(severity Severity) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.severities[severity] = true
}

func (sm *SeverityManager) RemoveSeverity(severity Severity) bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if _, exists := sm.severities[severity]; exists {
		delete(sm.severities, severity)
		return true
	}
	return false
}

func (sm *SeverityManager) HasSeverity(severity Severity) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	_, exists := sm.severities[severity]
	return exists
}

func (sm *SeverityManager) ListSeverities() []Severity {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	severities := make([]Severity, 0, len(sm.severities))
	for severity := range sm.severities {
		severities = append(severities, severity)
	}
	return severities
}
