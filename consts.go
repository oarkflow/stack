package stack

type (
	CallbackMode string
	// Domain represents a logical grouping for errors.
	Domain string
	// Severity levels for errors
	Severity uint
)

const (
	CallbackModeAsync CallbackMode = "async"
	CallbackModeSync  CallbackMode = "sync"
	CallbackModeMixed CallbackMode = "mixed"
)

const (
	SeverityLow Severity = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

func (s Severity) IsValid() bool {
	if s < SeverityLow || s > SeverityCritical {
		return false
	}
	return true
}

// Predefined domains
const (
	DomainValidation Domain = "validation"
	DomainSystem     Domain = "system"
	DomainNetwork    Domain = "network"
	DomainUser       Domain = "user"
	DomainAPI        Domain = "api"
	DomainAuth       Domain = "auth"
	DomainDB         Domain = "database"
)
