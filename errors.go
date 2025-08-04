// package stack provides a robust, CloudFlare-style error handling framework
package stack

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/oarkflow/stack/logs"
)

// IDFormat specifies the format of the error ID
type IDFormat string

const (
	IDFormatRandom    IDFormat = "random"    // ERR-<16hex>
	IDFormatUUID      IDFormat = "uuid"      // ERR-<uuid>
	IDFormatTimestamp IDFormat = "timestamp" // ERR-<timestamp>-<8hex>
	IDFormatMetadata  IDFormat = "metadata"  // ERR-<domain>-<status>-<8hex>
)

// Pagination support
type PaginationOptions struct {
	Offset int `json:"offset"`
	Limit  int `json:"limit"`
}

type SearchResult struct {
	Records []*ErrorRecord `json:"records"`
	Total   int            `json:"total"`
	Offset  int            `json:"offset"`
	Limit   int            `json:"limit"`
	HasMore bool           `json:"has_more"`
}

// Context keys for correlation IDs
type contextKey string

const (
	RequestIDKey contextKey = "request_id"
	SessionIDKey contextKey = "session_id"
	UserIDKey    contextKey = "user_id"
	TraceIDKey   contextKey = "trace_id"
)

// Output sink interface for extensible backends
type OutputSink interface {
	Write(record *ErrorRecord) error
	Close() error
}

// Null output sink (for testing)
type NullOutputSink struct{}

func NewNullOutputSink() *NullOutputSink                  { return &NullOutputSink{} }
func (n *NullOutputSink) Write(record *ErrorRecord) error { return nil }
func (n *NullOutputSink) Close() error                    { return nil }

// Default configuration
func DefaultConfig() *Config {
	return &Config{
		CaptureStack:         true,
		StackSeverityLevel:   SeverityHigh,
		MaxRetryWrites:       3,
		WriteBufferSize:      100,
		IDFormat:             IDFormatTimestamp,
		CallbackMode:         CallbackModeAsync,
		PaginationLimit:      100,
		Environment:          "development",
		DebugMode:            false,
		IndexingEnabled:      true,
		CorrelationIDEnabled: true,
	}
}

// ErrorRecord stores comprehensive error information for debugging
type ErrorRecord struct {
	ID          string            `json:"id"`
	Code        string            `json:"code"`
	Domain      Domain            `json:"domain"`
	Severity    Severity          `json:"severity"`
	Status      int               `json:"status"`
	Message     string            `json:"message"`
	Timestamp   time.Time         `json:"timestamp"`
	Stack       string            `json:"stack,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	File        string            `json:"file,omitempty"`
	Line        int               `json:"line,omitempty"`
	Function    string            `json:"function,omitempty"`
	UserID      string            `json:"user_id,omitempty"`
	RequestID   string            `json:"request_id,omitempty"`
	SessionID   string            `json:"session_id,omitempty"`
	TraceID     string            `json:"trace_id,omitempty"`
	Environment string            `json:"environment,omitempty"`
	Version     string            `json:"version,omitempty"`
}

// MarshalJSON provides custom JSON marshaling for ErrorRecord
func (r *ErrorRecord) MarshalJSON() ([]byte, error) {
	type Alias ErrorRecord
	aux := &struct {
		*Alias
		DebugInfo *struct {
			File     string `json:"file,omitempty"`
			Line     int    `json:"line,omitempty"`
			Function string `json:"function,omitempty"`
			Stack    string `json:"stack,omitempty"`
		} `json:"debug_info,omitempty"`
	}{
		Alias: (*Alias)(r),
	}

	// Only include debug info in debug mode or for high severity errors
	if globalRegistry != nil && (globalRegistry.config.DebugMode || r.Severity == SeverityHigh || r.Severity == SeverityCritical) {
		aux.DebugInfo = &struct {
			File     string `json:"file,omitempty"`
			Line     int    `json:"line,omitempty"`
			Function string `json:"function,omitempty"`
			Stack    string `json:"stack,omitempty"`
		}{
			File:     r.File,
			Line:     r.Line,
			Function: r.Function,
			Stack:    r.Stack,
		}
		// Remove from main struct to avoid duplication
		aux.File = ""
		aux.Line = 0
		aux.Function = ""
		aux.Stack = ""
	}

	return json.Marshal(aux)
}

// Global error registry and callback manager
var (
	globalRegistry    *ErrorRegistry
	globalCallbackMgr *ErrorCallbackManager
	globalDomainMgr   *DomainManager
	globalSeverityMgr *SeverityManager
	globalLogger      logs.Logger
	syncCallbacks     = false // Deprecated: use config.CallbackMode instead
)

func init() {
	globalRegistry = NewErrorRegistry("errors.json")
	globalCallbackMgr = NewErrorCallbackManager()
	globalDomainMgr = NewDomainManager()
	globalSeverityMgr = NewSeverityManager()
	globalLogger = logs.NewStdLogger(nil) // Default to standard logger
}

// Error is the custom error type returned by this package.
type Error struct {
	ID        string            `json:"id"`                         // formatted as ERR-<format>
	Code      string            `json:"code"`                       // custom error code (e.g., "E_AUTH_01")
	Domain    Domain            `json:"domain"`                     // the domain of the error
	Severity  Severity          `json:"severity"`                   // severity level
	Status    int               `json:"status"`                     // HTTP-style status code or custom status
	Message   string            `json:"message"`                    // human-readable message
	Timestamp time.Time         `json:"timestamp"`                  // error creation time
	Stack     string            `json:"stack,omitempty"`            // stack trace (omit if not captured)
	Metadata  map[string]string `json:"metadata,omitempty"`         // extensible metadata
	Err       error             `json:"underlying_error,omitempty"` // underlying error (optional)
	RequestID string            `json:"request_id,omitempty"`       // correlation ID
	SessionID string            `json:"session_id,omitempty"`       // session correlation
	UserID    string            `json:"user_id,omitempty"`          // user correlation
	TraceID   string            `json:"trace_id,omitempty"`         // trace correlation
}

// MarshalJSON provides custom JSON marshaling for Error
func (e *Error) MarshalJSON() ([]byte, error) {
	type Alias Error
	aux := &struct {
		*Alias
		UnderlyingError string `json:"underlying_error,omitempty"`
		DebugInfo       *struct {
			Stack string `json:"stack,omitempty"`
		} `json:"debug_info,omitempty"`
	}{
		Alias: (*Alias)(e),
	}

	// Include underlying error as string
	if e.Err != nil {
		aux.UnderlyingError = e.Err.Error()
	}

	// Only include debug info if in debug mode or high severity
	if globalRegistry != nil && (globalRegistry.config.DebugMode || e.Severity == SeverityHigh || e.Severity == SeverityCritical) {
		if e.Stack != "" {
			aux.DebugInfo = &struct {
				Stack string `json:"stack,omitempty"`
			}{
				Stack: e.Stack,
			}
		}
	}

	return json.Marshal(aux)
}

// UnmarshalJSON provides custom JSON unmarshaling for Error
func (e *Error) UnmarshalJSON(data []byte) error {
	type Alias Error
	aux := &struct {
		*Alias
		UnderlyingError string `json:"underlying_error,omitempty"`
		DebugInfo       *struct {
			Stack string `json:"stack,omitempty"`
		} `json:"debug_info,omitempty"`
	}{
		Alias: (*Alias)(e),
	}

	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	// Restore underlying error if present
	if aux.UnderlyingError != "" {
		e.Err = fmt.Errorf("%s", aux.UnderlyingError)
	}

	// Restore stack if present
	if aux.DebugInfo != nil && aux.DebugInfo.Stack != "" {
		e.Stack = aux.DebugInfo.Stack
	}

	return nil
}

// SearchCriteria defines search parameters for error records
type SearchCriteria struct {
	Domain    *Domain    `json:"domain,omitempty"`
	Severity  *Severity  `json:"severity,omitempty"`
	Code      string     `json:"code,omitempty"`
	Status    *int       `json:"status,omitempty"`
	UserID    string     `json:"user_id,omitempty"`
	RequestID string     `json:"request_id,omitempty"`
	FromTime  *time.Time `json:"from_time,omitempty"`
	ToTime    *time.Time `json:"to_time,omitempty"`
}

// Error implements the error interface.
func (e *Error) Error() string {
	prefix := fmt.Sprintf("%s [%s:%s:%d:%s] %s", e.ID, e.Domain, e.Severity, e.Status, e.Code, e.Message)
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", prefix, e.Err)
	}
	return prefix
}

// String returns a detailed string representation for debugging
func (e *Error) String() string {
	if e.Err != nil {
		return fmt.Sprintf("%s [%s:%s:%d:%s] %s: %v\nStack: %s",
			e.ID, e.Domain, e.Severity, e.Status, e.Code, e.Message, e.Err, e.Stack)
	}
	return fmt.Sprintf("%s [%s:%s:%d:%s] %s\nStack: %s",
		e.ID, e.Domain, e.Severity, e.Status, e.Code, e.Message, e.Stack)
}

// Unwrap returns the underlying error, if any.
func (e *Error) Unwrap() error {
	return e.Err
}

// Wrap wraps an existing error with comprehensive debugging information.
func Wrap(underlying error, domain Domain, severity Severity, status int, code, message string, metadata map[string]string) *Error {
	return WrapWithContext(context.Background(), underlying, domain, severity, status, code, message, metadata)
}

// WrapWithContext wraps an existing error with context for correlation IDs.
func WrapWithContext(ctx context.Context, underlying error, domain Domain, severity Severity, status int, code, message string, metadata map[string]string) *Error {
	// Validate domain and severity
	if !globalRegistry.HasDomain(domain) {
		globalLogger.Warn("Wrapping error with unknown domain", map[string]any{
			"domain": string(domain),
			"code":   code,
		})
	}

	if !globalRegistry.HasSeverity(severity) {
		globalLogger.Warn("Wrapping error with unknown severity", map[string]any{
			"severity": severity.String(),
			"code":     code,
		})
	}

	file, line, function := getCallerInfo()
	requestID, sessionID, userID, traceID := extractCorrelationIDs(ctx, metadata)
	ops, _ := metadata["operation"]

	err := &Error{
		ID:        generateID(domain, ops, severity, status),
		Code:      code,
		Domain:    domain,
		Severity:  severity,
		Status:    status,
		Message:   message,
		Timestamp: time.Now(),
		Stack:     captureStack(globalRegistry.config, severity),
		Metadata:  metadata,
		Err:       underlying,
		RequestID: requestID,
		SessionID: sessionID,
		UserID:    userID,
		TraceID:   traceID,
	}

	// Create error record for registry
	record := &ErrorRecord{
		ID:          err.ID,
		Code:        code,
		Domain:      domain,
		Severity:    severity,
		Status:      status,
		Message:     message,
		Timestamp:   err.Timestamp,
		Stack:       err.Stack,
		Metadata:    metadata,
		File:        file,
		Line:        line,
		Function:    function,
		Environment: getEnvironment(),
		Version:     getVersion(),
		RequestID:   requestID,
		SessionID:   sessionID,
		UserID:      userID,
		TraceID:     traceID,
	}

	// Register error for debugging
	globalRegistry.Register(record)

	return err
}

// NewAuthError creates a new authentication error
func NewAuthError(code, message string, metadata map[string]string) *Error {
	return New(DomainAuth, SeverityMedium, 401, code, message, metadata)
}

// NewAuthErrorWithContext creates a new authentication error with context
func NewAuthErrorWithContext(ctx context.Context, code, message string, metadata map[string]string) *Error {
	return NewWithContext(ctx, DomainAuth, SeverityMedium, 401, code, message, metadata)
}

// NewDBError creates a new database error
func NewDBError(code, message string, metadata map[string]string) *Error {
	return New(DomainDB, SeverityHigh, 500, code, message, metadata)
}

// NewDBErrorWithContext creates a new database error with context
func NewDBErrorWithContext(ctx context.Context, code, message string, metadata map[string]string) *Error {
	return NewWithContext(ctx, DomainDB, SeverityHigh, 500, code, message, metadata)
}

// NewAPIError creates a new API error
func NewAPIError(status int, code, message string, metadata map[string]string) *Error {
	severity := SeverityMedium
	if status >= 500 {
		severity = SeverityHigh
	} else if status >= 400 {
		severity = SeverityMedium
	} else {
		severity = SeverityLow
	}
	return New(DomainAPI, severity, status, code, message, metadata)
}

// NewAPIErrorWithContext creates a new API error with context
func NewAPIErrorWithContext(ctx context.Context, status int, code, message string, metadata map[string]string) *Error {
	severity := SeverityMedium
	if status >= 500 {
		severity = SeverityHigh
	} else if status >= 400 {
		severity = SeverityMedium
	} else {
		severity = SeverityLow
	}
	return NewWithContext(ctx, DomainAPI, severity, status, code, message, metadata)
}

// NewCriticalError creates a new critical system error
func NewCriticalError(domain Domain, code, message string, metadata map[string]string) *Error {
	return New(domain, SeverityCritical, 500, code, message, metadata)
}

// NewCriticalErrorWithContext creates a new critical system error with context
func NewCriticalErrorWithContext(ctx context.Context, domain Domain, code, message string, metadata map[string]string) *Error {
	return NewWithContext(ctx, domain, SeverityCritical, 500, code, message, metadata)
}
