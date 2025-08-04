package stack

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sms/pkg/errors/logs"
	"strings"
	"sync"
	"time"

	"github.com/oarkflow/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/slack-go/slack"
)

// extractCorrelationIDs extracts correlation IDs from context and metadata
func extractCorrelationIDs(ctx context.Context, metadata map[string]string) (requestID, sessionID, userID, traceID string) {
	// First try context
	if ctx != nil {
		if val := ctx.Value(RequestIDKey); val != nil {
			if str, ok := val.(string); ok {
				requestID = str
			}
		}
		if val := ctx.Value(SessionIDKey); val != nil {
			if str, ok := val.(string); ok {
				sessionID = str
			}
		}
		if val := ctx.Value(UserIDKey); val != nil {
			if str, ok := val.(string); ok {
				userID = str
			}
		}
		if val := ctx.Value(TraceIDKey); val != nil {
			if str, ok := val.(string); ok {
				traceID = str
			}
		}
	}

	// Override with metadata if present
	if metadata != nil {
		if val, ok := metadata["request_id"]; ok && val != "" {
			requestID = val
		}
		if val, ok := metadata["session_id"]; ok && val != "" {
			sessionID = val
		}
		if val, ok := metadata["user_id"]; ok && val != "" {
			userID = val
		}
		if val, ok := metadata["trace_id"]; ok && val != "" {
			traceID = val
		}
	}

	return requestID, sessionID, userID, traceID
}

var (
	projectRoot string
	rootOnce    sync.Once
)

// findProjectRoot returns the absolute working dir (where you ran `go run`).
func findProjectRoot() string {
	rootOnce.Do(func() {
		if wd, err := os.Getwd(); err == nil {
			projectRoot, _ = filepath.Abs(wd)
		}
	})
	return projectRoot
}

// captureStack dumps, filters, and rewrites your stack trace.
func captureStack(cfg *Config, severity Severity) string {
	if !cfg.CaptureStack {
		return ""
	}
	// severity gating
	pri := map[Severity]int{
		SeverityLow:      1,
		SeverityMedium:   2,
		SeverityHigh:     3,
		SeverityCritical: 4,
	}
	if pri[severity] < pri[cfg.StackSeverityLevel] {
		return ""
	}

	// 1) grab the raw goroutine stack
	buf := make([]byte, 64<<10)
	n := runtime.Stack(buf, false)
	raw := string(buf[:n])

	// 2) strip out any pkg/errors frames if desired
	if cfg.FilterInternalStack {
		raw = filterInternal(raw)
	}

	// 3) rewrite all absolute paths under projectRoot → /root/, GOROOT → /go/
	return rewritePaths(raw)
}

// filterInternal removes every frame whose file line lives in pkg/errors.
func filterInternal(raw string) string {
	// discover exactly where pkg/errors lives
	_, thisFile, _, _ := runtime.Caller(0)
	errorsDir := filepath.Dir(thisFile)

	var out strings.Builder
	lines := strings.Split(raw, "\n")

	// keep the goroutine header
	if len(lines) > 0 {
		out.WriteString(lines[0] + "\n")
	}

	// frames are [funcLine, fileLine, blankLine]
	for i := 1; i < len(lines)-1; i += 3 {
		funcLine := lines[i]
		fileLine := lines[i+1]

		// drop if fileLine points into pkg/errors dir
		if !strings.HasPrefix(fileLine, errorsDir) {
			out.WriteString(funcLine + "\n")
			out.WriteString(fileLine + "\n")
		}
		// skip the blank line automatically
	}
	return out.String()
}

// rewritePaths turns absolute paths into /root/... or /go/...
func rewritePaths(raw string) string {
	root := findProjectRoot()
	goRoot := runtime.GOROOT()

	var out strings.Builder
	for _, line := range strings.Split(raw, "\n") {
		// 1) Pull off all leading spaces or tabs
		indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		trimmed := strings.TrimLeft(line, " \t")

		// 2) If it starts with root or goRoot, rewrite it
		var newBody string
		switch {
		case root != "" && strings.HasPrefix(trimmed, root):
			// split out any suffix (":line +offset")
			parts := strings.Fields(trimmed)
			pathPart := parts[0]
			rel, err := filepath.Rel(root, pathPart)
			if err != nil {
				newBody = trimmed
			} else {
				newBody = "/root/" + filepath.ToSlash(rel)
				if len(parts) > 1 {
					newBody += " " + strings.Join(parts[1:], " ")
				}
			}
		case goRoot != "" && strings.HasPrefix(trimmed, goRoot):
			parts := strings.Fields(trimmed)
			pathPart := parts[0]
			rel, err := filepath.Rel(goRoot, pathPart)
			if err != nil {
				newBody = trimmed
			} else {
				newBody = "/go/" + filepath.ToSlash(rel)
				if len(parts) > 1 {
					newBody += " " + strings.Join(parts[1:], " ")
				}
			}
		default:
			newBody = trimmed
		}

		// 3) rebuild with original indent
		out.WriteString(indent + newBody + "\n")
	}
	return out.String()
}

// getCallerInfo returns the first external frame, with its path
// rewritten to start with "/root/" instead of the real project path.
func getCallerInfo() (file string, line int, function string) {
	// 1) where do errors live on disk?
	_, thisFile, _, _ := runtime.Caller(0)
	thisDir := filepath.Dir(thisFile)

	// 2) capture PCs, skipping Callers + this func
	pcs := make([]uintptr, 32)
	n := runtime.Callers(2, pcs)
	frames := runtime.CallersFrames(pcs[:n])
	// 3) project root for path-rewriting
	root := findProjectRoot()

	for {
		fr, more := frames.Next()
		// skip any frame in the errors package
		if strings.HasPrefix(fr.File, thisDir) {
			if !more {
				break
			}
			continue
		}

		// compute a relative path from projectRoot → fr.File
		rel, err := filepath.Rel(root, fr.File)
		if err != nil {
			// fallback to full path on error
			file = fr.File
		} else {
			// always use forward slashes on the returned path
			rel = filepath.ToSlash(rel)
			file = "/root/" + rel
		}

		line = fr.Line
		function = fr.Function
		return
	}

	return "unknown", 0, "unknown"
}

// New creates a new Error with comprehensive debugging information.
func New(domain Domain, severity Severity, status int, code, message string, metadata map[string]string) *Error {
	return NewWithContext(context.Background(), domain, severity, status, code, message, metadata)
}

// NewWithContext creates a new Error with context for correlation IDs.
func NewWithContext(ctx context.Context, domain Domain, severity Severity, status int, code, message string, metadata map[string]string) *Error {
	// Validate domain and severity
	if !globalRegistry.HasDomain(domain) {
		globalLogger.Warn("Creating error with unknown domain", map[string]any{
			"domain": string(domain),
			"code":   code,
		})
	}

	if !globalRegistry.HasSeverity(severity) {
		globalLogger.Warn("Creating error with unknown severity", map[string]any{
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

// getEnvironment returns the current environment (dev, staging, prod)
func getEnvironment() string {
	if env := os.Getenv("ENVIRONMENT"); env != "" {
		return env
	}
	if env := os.Getenv("ENV"); env != "" {
		return env
	}
	return "development"
}

// getVersion returns the application version
func getVersion() string {
	if version := os.Getenv("VERSION"); version != "" {
		return version
	}
	if version := os.Getenv("APP_VERSION"); version != "" {
		return version
	}
	return "unknown"
}

// Utility functions for checking error properties

// IsStatus checks whether err or any of its wrappers has the given status code.
func IsStatus(err error, target int) bool {
	var e *Error
	if errors.As(err, &e) {
		return e.Status == target
	}
	return false
}

// IsCode checks whether err or any of its wrappers has the given error code.
func IsCode(err error, code string) bool {
	var e *Error
	if errors.As(err, &e) {
		return e.Code == code
	}
	return false
}

// IsDomain checks whether err or any of its wrappers has the given domain.
func IsDomain(err error, domain Domain) bool {
	var e *Error
	if errors.As(err, &e) {
		return e.Domain == domain
	}
	return false
}

// IsSeverity checks whether err or any of its wrappers has the given severity.
func IsSeverity(err error, severity Severity) bool {
	var e *Error
	if errors.As(err, &e) {
		return e.Severity == severity
	}
	return false
}

// GetErrorID extracts the error ID from an error
func GetErrorID(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.ID
	}
	return ""
}

// Debugging and analysis functions

// LookupError retrieves comprehensive error information by ID
func LookupError(id string) (*ErrorRecord, error) {
	record, exists := globalRegistry.Lookup(id)
	if !exists {
		return nil, fmt.Errorf("error with ID %s not found", id)
	}
	return record, nil
}

// PrintErrorDetails prints comprehensive error details for debugging
func PrintErrorDetails(id string) error {
	record, err := LookupError(id)
	if err != nil {
		return err
	}

	fmt.Printf("=== ERROR DETAILS ===\n")
	fmt.Printf("ID: %s\n", record.ID)
	fmt.Printf("Code: %s\n", record.Code)
	fmt.Printf("Domain: %s\n", record.Domain)
	fmt.Printf("Severity: %s\n", record.Severity)
	fmt.Printf("Status: %d\n", record.Status)
	fmt.Printf("Message: %s\n", record.Message)
	fmt.Printf("Timestamp: %s\n", record.Timestamp.Format(time.RFC3339))
	fmt.Printf("File: %s:%d\n", record.File, record.Line)
	fmt.Printf("Function: %s\n", record.Function)
	fmt.Printf("Environment: %s\n", record.Environment)
	fmt.Printf("Version: %s\n", record.Version)

	if record.UserID != "" {
		fmt.Printf("User ID: %s\n", record.UserID)
	}
	if record.RequestID != "" {
		fmt.Printf("Request ID: %s\n", record.RequestID)
	}
	if record.SessionID != "" {
		fmt.Printf("Session ID: %s\n", record.SessionID)
	}

	if len(record.Metadata) > 0 {
		fmt.Printf("Metadata:\n")
		for k, v := range record.Metadata {
			fmt.Printf("  %s: %s\n", k, v)
		}
	}

	fmt.Printf("Stack Trace:\n%s\n", record.Stack)
	fmt.Printf("=====================\n")

	return nil
}

// SearchErrors searches for errors based on criteria
func SearchErrors(criteria SearchCriteria) []*ErrorRecord {
	var results []*ErrorRecord

	if criteria.Domain != nil {
		results = globalRegistry.storage.SearchByDomain(*criteria.Domain)
	} else if criteria.Severity != nil {
		results = globalRegistry.storage.SearchBySeverity(*criteria.Severity)
	} else if criteria.Code != "" {
		results = globalRegistry.storage.SearchByCode(criteria.Code)
	} else if criteria.Status != nil {
		results = globalRegistry.storage.SearchByStatus(*criteria.Status)
	} else if criteria.UserID != "" {
		results = globalRegistry.storage.SearchByUserID(criteria.UserID)
	} else if criteria.RequestID != "" {
		results = globalRegistry.storage.SearchByRequestID(criteria.RequestID)
	} else {
		results = globalRegistry.storage.SearchByDomain("") // Retrieve all records
	}

	return results
}

// SearchErrorsWithPagination searches for errors with pagination support
func SearchErrorsWithPagination(criteria SearchCriteria, pagination PaginationOptions) *SearchResult {
	return globalRegistry.SearchWithPagination(criteria, pagination)
}

// GetConfig returns the current global configuration
func GetConfig() *Config {
	return globalRegistry.config
}

// SetConfig updates the global configuration
func SetConfig(config *Config) {
	globalRegistry.mu.Lock()
	defer globalRegistry.mu.Unlock()
	globalRegistry.config = config
}

// GetCallbackErrors returns any errors from callback execution
func GetCallbackErrors() []error {
	return globalRegistry.GetCallbackErrors()
}

// ClearCallbackErrors clears the callback error list
func ClearCallbackErrors() {
	globalRegistry.ClearCallbackErrors()
}

// WithRequestID adds a request ID to the context
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, RequestIDKey, requestID)
}

// WithSessionID adds a session ID to the context
func WithSessionID(ctx context.Context, sessionID string) context.Context {
	return context.WithValue(ctx, SessionIDKey, sessionID)
}

// WithUserID adds a user ID to the context
func WithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, UserIDKey, userID)
}

// WithTraceID adds a trace ID to the context
func WithTraceID(ctx context.Context, traceID string) context.Context {
	return context.WithValue(ctx, TraceIDKey, traceID)
}

// GetRequestID extracts request ID from context
func GetRequestID(ctx context.Context) string {
	if val := ctx.Value(RequestIDKey); val != nil {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

// GetSessionID extracts session ID from context
func GetSessionID(ctx context.Context) string {
	if val := ctx.Value(SessionIDKey); val != nil {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

// GetUserID extracts user ID from context
func GetUserID(ctx context.Context) string {
	if val := ctx.Value(UserIDKey); val != nil {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

// GetTraceID extracts trace ID from context
func GetTraceID(ctx context.Context) string {
	if val := ctx.Value(TraceIDKey); val != nil {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

// Helper functions for common error creation patterns

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

// Global callback management functions

// SetSyncCallbacks sets whether callbacks should be executed synchronously (deprecated)
func SetSyncCallbacks(sync bool) {
	syncCallbacks = sync
}

// RegisterErrorCallback registers a global error callback
func RegisterErrorCallback(name string, callback ErrorCallback) {
	globalCallbackMgr.RegisterCallback(name, callback)
}

// UnregisterErrorCallback removes a global error callback
func UnregisterErrorCallback(name string) {
	globalCallbackMgr.UnregisterCallback(name)
}

// Global domain management functions
func AddDomain(domain Domain) {
	globalRegistry.AddDomain(domain)
}

func RemoveDomain(domain Domain) bool {
	return globalRegistry.RemoveDomain(domain)
}

func HasDomain(domain Domain) bool {
	return globalRegistry.HasDomain(domain)
}

func ListDomains() []Domain {
	return globalRegistry.ListDomains()
}

// Global severity management functions
func AddSeverity(severity Severity) {
	globalRegistry.AddSeverity(severity)
}

func RemoveSeverity(severity Severity) bool {
	return globalRegistry.RemoveSeverity(severity)
}

func HasSeverity(severity Severity) bool {
	return globalRegistry.HasSeverity(severity)
}

func ListSeverities() []Severity {
	return globalRegistry.ListSeverities()
}

// Global logger management functions
func SetGlobalLogger(logger logs.Logger) {
	globalRegistry.SetLogger(logger)
	globalLogger = logger
}

func GetGlobalLogger() logs.Logger {
	return globalLogger
}

// Fixing ErrorMiddleware
func ErrorMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				err := NewCriticalError(DomainSystem, "SYS_002", "Unhandled panic", nil)
				PrintErrorDetails(err.ID)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// Metrics Integration
var errorCounter = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "error_count",
		Help: "Count of errors categorized by domain and severity",
	},
	[]string{"domain", "severity"},
)

func RegisterMetricsCallback(callback func(err Error)) {
	prometheus.MustRegister(errorCounter)
	callback = func(err Error) {
		errorCounter.WithLabelValues(string(err.Domain), err.Severity.String()).Inc()
	}
}

// Error Categorization
func NewValidationError(code, message string, details map[string]string) *Error {
	return New(DomainValidation, SeverityMedium, 400, code, message, details)
}

// Error Notification
func RegisterNotificationCallback(callback func(err Error)) {
	callback = func(err Error) {
		if err.Severity == SeverityCritical {
			slackClient := slack.New("your-slack-token")
			_, _, err := slackClient.PostMessage("#alerts", slack.MsgOptionText(fmt.Sprintf("Critical Error: %s", err.Message), false))
			if err != nil {
				log.Printf("Failed to send Slack notification: %v", err)
			}
		}
	}
}

// RenderErrorPage implementation
func RenderErrorPage(w http.ResponseWriter, status int, title, message, suggestion, details, retryURL string) {
	w.WriteHeader(status)
	fmt.Fprintf(w, "<html><head><title>%s</title></head><body>", title)
	fmt.Fprintf(w, "<h1>%s</h1>", title)
	fmt.Fprintf(w, "<p>%s</p>", message)
	fmt.Fprintf(w, "<p>%s</p>", suggestion)
	fmt.Fprintf(w, "<p>%s</p>", details)
	fmt.Fprintf(w, "<a href='%s'>Retry</a>", retryURL)
	fmt.Fprintf(w, "</body></html>")
}
