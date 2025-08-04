package logs

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/oarkflow/log"
)

// Logger interface for different logging implementations
type Logger interface {
	Debug(msg string, fields map[string]any)
	Info(msg string, fields map[string]any)
	Warn(msg string, fields map[string]any)
	Error(msg string, fields map[string]any)
	Fatal(msg string, fields map[string]any)
}

// SlogLogger implements Logger using log/slog
type SlogLogger struct {
	logger *slog.Logger
}

// StdLogger implements Logger using standard log package
type StdLogger struct {
	logger *log.Logger
}

// OarkflowLogger implements Logger using phuslu/log
type OarkflowLogger struct {
	logger *log.Logger
}

// NewSlogLogger creates a new slog-based logger
func NewSlogLogger(logger *slog.Logger) *SlogLogger {
	if logger == nil {
		logger = slog.Default()
	}
	return &SlogLogger{logger: logger}
}

// NewStdLogger creates a new standard log-based logger
func NewStdLogger(logger *log.Logger) *StdLogger {
	if logger == nil {
		logger = &log.DefaultLogger
	}
	return &StdLogger{logger: logger}
}

func NewOarkflowLogger(logger *log.Logger) *OarkflowLogger {
	return &OarkflowLogger{logger: logger}
}

// SlogLogger methods
func (l *SlogLogger) Debug(msg string, fields map[string]any) {
	l.logger.Debug(msg, convertToSlogArgs(fields)...)
}

func (l *SlogLogger) Info(msg string, fields map[string]any) {
	l.logger.Info(msg, convertToSlogArgs(fields)...)
}

func (l *SlogLogger) Warn(msg string, fields map[string]any) {
	l.logger.Warn(msg, convertToSlogArgs(fields)...)
}

func (l *SlogLogger) Error(msg string, fields map[string]any) {
	l.logger.Error(msg, convertToSlogArgs(fields)...)
}

func (l *SlogLogger) Fatal(msg string, fields map[string]any) {
	l.logger.Error(msg, convertToSlogArgs(fields)...)
	os.Exit(1)
}

// StdLogger methods
func (l *StdLogger) Debug(msg string, fields map[string]any) {
	l.logger.Printf("[DEBUG] %s %s", msg, formatFields(fields))
}

func (l *StdLogger) Info(msg string, fields map[string]any) {
	l.logger.Printf("[INFO] %s %s", msg, formatFields(fields))
}

func (l *StdLogger) Warn(msg string, fields map[string]any) {
	l.logger.Printf("[WARN] %s %s", msg, formatFields(fields))
}

func (l *StdLogger) Error(msg string, fields map[string]any) {
	l.logger.Printf("[ERROR] %s %s", msg, formatFields(fields))
}

func (l *StdLogger) Fatal(msg string, fields map[string]any) {
	l.logger.Printf("[FATAL] %s %s", msg, formatFields(fields))
	os.Exit(1)
}

func formatFields(fields map[string]any) string {
	if len(fields) == 0 {
		return ""
	}

	result := "{"
	first := true
	for k, v := range fields {
		if !first {
			result += ", "
		}
		result += fmt.Sprintf("%s: %v", k, v)
		first = false
	}
	result += "}"
	return result
}

// Helper functions for logger implementations
func convertToSlogArgs(fields map[string]any) []any {
	args := make([]any, 0, len(fields)*2)
	for k, v := range fields {
		args = append(args, k, v)
	}
	return args
}

// OarkflowLogger methods
func (l *OarkflowLogger) Debug(msg string, fields map[string]any) {
	entry := l.logger.Debug()
	for k, v := range fields {
		entry = entry.Interface(k, v)
	}
	entry.Msg(msg)
}

func (l *OarkflowLogger) Info(msg string, fields map[string]any) {
	entry := l.logger.Info()
	for k, v := range fields {
		entry = entry.Interface(k, v)
	}
	entry.Msg(msg)
}

func (l *OarkflowLogger) Warn(msg string, fields map[string]any) {
	entry := l.logger.Warn()
	for k, v := range fields {
		entry = entry.Interface(k, v)
	}
	entry.Msg(msg)
}

func (l *OarkflowLogger) Error(msg string, fields map[string]any) {
	entry := l.logger.Error()
	for k, v := range fields {
		entry = entry.Interface(k, v)
	}
	entry.Msg(msg)
}

func (l *OarkflowLogger) Fatal(msg string, fields map[string]any) {
	entry := l.logger.Fatal()
	for k, v := range fields {
		entry = entry.Interface(k, v)
	}
	entry.Msg(msg)
	os.Exit(1)
}
