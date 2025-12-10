package logger

import (
	"fmt"
	"log"
	"strings"
)

// Logger defines the interface for logging operations
type Logger interface {
	Debug(format string, args ...interface{})
	Info(format string, args ...interface{})
	Warn(format string, args ...interface{})
	Error(format string, args ...interface{})

	// WithField returns a new logger with additional context field
	WithField(key string, value interface{}) Logger

	// WithFields returns a new logger with multiple context fields
	WithFields(fields map[string]interface{}) Logger
}

// Level represents the logging level
type Level int

const (
	DebugLevel Level = iota
	InfoLevel
	WarnLevel
	ErrorLevel
)

// ParseLevel converts a string to a Level
func ParseLevel(level string) Level {
	switch strings.ToLower(level) {
	case "debug":
		return DebugLevel
	case "info":
		return InfoLevel
	case "warn", "warning":
		return WarnLevel
	case "error":
		return ErrorLevel
	default:
		return InfoLevel
	}
}

// standardLogger implements Logger using Go's standard log package
// Uses immutable field maps for efficiency (copy-on-write)
type standardLogger struct {
	level  Level
	fields map[string]interface{} // Immutable after creation
}

// NewStandardLogger creates a new logger using the standard log package
func NewStandardLogger(level string) Logger {
	return &standardLogger{
		level:  ParseLevel(level),
		fields: nil, // nil map to save allocation for loggers without fields
	}
}

func (l *standardLogger) shouldLog(level Level) bool {
	return level >= l.level
}

func (l *standardLogger) formatMessage(prefix, format string, args ...interface{}) string {
	msg := fmt.Sprintf(format, args...)

	if len(l.fields) > 0 {
		var fieldStrs []string
		for k, v := range l.fields {
			fieldStrs = append(fieldStrs, fmt.Sprintf("%s=%v", k, v))
		}
		msg = fmt.Sprintf("%s [%s]", msg, strings.Join(fieldStrs, ", "))
	}

	return fmt.Sprintf("[%s] %s", prefix, msg)
}

func (l *standardLogger) Debug(format string, args ...interface{}) {
	if l.shouldLog(DebugLevel) {
		log.Println(l.formatMessage("DEBUG", format, args...))
	}
}

func (l *standardLogger) Info(format string, args ...interface{}) {
	if l.shouldLog(InfoLevel) {
		log.Println(l.formatMessage("INFO", format, args...))
	}
}

func (l *standardLogger) Warn(format string, args ...interface{}) {
	if l.shouldLog(WarnLevel) {
		log.Println(l.formatMessage("WARN", format, args...))
	}
}

func (l *standardLogger) Error(format string, args ...interface{}) {
	if l.shouldLog(ErrorLevel) {
		log.Println(l.formatMessage("ERROR", format, args...))
	}
}

func (l *standardLogger) WithField(key string, value interface{}) Logger {
	// Optimize: pre-allocate exact size needed
	capacity := len(l.fields) + 1
	newFields := make(map[string]interface{}, capacity)

	// Copy existing fields (no-op if l.fields is nil)
	for k, v := range l.fields {
		newFields[k] = v
	}
	newFields[key] = value

	return &standardLogger{
		level:  l.level,
		fields: newFields, // Immutable reference, never modified after creation
	}
}

func (l *standardLogger) WithFields(fields map[string]interface{}) Logger {
	if len(fields) == 0 {
		return l // No allocation needed if no fields to add
	}

	// Optimize: pre-allocate exact size needed
	capacity := len(l.fields) + len(fields)
	newFields := make(map[string]interface{}, capacity)

	// Copy existing fields
	for k, v := range l.fields {
		newFields[k] = v
	}

	// Add new fields (overwrites existing keys)
	for k, v := range fields {
		newFields[k] = v
	}

	return &standardLogger{
		level:  l.level,
		fields: newFields, // Immutable reference
	}
}
