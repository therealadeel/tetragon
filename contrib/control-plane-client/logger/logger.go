package logger

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
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

	// Close closes any open file handles (no-op for stdout loggers)
	Close() error

	// Reopen reopens log files (for logrotate support via SIGHUP)
	Reopen() error
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

// NewFileLogger creates a logger that writes to a file in the specified directory
// Format can be "json" or "text"
// If directory is empty, logs to stdout
func NewFileLogger(level, format, directory string) (Logger, error) {
	var writer io.Writer = os.Stdout

	if directory != "" {
		// Create directory if it doesn't exist
		if err := os.MkdirAll(directory, 0755); err != nil {
			return nil, fmt.Errorf("failed to create log directory: %w", err)
		}

		// Determine file extension based on format
		extension := ".log"
		if format == "json" {
			extension = ".json"
		}

		// Create log file with timestamp
		filename := filepath.Join(directory, fmt.Sprintf("tetragon-control-plane%s", extension))
		file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %w", err)
		}

		writer = file
	}

	var fileHandle *os.File
	var filePath string
	if directory != "" {
		extension := ".log"
		if format == "json" {
			extension = ".json"
		}
		filePath = filepath.Join(directory, fmt.Sprintf("tetragon-control-plane%s", extension))
		fileHandle = writer.(*os.File)
	}

	if format == "json" {
		return &jsonLogger{
			level:    ParseLevel(level),
			writer:   writer,
			fields:   nil,
			file:     fileHandle,
			filePath: filePath,
		}, nil
	}

	return &textLogger{
		level:    ParseLevel(level),
		writer:   writer,
		fields:   nil,
		file:     fileHandle,
		filePath: filePath,
	}, nil
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

func (l *standardLogger) Close() error {
	return nil // No resources to close for stdout logger
}

func (l *standardLogger) Reopen() error {
	return nil // Nothing to reopen for stdout logger
}

// jsonLogger implements Logger with JSON output to a file
type jsonLogger struct {
	level    Level
	writer   io.Writer
	fields   map[string]interface{}
	file     *os.File // nil for stdout
	filePath string   // empty for stdout
}

func (l *jsonLogger) shouldLog(level Level) bool {
	return level >= l.level
}

func (l *jsonLogger) writeJSON(level, message string) {
	entry := map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"level":     level,
		"message":   message,
	}

	// Add context fields
	for k, v := range l.fields {
		entry[k] = v
	}

	data, err := json.Marshal(entry)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to marshal log entry: %v\n", err)
		return
	}

	fmt.Fprintf(l.writer, "%s\n", data)
}

func (l *jsonLogger) Debug(format string, args ...interface{}) {
	if l.shouldLog(DebugLevel) {
		l.writeJSON("debug", fmt.Sprintf(format, args...))
	}
}

func (l *jsonLogger) Info(format string, args ...interface{}) {
	if l.shouldLog(InfoLevel) {
		l.writeJSON("info", fmt.Sprintf(format, args...))
	}
}

func (l *jsonLogger) Warn(format string, args ...interface{}) {
	if l.shouldLog(WarnLevel) {
		l.writeJSON("warn", fmt.Sprintf(format, args...))
	}
}

func (l *jsonLogger) Error(format string, args ...interface{}) {
	if l.shouldLog(ErrorLevel) {
		l.writeJSON("error", fmt.Sprintf(format, args...))
	}
}

func (l *jsonLogger) WithField(key string, value interface{}) Logger {
	capacity := len(l.fields) + 1
	newFields := make(map[string]interface{}, capacity)

	for k, v := range l.fields {
		newFields[k] = v
	}
	newFields[key] = value

	return &jsonLogger{
		level:    l.level,
		writer:   l.writer,
		fields:   newFields,
		file:     l.file,
		filePath: l.filePath,
	}
}

func (l *jsonLogger) WithFields(fields map[string]interface{}) Logger {
	if len(fields) == 0 {
		return l
	}

	capacity := len(l.fields) + len(fields)
	newFields := make(map[string]interface{}, capacity)

	for k, v := range l.fields {
		newFields[k] = v
	}

	for k, v := range fields {
		newFields[k] = v
	}

	return &jsonLogger{
		level:    l.level,
		writer:   l.writer,
		fields:   newFields,
		file:     l.file,
		filePath: l.filePath,
	}
}

func (l *jsonLogger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

func (l *jsonLogger) Reopen() error {
	if l.filePath == "" {
		return nil // stdout logger, nothing to reopen
	}

	// Close existing file
	if l.file != nil {
		if err := l.file.Close(); err != nil {
			return fmt.Errorf("failed to close log file: %w", err)
		}
	}

	// Reopen file
	file, err := os.OpenFile(l.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to reopen log file: %w", err)
	}

	l.file = file
	l.writer = file
	return nil
}

// textLogger implements Logger with text output to a file
type textLogger struct {
	level    Level
	writer   io.Writer
	fields   map[string]interface{}
	file     *os.File // nil for stdout
	filePath string   // empty for stdout
}

func (l *textLogger) shouldLog(level Level) bool {
	return level >= l.level
}

func (l *textLogger) formatMessage(prefix, format string, args ...interface{}) string {
	msg := fmt.Sprintf(format, args...)

	if len(l.fields) > 0 {
		var fieldStrs []string
		for k, v := range l.fields {
			fieldStrs = append(fieldStrs, fmt.Sprintf("%s=%v", k, v))
		}
		msg = fmt.Sprintf("%s [%s]", msg, strings.Join(fieldStrs, ", "))
	}

	timestamp := time.Now().UTC().Format(time.RFC3339)
	return fmt.Sprintf("%s [%s] %s", timestamp, prefix, msg)
}

func (l *textLogger) Debug(format string, args ...interface{}) {
	if l.shouldLog(DebugLevel) {
		fmt.Fprintf(l.writer, "%s\n", l.formatMessage("DEBUG", format, args...))
	}
}

func (l *textLogger) Info(format string, args ...interface{}) {
	if l.shouldLog(InfoLevel) {
		fmt.Fprintf(l.writer, "%s\n", l.formatMessage("INFO", format, args...))
	}
}

func (l *textLogger) Warn(format string, args ...interface{}) {
	if l.shouldLog(WarnLevel) {
		fmt.Fprintf(l.writer, "%s\n", l.formatMessage("WARN", format, args...))
	}
}

func (l *textLogger) Error(format string, args ...interface{}) {
	if l.shouldLog(ErrorLevel) {
		fmt.Fprintf(l.writer, "%s\n", l.formatMessage("ERROR", format, args...))
	}
}

func (l *textLogger) WithField(key string, value interface{}) Logger {
	capacity := len(l.fields) + 1
	newFields := make(map[string]interface{}, capacity)

	for k, v := range l.fields {
		newFields[k] = v
	}
	newFields[key] = value

	return &textLogger{
		level:    l.level,
		writer:   l.writer,
		fields:   newFields,
		file:     l.file,
		filePath: l.filePath,
	}
}

func (l *textLogger) WithFields(fields map[string]interface{}) Logger {
	if len(fields) == 0 {
		return l
	}

	capacity := len(l.fields) + len(fields)
	newFields := make(map[string]interface{}, capacity)

	for k, v := range l.fields {
		newFields[k] = v
	}

	for k, v := range fields {
		newFields[k] = v
	}

	return &textLogger{
		level:    l.level,
		writer:   l.writer,
		fields:   newFields,
		file:     l.file,
		filePath: l.filePath,
	}
}

func (l *textLogger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

func (l *textLogger) Reopen() error {
	if l.filePath == "" {
		return nil // stdout logger, nothing to reopen
	}

	// Close existing file
	if l.file != nil {
		if err := l.file.Close(); err != nil {
			return fmt.Errorf("failed to close log file: %w", err)
		}
	}

	// Reopen file
	file, err := os.OpenFile(l.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to reopen log file: %w", err)
	}

	l.file = file
	l.writer = file
	return nil
}
