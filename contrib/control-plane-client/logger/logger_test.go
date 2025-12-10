package logger

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewFileLogger_JSON(t *testing.T) {
	tmpDir := t.TempDir()

	log, err := NewFileLogger("info", "json", tmpDir)
	if err != nil {
		t.Fatalf("Failed to create JSON logger: %v", err)
	}

	log.Info("test message")

	files, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("Failed to read temp directory: %v", err)
	}

	if len(files) != 1 {
		t.Fatalf("Expected 1 log file, got %d", len(files))
	}

	filename := files[0].Name()
	if !strings.HasSuffix(filename, ".json") {
		t.Errorf("Expected .json extension, got: %s", filename)
	}

	content, err := os.ReadFile(filepath.Join(tmpDir, filename))
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	var logEntry map[string]interface{}
	if err := json.Unmarshal(content, &logEntry); err != nil {
		t.Fatalf("Failed to parse JSON log entry: %v", err)
	}

	if logEntry["level"] != "info" {
		t.Errorf("Expected level=info, got: %v", logEntry["level"])
	}

	if logEntry["message"] != "test message" {
		t.Errorf("Expected message='test message', got: %v", logEntry["message"])
	}

	if _, ok := logEntry["timestamp"]; !ok {
		t.Error("Expected timestamp field in JSON log entry")
	}
}

func TestNewFileLogger_Text(t *testing.T) {
	tmpDir := t.TempDir()

	log, err := NewFileLogger("debug", "text", tmpDir)
	if err != nil {
		t.Fatalf("Failed to create text logger: %v", err)
	}

	log.Debug("debug message")

	files, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("Failed to read temp directory: %v", err)
	}

	if len(files) != 1 {
		t.Fatalf("Expected 1 log file, got %d", len(files))
	}

	filename := files[0].Name()
	if !strings.HasSuffix(filename, ".log") {
		t.Errorf("Expected .log extension, got: %s", filename)
	}

	content, err := os.ReadFile(filepath.Join(tmpDir, filename))
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	logLine := string(content)
	if !strings.Contains(logLine, "[DEBUG]") {
		t.Error("Expected [DEBUG] in log line")
	}

	if !strings.Contains(logLine, "debug message") {
		t.Error("Expected 'debug message' in log line")
	}
}

func TestNewFileLogger_Stdout(t *testing.T) {
	log, err := NewFileLogger("info", "json", "")
	if err != nil {
		t.Fatalf("Failed to create stdout logger: %v", err)
	}

	log.Info("test message to stdout")
}

func TestFileLogger_WithFields(t *testing.T) {
	tmpDir := t.TempDir()

	log, err := NewFileLogger("info", "json", tmpDir)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	log = log.WithField("component", "test").WithField("request_id", "123")
	log.Info("test with fields")

	files, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("Failed to read temp directory: %v", err)
	}

	content, err := os.ReadFile(filepath.Join(tmpDir, files[0].Name()))
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	var logEntry map[string]interface{}
	if err := json.Unmarshal(content, &logEntry); err != nil {
		t.Fatalf("Failed to parse JSON log entry: %v", err)
	}

	if logEntry["component"] != "test" {
		t.Errorf("Expected component=test, got: %v", logEntry["component"])
	}

	if logEntry["request_id"] != "123" {
		t.Errorf("Expected request_id=123, got: %v", logEntry["request_id"])
	}
}

func TestFileLogger_DirectoryCreation(t *testing.T) {
	tmpDir := t.TempDir()
	logDir := filepath.Join(tmpDir, "logs", "tetragon", "control-plane")

	log, err := NewFileLogger("info", "json", logDir)
	if err != nil {
		t.Fatalf("Failed to create logger with nested directory: %v", err)
	}

	log.Info("test directory creation")

	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		t.Error("Expected directory to be created")
	}

	files, err := os.ReadDir(logDir)
	if err != nil {
		t.Fatalf("Failed to read log directory: %v", err)
	}

	if len(files) != 1 {
		t.Fatalf("Expected 1 log file, got %d", len(files))
	}
}

func TestFileLogger_Reopen(t *testing.T) {
	tmpDir := t.TempDir()

	log, err := NewFileLogger("info", "json", tmpDir)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Write first message
	log.Info("before rotation")

	// Simulate logrotate: move file
	files, _ := os.ReadDir(tmpDir)
	oldFile := filepath.Join(tmpDir, files[0].Name())
	rotatedFile := oldFile + ".1"
	if err := os.Rename(oldFile, rotatedFile); err != nil {
		t.Fatalf("Failed to rotate log file: %v", err)
	}

	// Reopen (simulates SIGHUP)
	if err := log.Reopen(); err != nil {
		t.Fatalf("Failed to reopen log file: %v", err)
	}

	// Write second message
	log.Info("after rotation")

	// Verify rotated file has first message
	rotatedContent, err := os.ReadFile(rotatedFile)
	if err != nil {
		t.Fatalf("Failed to read rotated file: %v", err)
	}
	if !strings.Contains(string(rotatedContent), "before rotation") {
		t.Error("Rotated file should contain 'before rotation'")
	}

	// Verify new file has second message
	newContent, err := os.ReadFile(oldFile)
	if err != nil {
		t.Fatalf("Failed to read new file: %v", err)
	}
	if !strings.Contains(string(newContent), "after rotation") {
		t.Error("New file should contain 'after rotation'")
	}
	if strings.Contains(string(newContent), "before rotation") {
		t.Error("New file should not contain 'before rotation'")
	}
}

func TestFileLogger_Close(t *testing.T) {
	tmpDir := t.TempDir()

	log, err := NewFileLogger("info", "text", tmpDir)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	log.Info("test message")

	// Close should not error
	if err := log.Close(); err != nil {
		t.Errorf("Close returned error: %v", err)
	}

	// Stdout logger should also not error on Close
	stdoutLog, _ := NewFileLogger("info", "json", "")
	if err := stdoutLog.Close(); err != nil {
		t.Errorf("Close on stdout logger returned error: %v", err)
	}
}
