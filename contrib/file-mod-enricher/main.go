package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"gopkg.in/yaml.v2"

	tetragon "github.com/cilium/tetragon/api/v1/tetragon"
)

// Configuration structures
type Config struct {
	TargetFiles []string       `yaml:"target_files"`
	Tetragon    TetragonConfig `yaml:"tetragon"`
	Output      OutputConfig   `yaml:"output"`
	Tracker     TrackerConfig  `yaml:"tracker"`
}

type TetragonConfig struct {
	ServerAddress string `yaml:"server_address"`
}

type OutputConfig struct {
	Format         string `yaml:"format"`
	Indent         bool   `yaml:"indent"`
	IncludeMetrics bool   `yaml:"include_metrics"`
}

type TrackerConfig struct {
	CleanupTimeout string `yaml:"cleanup_timeout"`
	StatsInterval  string `yaml:"stats_interval"`
}

// Advanced FileDescriptorTracker with configurable target files
type FileDescriptorTracker struct {
	mu          sync.RWMutex
	openFiles   map[string]*OpenFileInfo // key: "pid:fd"
	timeout     time.Duration
	metrics     *TrackerMetrics
	targetFiles map[string]bool // files we care about (now configurable)
}

type OpenFileInfo struct {
	PID           uint32
	FD            int32
	FilePath      string
	OpenTime      time.Time
	Process       *tetragon.Process
	OpenEvent     *tetragon.GetEventsResponse
	WriteDetected bool
	PreFileInfo   *FileMetadata `json:"pre_file_info,omitempty"`
}

type FileMetadata struct {
	Size        int64     `json:"size"`
	ModTime     time.Time `json:"mod_time"`
	Permissions string    `json:"permissions"`
	Inode       uint64    `json:"inode"`
}

type TrackerMetrics struct {
	OpenEventsTracked  int64
	CloseEventsMatched int64
	HashCalculations   int64
	HashErrors         int64
	StaleFDsCleanedUp  int64
}

type EnrichedEvent struct {
	Event    *tetragon.GetEventsResponse `json:"event"`
	FileHash *FileHashInfo               `json:"file_hash,omitempty"`
	Metrics  *TrackerMetrics             `json:"metrics,omitempty"`
}

type FileHashInfo struct {
	Algorithm        string        `json:"algorithm"`
	Value            string        `json:"value"`
	FilePath         string        `json:"file_path"`
	Timestamp        time.Time     `json:"timestamp"`
	FileSize         int64         `json:"file_size"`
	ModificationTime time.Time     `json:"modification_time"`
	PreFileInfo      *FileMetadata `json:"pre_file_info,omitempty"`
	Changed          bool          `json:"changed"`
}

func NewFileDescriptorTracker(config *Config) *FileDescriptorTracker {
	// Parse timeout from config
	timeout := 5 * time.Minute // default
	if config.Tracker.CleanupTimeout != "" {
		if parsed, err := time.ParseDuration(config.Tracker.CleanupTimeout); err == nil {
			timeout = parsed
		}
	}

	// Build target files map from config
	targetFiles := make(map[string]bool)
	for _, file := range config.TargetFiles {
		targetFiles[file] = true
	}

	return &FileDescriptorTracker{
		openFiles:   make(map[string]*OpenFileInfo),
		timeout:     timeout,
		metrics:     &TrackerMetrics{},
		targetFiles: targetFiles,
	}
}

func (fdt *FileDescriptorTracker) IsTargetFile(filePath string) bool {
	fdt.mu.RLock()
	defer fdt.mu.RUnlock()
	return fdt.targetFiles[filePath]
}

func (fdt *FileDescriptorTracker) captureFileMetadata(filePath string) *FileMetadata {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		log.Printf("Warning: Could not stat file %s at open time: %v", filePath, err)
		return nil
	}

	// Get inode (Unix-specific)
	var inode uint64
	if stat, ok := fileInfo.Sys().(*syscall.Stat_t); ok {
		inode = stat.Ino
	}

	return &FileMetadata{
		Size:        fileInfo.Size(),
		ModTime:     fileInfo.ModTime(),
		Permissions: fileInfo.Mode().String(),
		Inode:       inode,
	}
}

func (fdt *FileDescriptorTracker) TrackOpen(event *tetragon.GetEventsResponse) {
	kprobe := event.GetProcessKprobe()
	if kprobe == nil || !strings.HasSuffix(kprobe.FunctionName, "sys_openat") {
		return
	}

	// Check arguments
	if len(kprobe.Args) < 3 {
		return
	}

	filePath := kprobe.Args[1].GetStringArg()
	if !fdt.IsTargetFile(filePath) {
		return
	}

	// Check if opened with write permissions
	flags := kprobe.Args[2].GetIntArg()
	hasWriteFlag := (flags&0x01 != 0) || (flags&0x02 != 0) || (flags&0x40 != 0) // O_WRONLY | O_RDWR | O_CREAT

	if !hasWriteFlag {
		return
	}

	// Get the returned file descriptor
	if kprobe.Return == nil {
		return
	}

	fd := kprobe.Return.GetIntArg()
	if fd <= 0 {
		return
	}

	pid := kprobe.Process.Pid.Value
	key := fmt.Sprintf("%d:%d", pid, fd)

	fdt.mu.Lock()
	defer fdt.mu.Unlock()

	fdt.openFiles[key] = &OpenFileInfo{
		PID:         pid,
		FD:          fd,
		FilePath:    filePath,
		OpenTime:    time.Now(),
		Process:     kprobe.Process,
		OpenEvent:   event,
		PreFileInfo: fdt.captureFileMetadata(filePath),
	}

	fdt.metrics.OpenEventsTracked++
	log.Printf("Tracking fd %d for %s in process %d (flags: 0x%x)", fd, filePath, pid, flags)
}

func (fdt *FileDescriptorTracker) TrackWrite(event *tetragon.GetEventsResponse) {
	kprobe := event.GetProcessKprobe()
	if kprobe == nil || (!strings.HasSuffix(kprobe.FunctionName, "sys_write") && !strings.HasSuffix(kprobe.FunctionName, "sys_writev")) {
		return
	}

	if len(kprobe.Args) < 1 {
		return
	}

	fd := kprobe.Args[0].GetIntArg()
	pid := kprobe.Process.Pid.Value
	key := fmt.Sprintf("%d:%d", pid, fd)

	fdt.mu.Lock()
	defer fdt.mu.Unlock()

	if openInfo, exists := fdt.openFiles[key]; exists {
		openInfo.WriteDetected = true
		log.Printf("Write detected to tracked fd %d for %s", fd, openInfo.FilePath)
	}
}

func (fdt *FileDescriptorTracker) HandleClose(event *tetragon.GetEventsResponse, config *Config) *EnrichedEvent {
	kprobe := event.GetProcessKprobe()
	if kprobe == nil || !strings.HasSuffix(kprobe.FunctionName, "sys_close") {
		return nil
	}

	// Get the file descriptor being closed
	if len(kprobe.Args) < 1 {
		return nil
	}

	fd := kprobe.Args[0].GetIntArg()
	pid := kprobe.Process.Pid.Value
	key := fmt.Sprintf("%d:%d", pid, fd)

	fdt.mu.Lock()
	openInfo, exists := fdt.openFiles[key]
	if exists {
		delete(fdt.openFiles, key)
	}
	fdt.mu.Unlock()

	if !exists {
		// This close doesn't correspond to a tracked file
		return nil
	}

	fdt.metrics.CloseEventsMatched++
	log.Printf("File descriptor %d closed for %s in process %d", fd, openInfo.FilePath, pid)

	// Calculate the file hash with pre/post comparison
	hashInfo, err := fdt.calculateFileHash(openInfo.FilePath, openInfo.PreFileInfo)
	if err != nil {
		fdt.metrics.HashErrors++
		log.Printf("Error calculating hash for %s: %v", openInfo.FilePath, err)
		return nil
	}

	fdt.metrics.HashCalculations++

	// Create enriched event with hash
	enriched := &EnrichedEvent{
		Event:    event,
		FileHash: hashInfo,
	}

	// Include metrics if configured
	if config.Output.IncludeMetrics {
		enriched.Metrics = fdt.GetMetrics()
	}

	return enriched
}

func (fdt *FileDescriptorTracker) calculateFileHash(filePath string, preFileInfo *FileMetadata) (*FileHashInfo, error) {
	// Get current file stats
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file %s: %w", filePath, err)
	}

	// Read file content for hash
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	// Calculate hash
	hasher := sha256.New()
	hasher.Write(data)
	hash := hex.EncodeToString(hasher.Sum(nil))

	// Check if file changed based on metadata comparison
	changed := false
	if preFileInfo != nil {
		changed = preFileInfo.Size != fileInfo.Size() ||
			preFileInfo.ModTime != fileInfo.ModTime() ||
			preFileInfo.Permissions != fileInfo.Mode().String()
	}

	return &FileHashInfo{
		Algorithm:        "sha256",
		Value:            hash,
		FilePath:         filePath,
		Timestamp:        time.Now(),
		FileSize:         fileInfo.Size(),
		ModificationTime: fileInfo.ModTime(),
		PreFileInfo:      preFileInfo,
		Changed:          changed,
	}, nil
}

func (fdt *FileDescriptorTracker) Cleanup() {
	fdt.mu.Lock()
	defer fdt.mu.Unlock()

	now := time.Now()
	cleaned := 0
	for key, info := range fdt.openFiles {
		if now.Sub(info.OpenTime) > fdt.timeout {
			log.Printf("Cleaning up stale fd tracking for %s (age: %v)", key, now.Sub(info.OpenTime))
			delete(fdt.openFiles, key)
			cleaned++
		}
	}

	if cleaned > 0 {
		fdt.metrics.StaleFDsCleanedUp += int64(cleaned)
		log.Printf("Cleaned up %d stale file descriptor entries", cleaned)
	}
}

func (fdt *FileDescriptorTracker) GetMetrics() *TrackerMetrics {
	fdt.mu.RLock()
	defer fdt.mu.RUnlock()

	// Return a copy
	return &TrackerMetrics{
		OpenEventsTracked:  fdt.metrics.OpenEventsTracked,
		CloseEventsMatched: fdt.metrics.CloseEventsMatched,
		HashCalculations:   fdt.metrics.HashCalculations,
		HashErrors:         fdt.metrics.HashErrors,
		StaleFDsCleanedUp:  fdt.metrics.StaleFDsCleanedUp,
	}
}

func (fdt *FileDescriptorTracker) PrintStats() {
	metrics := fdt.GetMetrics()
	log.Printf("Stats - Opens: %d, Closes: %d, Hashes: %d, Errors: %d, Cleanups: %d",
		metrics.OpenEventsTracked,
		metrics.CloseEventsMatched,
		metrics.HashCalculations,
		metrics.HashErrors,
		metrics.StaleFDsCleanedUp)
}

func loadConfig(configPath string) (*Config, error) {
	// Default configuration
	config := &Config{
		TargetFiles: []string{
			"/etc/passwd",
			"/etc/shadow",
			"/etc/group",
			"/etc/sudoers",
		},
		Tetragon: TetragonConfig{
			ServerAddress: "localhost:54321",
		},
		Output: OutputConfig{
			Format:         "json",
			Indent:         true,
			IncludeMetrics: false,
		},
		Tracker: TrackerConfig{
			CleanupTimeout: "5m",
			StatsInterval:  "1m",
		},
	}

	// Load from file if provided
	if configPath != "" {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file %s: %w", configPath, err)
		}

		if err := yaml.Unmarshal(data, config); err != nil {
			return nil, fmt.Errorf("failed to parse config file %s: %w", configPath, err)
		}
	}

	// Allow environment variable override for server address
	if serverAddr := os.Getenv("TETRAGON_SERVER"); serverAddr != "" {
		config.Tetragon.ServerAddress = serverAddr
	}

	return config, nil
}

func main() {
	// Parse command line flags
	var configPath string
	flag.StringVar(&configPath, "config", "", "Path to configuration file (optional)")
	flag.Parse()

	// Configure logging
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Load configuration
	config, err := loadConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	log.Printf("Loaded configuration with %d target files", len(config.TargetFiles))
	for _, file := range config.TargetFiles {
		log.Printf("  - %s", file)
	}

	// Configure output destination
	var output *os.File = os.Stdout
	outputFile := os.Getenv("ENRICHER_OUTPUT_FILE")

	// If no explicit output file, but TETRAGON_EXPORT_DIR is set, create enriched file in same dir
	if outputFile == "" {
		if exportDir := os.Getenv("TETRAGON_EXPORT_DIR"); exportDir != "" {
			outputFile = filepath.Join(exportDir, "tetragon-enriched.json")
		}
	}

	if outputFile != "" {
		// Ensure directory exists
		if dir := filepath.Dir(outputFile); dir != "." {
			if err := os.MkdirAll(dir, 0755); err != nil {
				log.Fatalf("Failed to create output directory %s: %v", dir, err)
			}
		}

		var err error
		output, err = os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("Failed to open output file %s: %v", outputFile, err)
		}
		defer output.Close()
		log.Printf("Outputting enriched events to: %s", outputFile)
	}

	conn, err := grpc.Dial(config.Tetragon.ServerAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Failed to connect to Tetragon at %s: %v", config.Tetragon.ServerAddress, err)
	}
	defer conn.Close()

	client := tetragon.NewFineGuidanceSensorsClient(conn)
	tracker := NewFileDescriptorTracker(config)

	// Parse stats interval from config
	statsInterval := 1 * time.Minute // default
	if config.Tracker.StatsInterval != "" {
		if parsed, err := time.ParseDuration(config.Tracker.StatsInterval); err == nil {
			statsInterval = parsed
		}
	}

	// Set up cleanup and stats routine
	go func() {
		ticker := time.NewTicker(statsInterval)
		defer ticker.Stop()
		for range ticker.C {
			tracker.Cleanup()
			tracker.PrintStats()
		}
	}()

	// Set up event stream with filters
	ctx := context.Background()

	filter := &tetragon.Filter{
		EventSet: []tetragon.EventType{
			tetragon.EventType_PROCESS_KPROBE,
		},
	}

	stream, err := client.GetEvents(ctx, &tetragon.GetEventsRequest{
		AllowList: []*tetragon.Filter{filter},
	})
	if err != nil {
		log.Fatalf("Failed to get events stream: %v", err)
	}

	log.Printf("Starting file modification event processing (server: %s)...", config.Tetragon.ServerAddress)

	encoder := json.NewEncoder(output)
	if config.Output.Indent {
		encoder.SetIndent("", "  ")
	}

	for {
		event, err := stream.Recv()
		if err != nil {
			log.Fatalf("Failed to receive event: %v", err)
		}

		kprobe := event.GetProcessKprobe()
		if kprobe == nil {
			continue
		}

		// Handle syscalls with potential architecture prefixes (e.g., __arm64_sys_openat, __x64_sys_openat)
		if strings.HasSuffix(kprobe.FunctionName, "sys_openat") {
			tracker.TrackOpen(event)
			// Don't output sys_openat events
		} else if strings.HasSuffix(kprobe.FunctionName, "sys_write") || strings.HasSuffix(kprobe.FunctionName, "sys_writev") {
			tracker.TrackWrite(event)
			// Don't output sys_write events
		} else if strings.HasSuffix(kprobe.FunctionName, "sys_close") {
			enriched := tracker.HandleClose(event, config)
			// Only output if the event was actually enriched (HandleClose returns non-nil)
			if enriched != nil {
				encoder.Encode(enriched)
			}
		}
		// Don't output other events
	}
}
