package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"gopkg.in/yaml.v2"

	tetragon "github.com/cilium/tetragon/api/v1/tetragon"
)

// Configuration structures
type Config struct {
	Tetragon TetragonConfig `yaml:"tetragon"`
	Output   OutputConfig   `yaml:"output"`
	OCSF     OCSFConfig     `yaml:"ocsf"`
}

type TetragonConfig struct {
	ServerAddress string `yaml:"server_address"`
}

type OutputConfig struct {
	Format string `yaml:"format"`
	Indent bool   `yaml:"indent"`
}

type OCSFConfig struct {
	SchemaVersion string            `yaml:"schema_version"`
	Product       ProductInfo       `yaml:"product"`
	Mappings      EventMappings     `yaml:"mappings"`
	Metadata      map[string]string `yaml:"metadata"`
}

type ProductInfo struct {
	Name    string `yaml:"name"`
	Vendor  string `yaml:"vendor"`
	Version string `yaml:"version"`
	Feature string `yaml:"feature"`
	UID     string `yaml:"uid"`
}

type EventMappings struct {
	ProcessKprobe     string `yaml:"process_kprobe"`
	ProcessTracepoint string `yaml:"process_tracepoint"`
	ProcessUprobe     string `yaml:"process_uprobe"`
	ProcessExec       string `yaml:"process_exec"`
	ProcessExit       string `yaml:"process_exit"`
}

// OCSF Base Event Structure
type OCSFEvent struct {
	CategoryUID  int                    `json:"category_uid"`
	CategoryName string                 `json:"category_name"`
	ClassUID     int                    `json:"class_uid"`
	ClassName    string                 `json:"class_name"`
	ActivityID   int                    `json:"activity_id"`
	ActivityName string                 `json:"activity_name"`
	TypeUID      int                    `json:"type_uid"`
	TypeName     string                 `json:"type_name"`
	SeverityID   int                    `json:"severity_id"`
	Severity     string                 `json:"severity"`
	Message      string                 `json:"message"`
	Time         int64                  `json:"time"`
	Timestamp    string                 `json:"timestamp"`
	Timezone     string                 `json:"timezone_offset"`
	Metadata     *Metadata              `json:"metadata,omitempty"`
	Device       *Device                `json:"device,omitempty"`
	Actor        *Actor                 `json:"actor,omitempty"`
	Process      *Process               `json:"process,omitempty"`
	Parent       *Process               `json:"parent,omitempty"`
	File         *File                  `json:"file,omitempty"`
	Enrichments  map[string]interface{} `json:"enrichments,omitempty"`
	Unmapped     map[string]interface{} `json:"unmapped,omitempty"`
}

// OCSF Objects
type Metadata struct {
	Version      string          `json:"version"`
	Product      *Product        `json:"product,omitempty"`
	Profiles     []string        `json:"profiles,omitempty"`
	Extensions   []string        `json:"extensions,omitempty"`
	OriginalTime string          `json:"original_time,omitempty"`
	EventCode    string          `json:"event_code,omitempty"`
	Correlation  *CorrelationUID `json:"correlation_uid,omitempty"`
}

type Product struct {
	Name    string `json:"name"`
	Vendor  string `json:"vendor_name"`
	Version string `json:"version"`
	Feature string `json:"feature,omitempty"`
	UID     string `json:"uid,omitempty"`
	URL     string `json:"url_string,omitempty"`
}

type CorrelationUID struct {
	ExecID string `json:"exec_id,omitempty"`
}

type Device struct {
	Hostname string `json:"hostname,omitempty"`
	Name     string `json:"name,omitempty"`
	Type     string `json:"type,omitempty"`
	OS       *OS    `json:"os,omitempty"`
}

type OS struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
	Build   string `json:"build,omitempty"`
	Type    string `json:"type,omitempty"`
}

type Actor struct {
	User    *User    `json:"user,omitempty"`
	Session *Session `json:"session,omitempty"`
}

type User struct {
	Name string `json:"name,omitempty"`
	UID  string `json:"uid,omitempty"`
	Type string `json:"type,omitempty"`
}

type Session struct {
	UID string `json:"uid,omitempty"`
	PID int32  `json:"pid,omitempty"`
}

type Process struct {
	Name          string     `json:"name,omitempty"`
	PID           int32      `json:"pid,omitempty"`
	UID           string     `json:"uid,omitempty"`
	CommandLine   string     `json:"cmd_line,omitempty"`
	CreatedTime   string     `json:"created_time,omitempty"`
	File          *File      `json:"file,omitempty"`
	Parent        *Process   `json:"parent,omitempty"`
	Session       *Session   `json:"session,omitempty"`
	User          *User      `json:"user,omitempty"`
	Container     *Container `json:"container,omitempty"`
	Terminated    string     `json:"terminated_time,omitempty"`
	ExitCode      int32      `json:"exit_code,omitempty"`
	Thread        *Thread    `json:"thread,omitempty"`
	LoadedModules []string   `json:"loaded_modules,omitempty"`
}

type File struct {
	Name               string `json:"name,omitempty"`
	Path               string `json:"path,omitempty"`
	Type               string `json:"type,omitempty"`
	TypeID             int    `json:"type_id,omitempty"`
	Size               int64  `json:"size,omitempty"`
	ModifiedTime       string `json:"modified_time,omitempty"`
	AccessedTime       string `json:"accessed_time,omitempty"`
	CreatedTime        string `json:"created_time,omitempty"`
	Permissions        string `json:"attributes,omitempty"`
	Hash               *Hash  `json:"hashes,omitempty"`
	Owner              *User  `json:"owner,omitempty"`
	SecurityDescriptor string `json:"security_descriptor,omitempty"`
}

type Hash struct {
	Algorithm string `json:"algorithm,omitempty"`
	Value     string `json:"value,omitempty"`
}

type Container struct {
	Name    string   `json:"name,omitempty"`
	Runtime string   `json:"runtime,omitempty"`
	Size    int64    `json:"size,omitempty"`
	Tag     string   `json:"tag,omitempty"`
	UID     string   `json:"uid,omitempty"`
	Image   *Image   `json:"image,omitempty"`
	Pod     *Pod     `json:"pod,omitempty"`
	Network *Network `json:"network,omitempty"`
}

type Image struct {
	Name string `json:"name,omitempty"`
	Path string `json:"path,omitempty"`
	Tag  string `json:"tag,omitempty"`
	UID  string `json:"uid,omitempty"`
}

type Pod struct {
	Name      string `json:"name,omitempty"`
	UID       string `json:"uid,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

type Network struct {
	Name string `json:"name,omitempty"`
	UID  string `json:"uid,omitempty"`
}

type Thread struct {
	TID string `json:"tid,omitempty"`
}

// OCSF Event Types and Constants
const (
	CategorySystemActivity      = 1
	CategoryNetworkActivity     = 4
	CategoryApplicationActivity = 6

	ClassProcessActivity = 1007
	ClassFileActivity    = 1001
	ClassKernelActivity  = 1003
	ClassModuleActivity  = 1005
	ClassMemoryActivity  = 1004

	ActivityProcessLaunch    = 1
	ActivityProcessTerminate = 2
	ActivityProcessAccess    = 3

	ActivityFileCreate = 1
	ActivityFileRead   = 2
	ActivityFileWrite  = 3
	ActivityFileDelete = 4
	ActivityFileRename = 5
	ActivityFileAccess = 6

	ActivityKernelSyscall = 1
	ActivityKernelModule  = 2

	SeverityInfo     = 1
	SeverityLow      = 2
	SeverityMedium   = 3
	SeverityHigh     = 4
	SeverityCritical = 5
	SeverityFatal    = 6
)

// Event Mapper handles conversion from Tetragon to OCSF
type EventMapper struct {
	config *Config
}

func NewEventMapper(config *Config) *EventMapper {
	return &EventMapper{config: config}
}

func (em *EventMapper) MapEvent(event *tetragon.GetEventsResponse) *OCSFEvent {
	timeStr := ""
	if event.Time != nil {
		timeStr = event.Time.AsTime().Format(time.RFC3339)
	}
	ocsf := &OCSFEvent{
		Time:       time.Now().Unix(),
		Timestamp:  timeStr,
		Timezone:   "+00:00",
		SeverityID: SeverityInfo,
		Severity:   "Informational",
		Metadata: &Metadata{
			Version: em.config.OCSF.SchemaVersion,
			Product: &Product{
				Name:    em.config.OCSF.Product.Name,
				Vendor:  em.config.OCSF.Product.Vendor,
				Version: em.config.OCSF.Product.Version,
				Feature: em.config.OCSF.Product.Feature,
				UID:     em.config.OCSF.Product.UID,
			},
			Profiles:     []string{"host"},
			Extensions:   []string{"linux"},
			OriginalTime: timeStr,
		},
		Device: &Device{
			Hostname: event.NodeName,
			Name:     event.NodeName,
			Type:     "Computer",
			OS: &OS{
				Name: "Linux",
				Type: "Linux",
			},
		},
		Enrichments: make(map[string]interface{}),
		Unmapped:    make(map[string]interface{}),
	}

	switch {
	case event.GetProcessExec() != nil:
		return em.mapProcessExec(ocsf, event)
	case event.GetProcessExit() != nil:
		return em.mapProcessExit(ocsf, event)
	case event.GetProcessKprobe() != nil:
		return em.mapProcessKprobe(ocsf, event)
	case event.GetProcessTracepoint() != nil:
		return em.mapProcessTracepoint(ocsf, event)
	case event.GetProcessUprobe() != nil:
		return em.mapProcessUprobe(ocsf, event)
	default:
		ocsf.CategoryUID = CategorySystemActivity
		ocsf.CategoryName = "System Activity"
		ocsf.ClassUID = ClassKernelActivity
		ocsf.ClassName = "Kernel Activity"
		ocsf.ActivityID = ActivityKernelSyscall
		ocsf.ActivityName = "System Call"
		ocsf.TypeUID = ClassKernelActivity*100 + ActivityKernelSyscall
		ocsf.TypeName = "Kernel Activity: System Call"
		ocsf.Message = "Unknown Tetragon event type"
		ocsf.Unmapped["original_event"] = event
	}

	return ocsf
}

func (em *EventMapper) mapProcessExec(ocsf *OCSFEvent, event *tetragon.GetEventsResponse) *OCSFEvent {
	exec := event.GetProcessExec()

	ocsf.CategoryUID = CategorySystemActivity
	ocsf.CategoryName = "System Activity"
	ocsf.ClassUID = ClassProcessActivity
	ocsf.ClassName = "Process Activity"
	ocsf.ActivityID = ActivityProcessLaunch
	ocsf.ActivityName = "Launch"
	ocsf.TypeUID = ClassProcessActivity*100 + ActivityProcessLaunch
	ocsf.TypeName = "Process Activity: Launch"
	ocsf.Message = fmt.Sprintf("Process started: %s", exec.Process.Binary)

	ocsf.Process = em.mapProcess(exec.Process)
	if exec.Parent != nil {
		ocsf.Parent = em.mapProcess(exec.Parent)
	}

	if exec.Process.ExecId != "" {
		ocsf.Metadata.Correlation = &CorrelationUID{ExecID: exec.Process.ExecId}
	}

	return ocsf
}

func (em *EventMapper) mapProcessExit(ocsf *OCSFEvent, event *tetragon.GetEventsResponse) *OCSFEvent {
	exit := event.GetProcessExit()

	ocsf.CategoryUID = CategorySystemActivity
	ocsf.CategoryName = "System Activity"
	ocsf.ClassUID = ClassProcessActivity
	ocsf.ClassName = "Process Activity"
	ocsf.ActivityID = ActivityProcessTerminate
	ocsf.ActivityName = "Terminate"
	ocsf.TypeUID = ClassProcessActivity*100 + ActivityProcessTerminate
	ocsf.TypeName = "Process Activity: Terminate"
	ocsf.Message = fmt.Sprintf("Process terminated: %s (exit code: %d)", exit.Process.Binary, exit.Status)

	ocsf.Process = em.mapProcess(exit.Process)
	if exit.Parent != nil {
		ocsf.Parent = em.mapProcess(exit.Parent)
	}

	ocsf.Process.ExitCode = int32(exit.Status)

	if exit.Process.ExecId != "" {
		ocsf.Metadata.Correlation = &CorrelationUID{ExecID: exit.Process.ExecId}
	}

	return ocsf
}

func (em *EventMapper) mapProcessKprobe(ocsf *OCSFEvent, event *tetragon.GetEventsResponse) *OCSFEvent {
	kprobe := event.GetProcessKprobe()

	if em.isFileSystemCall(kprobe.FunctionName) {
		return em.mapFileSystemCall(ocsf, event, kprobe)
	}

	ocsf.CategoryUID = CategorySystemActivity
	ocsf.CategoryName = "System Activity"
	ocsf.ClassUID = ClassKernelActivity
	ocsf.ClassName = "Kernel Activity"
	ocsf.ActivityID = ActivityKernelSyscall
	ocsf.ActivityName = "System Call"
	ocsf.TypeUID = ClassKernelActivity*100 + ActivityKernelSyscall
	ocsf.TypeName = "Kernel Activity: System Call"
	ocsf.Message = fmt.Sprintf("System call: %s", kprobe.FunctionName)

	ocsf.Process = em.mapProcess(kprobe.Process)
	if kprobe.Parent != nil {
		ocsf.Parent = em.mapProcess(kprobe.Parent)
	}

	ocsf.Enrichments["syscall"] = map[string]interface{}{
		"function_name": kprobe.FunctionName,
		"policy_name":   kprobe.PolicyName,
		"action":        kprobe.Action.String(),
		"return_action": kprobe.ReturnAction.String(),
	}

	if kprobe.Process.ExecId != "" {
		ocsf.Metadata.Correlation = &CorrelationUID{ExecID: kprobe.Process.ExecId}
	}

	return ocsf
}

func (em *EventMapper) mapFileSystemCall(ocsf *OCSFEvent, event *tetragon.GetEventsResponse, kprobe *tetragon.ProcessKprobe) *OCSFEvent {
	ocsf.CategoryUID = CategorySystemActivity
	ocsf.CategoryName = "System Activity"
	ocsf.ClassUID = ClassFileActivity
	ocsf.ClassName = "File System Activity"

	functionName := strings.ToLower(kprobe.FunctionName)
	if strings.Contains(functionName, "open") || strings.Contains(functionName, "create") {
		ocsf.ActivityID = ActivityFileCreate
		ocsf.ActivityName = "Create"
		ocsf.Message = "File opened/created"
	} else if strings.Contains(functionName, "read") {
		ocsf.ActivityID = ActivityFileRead
		ocsf.ActivityName = "Read"
		ocsf.Message = "File read"
	} else if strings.Contains(functionName, "write") {
		ocsf.ActivityID = ActivityFileWrite
		ocsf.ActivityName = "Write"
		ocsf.Message = "File write"
	} else if strings.Contains(functionName, "close") {
		ocsf.ActivityID = ActivityFileAccess
		ocsf.ActivityName = "Access"
		ocsf.Message = "File closed"
	} else {
		ocsf.ActivityID = ActivityFileAccess
		ocsf.ActivityName = "Access"
		ocsf.Message = "File access"
	}

	ocsf.TypeUID = ClassFileActivity*100 + ocsf.ActivityID
	ocsf.TypeName = fmt.Sprintf("File System Activity: %s", ocsf.ActivityName)

	ocsf.Process = em.mapProcess(kprobe.Process)
	if kprobe.Parent != nil {
		ocsf.Parent = em.mapProcess(kprobe.Parent)
	}

	if len(kprobe.Args) > 1 && kprobe.Args[1].GetStringArg() != "" {
		filePath := kprobe.Args[1].GetStringArg()
		ocsf.File = &File{
			Path: filePath,
			Name: filepath.Base(filePath),
		}
		ocsf.Message = fmt.Sprintf("%s: %s", ocsf.Message, filePath)
	}

	ocsf.Enrichments["syscall"] = map[string]interface{}{
		"function_name": kprobe.FunctionName,
		"policy_name":   kprobe.PolicyName,
		"action":        kprobe.Action.String(),
		"return_action": kprobe.ReturnAction.String(),
	}

	if kprobe.Process.ExecId != "" {
		ocsf.Metadata.Correlation = &CorrelationUID{ExecID: kprobe.Process.ExecId}
	}

	return ocsf
}

func (em *EventMapper) mapProcessTracepoint(ocsf *OCSFEvent, event *tetragon.GetEventsResponse) *OCSFEvent {
	tracepoint := event.GetProcessTracepoint()

	ocsf.CategoryUID = CategorySystemActivity
	ocsf.CategoryName = "System Activity"
	ocsf.ClassUID = ClassKernelActivity
	ocsf.ClassName = "Kernel Activity"
	ocsf.ActivityID = ActivityKernelSyscall
	ocsf.ActivityName = "System Call"
	ocsf.TypeUID = ClassKernelActivity*100 + ActivityKernelSyscall
	ocsf.TypeName = "Kernel Activity: System Call"
	ocsf.Message = fmt.Sprintf("Tracepoint: %s:%s", tracepoint.Subsys, tracepoint.Event)

	ocsf.Process = em.mapProcess(tracepoint.Process)
	if tracepoint.Parent != nil {
		ocsf.Parent = em.mapProcess(tracepoint.Parent)
	}

	ocsf.Enrichments["tracepoint"] = map[string]interface{}{
		"subsys":      tracepoint.Subsys,
		"event":       tracepoint.Event,
		"policy_name": tracepoint.PolicyName,
		"action":      tracepoint.Action.String(),
	}

	if tracepoint.Process.ExecId != "" {
		ocsf.Metadata.Correlation = &CorrelationUID{ExecID: tracepoint.Process.ExecId}
	}

	return ocsf
}

func (em *EventMapper) mapProcessUprobe(ocsf *OCSFEvent, event *tetragon.GetEventsResponse) *OCSFEvent {
	uprobe := event.GetProcessUprobe()

	ocsf.CategoryUID = CategoryApplicationActivity
	ocsf.CategoryName = "Application Activity"
	ocsf.ClassUID = ClassProcessActivity
	ocsf.ClassName = "Process Activity"
	ocsf.ActivityID = ActivityProcessAccess
	ocsf.ActivityName = "Access"
	ocsf.TypeUID = ClassProcessActivity*100 + ActivityProcessAccess
	ocsf.TypeName = "Process Activity: Access"
	ocsf.Message = fmt.Sprintf("Uprobe: %s:%s", uprobe.Path, uprobe.Symbol)

	ocsf.Process = em.mapProcess(uprobe.Process)
	if uprobe.Parent != nil {
		ocsf.Parent = em.mapProcess(uprobe.Parent)
	}

	ocsf.Enrichments["uprobe"] = map[string]interface{}{
		"path":        uprobe.Path,
		"symbol":      uprobe.Symbol,
		"policy_name": uprobe.PolicyName,
		"action":      uprobe.Action.String(),
	}

	if uprobe.Process.ExecId != "" {
		ocsf.Metadata.Correlation = &CorrelationUID{ExecID: uprobe.Process.ExecId}
	}

	return ocsf
}

func (em *EventMapper) mapProcess(proc *tetragon.Process) *Process {
	if proc == nil {
		return nil
	}

	startTime := ""
	if proc.StartTime != nil {
		startTime = proc.StartTime.AsTime().Format(time.RFC3339)
	}
	process := &Process{
		PID:         int32(proc.Pid.Value),
		UID:         fmt.Sprintf("%d", proc.Uid.Value),
		CommandLine: proc.Arguments,
		CreatedTime: startTime,
		Session: &Session{
			PID: int32(proc.Pid.Value),
		},
		User: &User{
			UID: fmt.Sprintf("%d", proc.Uid.Value),
		},
	}

	if proc.Binary != "" {
		process.File = &File{
			Path: proc.Binary,
			Name: filepath.Base(proc.Binary),
		}
		process.Name = filepath.Base(proc.Binary)
	}

	if proc.Tid.Value != 0 && proc.Tid.Value != proc.Pid.Value {
		process.Thread = &Thread{
			TID: fmt.Sprintf("%d", proc.Tid.Value),
		}
	}

	return process
}

func (em *EventMapper) isFileSystemCall(functionName string) bool {
	fileSystemCalls := []string{
		"openat", "open", "creat", "close",
		"read", "write", "pread", "pwrite", "readv", "writev",
		"lseek", "stat", "fstat", "lstat",
		"access", "faccessat", "chmod", "fchmod", "chown", "fchown",
		"link", "unlink", "rename", "symlink", "readlink",
		"mkdir", "rmdir", "getcwd", "chdir", "fchdir",
		"dup", "dup2", "pipe", "mkfifo",
		"truncate", "ftruncate", "sync", "fsync", "fdatasync",
		"fcntl", "ioctl", "select", "poll", "epoll",
	}

	functionLower := strings.ToLower(functionName)
	for _, syscall := range fileSystemCalls {
		if strings.Contains(functionLower, syscall) {
			return true
		}
	}
	return false
}

func loadConfig(configPath string) (*Config, error) {
	config := &Config{
		Tetragon: TetragonConfig{
			ServerAddress: "localhost:54321",
		},
		Output: OutputConfig{
			Format: "json",
			Indent: true,
		},
		OCSF: OCSFConfig{
			SchemaVersion: "1.7.0",
			Product: ProductInfo{
				Name:    "Tetragon",
				Vendor:  "Cilium",
				Version: "1.0.0",
				Feature: "Runtime Security",
				UID:     "tetragon-001",
			},
			Metadata: map[string]string{
				"environment": "production",
				"datacenter":  "unknown",
			},
		},
	}

	if configPath != "" {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file %s: %w", configPath, err)
		}

		if err := yaml.Unmarshal(data, config); err != nil {
			return nil, fmt.Errorf("failed to parse config file %s: %w", configPath, err)
		}
	}

	if serverAddr := os.Getenv("TETRAGON_SERVER"); serverAddr != "" {
		config.Tetragon.ServerAddress = serverAddr
	}

	return config, nil
}

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "", "Path to configuration file (optional)")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	config, err := loadConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	log.Printf("Starting Tetragon to OCSF converter (OCSF version: %s)", config.OCSF.SchemaVersion)

	var output *os.File = os.Stdout
	outputFile := os.Getenv("OCSF_OUTPUT_FILE")

	if outputFile == "" {
		if exportDir := os.Getenv("TETRAGON_EXPORT_DIR"); exportDir != "" {
			outputFile = filepath.Join(exportDir, "tetragon-ocsf.json")
		}
	}

	if outputFile != "" {
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
		log.Printf("Outputting OCSF events to: %s", outputFile)
	}

	conn, err := grpc.Dial(config.Tetragon.ServerAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Failed to connect to Tetragon at %s: %v", config.Tetragon.ServerAddress, err)
	}
	defer conn.Close()

	client := tetragon.NewFineGuidanceSensorsClient(conn)
	mapper := NewEventMapper(config)

	ctx := context.Background()
	stream, err := client.GetEvents(ctx, &tetragon.GetEventsRequest{})
	if err != nil {
		log.Fatalf("Failed to get events stream: %v", err)
	}

	log.Printf("Converting Tetragon events to OCSF format (server: %s)...", config.Tetragon.ServerAddress)

	encoder := json.NewEncoder(output)
	if config.Output.Indent {
		encoder.SetIndent("", "  ")
	}

	eventCount := 0
	for {
		event, err := stream.Recv()
		if err != nil {
			log.Fatalf("Failed to receive event: %v", err)
		}

		ocsfEvent := mapper.MapEvent(event)

		if err := encoder.Encode(ocsfEvent); err != nil {
			log.Printf("Failed to encode OCSF event: %v", err)
			continue
		}

		eventCount++
		if eventCount%1000 == 0 {
			log.Printf("Converted %d events to OCSF format", eventCount)
		}
	}
}
