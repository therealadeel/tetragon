package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/tetragon/contrib/control-plane-client/client"
	"github.com/cilium/tetragon/contrib/control-plane-client/config"
)

var (
	version = "dev"
)

type arrayFlags []string

func (a *arrayFlags) String() string {
	return strings.Join(*a, ",")
}

func (a *arrayFlags) Set(value string) error {
	*a = append(*a, value)
	return nil
}

func main() {
	var (
		configFile       = flag.String("config", "", "Path to configuration file")
		managementAPIURL = flag.String("management-api-url", "", "Management API base URL (overrides config)")
		tetragonAddress  = flag.String("tetragon-address", "", "Tetragon gRPC server address (overrides config)")
		environment      = flag.String("environment", "", "Environment name (overrides config)")
		tags             arrayFlags
		logLevel         = flag.String("log-level", "info", "Log level (debug, info, warn, error)")
		logFormat        = flag.String("log-format", "text", "Log format (text, json)")
		showVersion      = flag.Bool("version", false, "Show version information")
	)

	flag.Var(&tags, "tag", "Additional tags (can be specified multiple times, overrides config)")
	flag.Parse()

	if *showVersion {
		fmt.Printf("control-plane-client version %s\n", version)
		os.Exit(0)
	}

	cfg, err := loadConfig(*configFile, *managementAPIURL, *tetragonAddress, *environment, tags)
	if err != nil {
		log.Fatalf("Configuration error: %v", err)
	}

	// Apply command-line overrides for logging
	if *logLevel != "info" { // "info" is the default flag value
		cfg.Logging.Level = *logLevel
	}
	if *logFormat != "text" { // "text" is the default flag value
		cfg.Logging.Format = *logFormat
	}

	// Setup logging from config
	setupLogging(cfg.Logging.Level, cfg.Logging.Format)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		log.Printf("Received signal %v, initiating shutdown...", sig)
		cancel()
	}()

	cpClient, err := client.NewControlPlaneClient(cfg)
	if err != nil {
		log.Fatalf("Failed to create control plane client: %v", err)
	}

	if err := cpClient.Start(ctx); err != nil {
		log.Fatalf("Control plane client error: %v", err)
	}
}

func loadConfig(configFile, managementAPIURL, tetragonAddress, environment string, tags []string) (*config.Config, error) {
	var cfg *config.Config
	var err error

	if configFile != "" {
		cfg, err = config.LoadConfig(configFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load config file: %w", err)
		}
	} else {
		cfg = &config.Config{}
		cfg.SetDefaults()
	}

	if managementAPIURL != "" {
		cfg.ManagementAPI.BaseURL = managementAPIURL
	}

	if tetragonAddress != "" {
		cfg.Tetragon.ServerAddress = tetragonAddress
	}

	if environment != "" {
		cfg.Registration.Environment = environment
	}

	if len(tags) > 0 {
		cfg.Registration.Tags = tags
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return cfg, nil
}

func setupLogging(level, format string) {
	if format == "json" {
		log.SetFlags(0)
		log.SetOutput(&jsonLogger{})
	} else {
		log.SetFlags(log.LstdFlags)
	}
}

type jsonLogger struct{}

func (j *jsonLogger) Write(p []byte) (n int, err error) {
	logEntry := map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"message":   strings.TrimSpace(string(p)),
	}
	data, err := json.Marshal(logEntry)
	if err != nil {
		return 0, err
	}
	return os.Stderr.Write(append(data, '\n'))
}
