package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

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

// cliOptions holds command-line flag values
type cliOptions struct {
	configFile            string
	managementAPIURL      string
	tetragonAddress       string
	environment           string
	tags                  arrayFlags
	logLevel              string
	logFormat             string
	logOutputDirectory    string
	insecureSkipTLSVerify bool
	showVersion           bool
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("Fatal error: %v", err)
	}
}

// run is the main application logic, separated for testability
func run() error {
	opts := parseFlags()

	if opts.showVersion {
		fmt.Printf("control-plane-client version %s\n", version)
		return nil
	}

	cfg, err := loadConfigWithOverrides(opts)
	if err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}

	ctx := setupSignalHandler()

	return runClient(ctx, cfg)
}

// parseFlags parses command-line flags and returns options
func parseFlags() *cliOptions {
	opts := &cliOptions{}

	flag.StringVar(&opts.configFile, "config", "", "Path to configuration file")
	flag.StringVar(&opts.managementAPIURL, "management-api-url", "", "Management API base URL (overrides config)")
	flag.StringVar(&opts.tetragonAddress, "tetragon-address", "", "Tetragon gRPC server address (overrides config)")
	flag.StringVar(&opts.environment, "environment", "", "Environment name (overrides config)")
	flag.Var(&opts.tags, "tag", "Additional tags (can be specified multiple times, overrides config)")
	flag.StringVar(&opts.logLevel, "log-level", "", "Log level: debug, info, warn, error (overrides config)")
	flag.StringVar(&opts.logFormat, "log-format", "", "Log format: text, json (overrides config)")
	flag.StringVar(&opts.logOutputDirectory, "log-output-directory", "", "Directory for log files, empty for stdout (overrides config)")
	flag.BoolVar(&opts.insecureSkipTLSVerify, "insecure-skip-tls-verify", false, "Skip TLS certificate verification (INSECURE, for testing only)")
	flag.BoolVar(&opts.showVersion, "version", false, "Show version information")

	flag.Parse()

	return opts
}

// setupSignalHandler creates a context that cancels on SIGINT/SIGTERM
func setupSignalHandler() context.Context {
	ctx, cancel := context.WithCancel(context.Background())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		log.Printf("Received signal %v, initiating shutdown...", sig)
		cancel()
	}()

	return ctx
}

// runClient creates and starts the control plane client
func runClient(ctx context.Context, cfg *config.Config) error {
	cpClient, err := client.NewControlPlaneClient(cfg)
	if err != nil {
		return fmt.Errorf("failed to create control plane client: %w", err)
	}

	if err := cpClient.Start(ctx); err != nil {
		return fmt.Errorf("control plane client error: %w", err)
	}

	return nil
}

// loadConfigWithOverrides loads configuration and applies command-line overrides
func loadConfigWithOverrides(opts *cliOptions) (*config.Config, error) {
	var cfg *config.Config
	var err error

	if opts.configFile != "" {
		cfg, err = config.LoadConfig(opts.configFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load config file: %w", err)
		}
	} else {
		cfg = &config.Config{}
		cfg.SetDefaults()
	}

	// Apply command-line overrides
	if opts.managementAPIURL != "" {
		cfg.ManagementAPI.BaseURL = opts.managementAPIURL
	}

	if opts.tetragonAddress != "" {
		cfg.Tetragon.ServerAddress = opts.tetragonAddress
	}

	if opts.environment != "" {
		cfg.Registration.Environment = opts.environment
	}

	if len(opts.tags) > 0 {
		cfg.Registration.Tags = opts.tags
	}

	// Apply logging overrides (only if explicitly set)
	if opts.logLevel != "" {
		cfg.Logging.Level = opts.logLevel
	}

	if opts.logFormat != "" {
		cfg.Logging.Format = opts.logFormat
	}

	if opts.logOutputDirectory != "" {
		cfg.Logging.OutputDirectory = opts.logOutputDirectory
	}

	// Apply TLS override if flag is set
	if opts.insecureSkipTLSVerify {
		cfg.ManagementAPI.HTTPClient.InsecureSkipTLSVerify = true
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return cfg, nil
}
