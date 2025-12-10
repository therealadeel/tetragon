package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ManagementAPI   ManagementAPIConfig   `yaml:"management_api"`
	Tetragon        TetragonConfig        `yaml:"tetragon"`
	Registration    RegistrationConfig    `yaml:"registration"`
	PolicySync      PolicySyncConfig      `yaml:"policy_sync"`
	HealthReporting HealthReportingConfig `yaml:"health_reporting"`
	Logging         LoggingConfig         `yaml:"logging"`
}

type ManagementAPIConfig struct {
	BaseURL   string        `yaml:"base_url"`
	AuthToken string        `yaml:"auth_token"` // Can also be set via TETRAGON_CONTROL_PLANE_AUTH_TOKEN env var
	Timeout   time.Duration `yaml:"timeout"`
	Retry     RetryConfig   `yaml:"retry"`
}

type RetryConfig struct {
	MaxAttempts        int           `yaml:"max_attempts"`
	InitialBackoff     time.Duration `yaml:"initial_backoff"`
	MaxBackoff         time.Duration `yaml:"max_backoff"`
	BackoffMultiplier  float64       `yaml:"backoff_multiplier"`
	RetryableHTTPCodes []int         `yaml:"retryable_http_codes"`
}

type TetragonConfig struct {
	ServerAddress string        `yaml:"server_address"`
	Timeout       time.Duration `yaml:"timeout"`
}

type RegistrationConfig struct {
	Environment string        `yaml:"environment"`
	Tags        []string      `yaml:"tags"`
	UseIMDS     bool          `yaml:"use_imds"`
	IMDSTimeout time.Duration `yaml:"imds_timeout"`
}

type PolicySyncConfig struct {
	Enabled         bool          `yaml:"enabled"`
	Interval        time.Duration `yaml:"interval"`
	CleanupExisting bool          `yaml:"cleanup_existing"`
	Incremental     bool          `yaml:"incremental"` // Use incremental updates instead of delete-all
}

type HealthReportingConfig struct {
	Enabled  bool          `yaml:"enabled"`
	Interval time.Duration `yaml:"interval"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	config.SetDefaults()

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &config, nil
}

func (c *Config) SetDefaults() {
	// Load auth token from environment if not set in config
	if c.ManagementAPI.AuthToken == "" {
		c.ManagementAPI.AuthToken = os.Getenv("TETRAGON_CONTROL_PLANE_AUTH_TOKEN")
	}

	if c.ManagementAPI.Timeout == 0 {
		c.ManagementAPI.Timeout = 30 * time.Second
	}
	if c.ManagementAPI.Retry.MaxAttempts == 0 {
		c.ManagementAPI.Retry.MaxAttempts = 5
	}
	if c.ManagementAPI.Retry.InitialBackoff == 0 {
		c.ManagementAPI.Retry.InitialBackoff = 1 * time.Second
	}
	if c.ManagementAPI.Retry.MaxBackoff == 0 {
		c.ManagementAPI.Retry.MaxBackoff = 60 * time.Second
	}
	if c.ManagementAPI.Retry.BackoffMultiplier == 0 {
		c.ManagementAPI.Retry.BackoffMultiplier = 2.0
	}
	if len(c.ManagementAPI.Retry.RetryableHTTPCodes) == 0 {
		c.ManagementAPI.Retry.RetryableHTTPCodes = []int{408, 429, 500, 502, 503, 504}
	}

	if c.Tetragon.ServerAddress == "" {
		c.Tetragon.ServerAddress = "localhost:54321"
	}
	if c.Tetragon.Timeout == 0 {
		c.Tetragon.Timeout = 30 * time.Second
	}

	if c.Registration.Environment == "" {
		c.Registration.Environment = "production"
	}
	if c.Registration.IMDSTimeout == 0 {
		c.Registration.IMDSTimeout = 5 * time.Second
	}

	if c.PolicySync.Interval == 0 {
		c.PolicySync.Interval = 60 * time.Second
	}
	// Incremental updates enabled by default
	if !c.PolicySync.Incremental {
		c.PolicySync.Incremental = true
	}

	if c.HealthReporting.Interval == 0 {
		c.HealthReporting.Interval = 300 * time.Second
	}

	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Logging.Format == "" {
		c.Logging.Format = "json"
	}
}

func (c *Config) Validate() error {
	if c.ManagementAPI.BaseURL == "" {
		return fmt.Errorf("management_api.base_url is required")
	}

	if c.ManagementAPI.AuthToken == "" {
		return fmt.Errorf("management_api.auth_token is required (set via config or TETRAGON_CONTROL_PLANE_AUTH_TOKEN env var)")
	}

	if c.ManagementAPI.Retry.MaxAttempts < 0 {
		return fmt.Errorf("management_api.retry.max_attempts must be >= 0")
	}
	if c.ManagementAPI.Retry.InitialBackoff < 0 {
		return fmt.Errorf("management_api.retry.initial_backoff must be >= 0")
	}
	if c.ManagementAPI.Retry.MaxBackoff < 0 {
		return fmt.Errorf("management_api.retry.max_backoff must be >= 0")
	}
	if c.ManagementAPI.Retry.BackoffMultiplier <= 0 {
		return fmt.Errorf("management_api.retry.backoff_multiplier must be > 0")
	}

	validEnvs := map[string]bool{"dev": true, "stage": true, "live": true, "production": true}
	if !validEnvs[c.Registration.Environment] {
		return fmt.Errorf("registration.environment must be one of: dev, stage, live, production")
	}

	validLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLevels[c.Logging.Level] {
		return fmt.Errorf("logging.level must be one of: debug, info, warn, error")
	}

	validFormats := map[string]bool{"json": true, "text": true}
	if !validFormats[c.Logging.Format] {
		return fmt.Errorf("logging.format must be one of: json, text")
	}

	return nil
}
