package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ManagementAPI   ManagementAPIConfig     `yaml:"management_api"`
	Tetragon        TetragonConfig          `yaml:"tetragon"`
	Registration    RegistrationConfig      `yaml:"registration"`
	PolicySync      PolicySyncConfig        `yaml:"policy_sync"`
	HealthReporting HealthReportingConfig   `yaml:"health_reporting"`
	Metrics         MetricsPublishingConfig `yaml:"metrics_publishing"`
	Logging         LoggingConfig           `yaml:"logging"`
}

type ManagementAPIConfig struct {
	BaseURL    string           `yaml:"base_url"`
	AuthToken  string           `yaml:"auth_token"` // Can also be set via TETRAGON_CONTROL_PLANE_AUTH_TOKEN env var
	Timeout    time.Duration    `yaml:"timeout"`
	Retry      RetryConfig      `yaml:"retry"`
	HTTPClient HTTPClientConfig `yaml:"http_client"`
}

type HTTPClientConfig struct {
	MaxIdleConns          int           `yaml:"max_idle_conns"`
	MaxIdleConnsPerHost   int           `yaml:"max_idle_conns_per_host"`
	IdleConnTimeout       time.Duration `yaml:"idle_conn_timeout"`
	TLSHandshakeTimeout   time.Duration `yaml:"tls_handshake_timeout"`
	InsecureSkipTLSVerify bool          `yaml:"insecure_skip_tls_verify"` // Skip TLS certificate verification (insecure, for testing only)
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
	Environment    string        `yaml:"environment"`
	DeploymentType string        `yaml:"deployment_type"` // "standalone" or "kubernetes"
	Tags           []string      `yaml:"tags"`
	UseIMDS        bool          `yaml:"use_imds"`
	IMDSTimeout    time.Duration `yaml:"imds_timeout"`
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

type MetricsPublishingConfig struct {
	Enabled               bool          `yaml:"enabled"`
	Interval              time.Duration `yaml:"interval"`
	Endpoint              string        `yaml:"endpoint"`
	RequestTimeout        time.Duration `yaml:"request_timeout"`
	Format                string        `yaml:"format"`
	InsecureSkipTLSVerify bool          `yaml:"insecure_skip_tls_verify"`
}

type LoggingConfig struct {
	Level           string `yaml:"level"`
	Format          string `yaml:"format"`
	OutputDirectory string `yaml:"output_directory"` // Directory for log files (empty = stdout)
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
	if c.ManagementAPI.HTTPClient.MaxIdleConns == 0 {
		c.ManagementAPI.HTTPClient.MaxIdleConns = 100
	}
	if c.ManagementAPI.HTTPClient.MaxIdleConnsPerHost == 0 {
		c.ManagementAPI.HTTPClient.MaxIdleConnsPerHost = 10
	}
	if c.ManagementAPI.HTTPClient.IdleConnTimeout == 0 {
		c.ManagementAPI.HTTPClient.IdleConnTimeout = 90 * time.Second
	}
	if c.ManagementAPI.HTTPClient.TLSHandshakeTimeout == 0 {
		c.ManagementAPI.HTTPClient.TLSHandshakeTimeout = 10 * time.Second
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
	if c.Registration.DeploymentType == "" {
		c.Registration.DeploymentType = "standalone"
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

	if c.Metrics.Interval == 0 {
		c.Metrics.Interval = 60 * time.Second
	}
	if c.Metrics.Endpoint == "" {
		c.Metrics.Endpoint = "http://localhost:2112/metrics"
	}
	if c.Metrics.RequestTimeout == 0 {
		c.Metrics.RequestTimeout = 10 * time.Second
	}
	if c.Metrics.Format == "" {
		c.Metrics.Format = "prometheus"
	}

	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Logging.Format == "" {
		c.Logging.Format = "json"
	}
	if c.Logging.OutputDirectory == "" {
		c.Logging.OutputDirectory = "/var/log/tetragon"
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

	if c.Metrics.Enabled {
		if c.Metrics.Endpoint == "" {
			return fmt.Errorf("metrics_publishing.endpoint is required when enabled")
		}
		if c.Metrics.Interval <= 0 {
			return fmt.Errorf("metrics_publishing.interval must be > 0 when enabled")
		}
		if c.Metrics.RequestTimeout <= 0 {
			return fmt.Errorf("metrics_publishing.request_timeout must be > 0 when enabled")
		}
		if c.Metrics.Format == "" {
			return fmt.Errorf("metrics_publishing.format is required when enabled")
		}
	}

	return nil
}
