package client

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/tetragon/contrib/control-plane-client/apiclient"
	"github.com/cilium/tetragon/contrib/control-plane-client/cache"
	"github.com/cilium/tetragon/contrib/control-plane-client/config"
	cperrors "github.com/cilium/tetragon/contrib/control-plane-client/errors"
	"github.com/cilium/tetragon/contrib/control-plane-client/logger"
	"github.com/cilium/tetragon/contrib/control-plane-client/metadata"
	"github.com/cilium/tetragon/contrib/control-plane-client/tetragon"
)

// ControlPlaneClient orchestrates the various managers
type ControlPlaneClient struct {
	cfg                 *config.Config
	cache               *cache.Cache
	apiClient           apiclient.ClientInterface
	tetragonClient      tetragon.ClientInterface
	registrationManager *RegistrationManager
	policySyncManager   *PolicySyncManager
	healthReporter      *HealthReporter
	metricsPublisher    *MetricsPublisher
	clientID            string
	stopCh              chan struct{}
	reloadCh            chan os.Signal
	logger              logger.Logger
}

// NewControlPlaneClient creates a new control plane client
func NewControlPlaneClient(cfg *config.Config) (*ControlPlaneClient, error) {
	if err := cfg.Validate(); err != nil {
		return nil, cperrors.NewConfigError("invalid configuration", err)
	}

	// Create logger with file output support
	log, logErr := logger.NewFileLogger(cfg.Logging.Level, cfg.Logging.Format, cfg.Logging.OutputDirectory)
	if logErr != nil {
		return nil, cperrors.NewConfigError("failed to create logger", logErr)
	}

	c := &ControlPlaneClient{
		cfg:      cfg,
		stopCh:   make(chan struct{}),
		reloadCh: make(chan os.Signal, 1),
		logger:   log,
	}

	// Setup signal handler for configuration reload (SIGHUP)
	signal.Notify(c.reloadCh, syscall.SIGHUP)

	c.cache = cache.NewCache()
	c.apiClient = apiclient.NewClient(cfg.ManagementAPI, log)

	var err error
	c.tetragonClient, err = tetragon.NewClient(cfg.Tetragon)
	if err != nil {
		return nil, cperrors.NewTetragonError("failed to create Tetragon client", err)
	}

	metadataCollector := metadata.NewCollector(cfg.Registration.UseIMDS, cfg.Registration.IMDSTimeout)

	// Create managers with their specific configs
	c.registrationManager = NewRegistrationManager(
		c.apiClient,
		c.cache,
		metadataCollector,
		log,
		RegistrationConfig{
			Environment:    cfg.Registration.Environment,
			DeploymentType: cfg.Registration.DeploymentType,
			Tags:           cfg.Registration.Tags,
		},
	)

	c.policySyncManager = NewPolicySyncManager(
		c.apiClient,
		c.tetragonClient,
		c.cache,
		log,
		PolicySyncConfig{
			Incremental:     cfg.PolicySync.Incremental,
			CleanupExisting: cfg.PolicySync.CleanupExisting,
		},
	)

	c.healthReporter = NewHealthReporter(
		c.apiClient,
		c.tetragonClient,
		c.cache,
		log,
		HealthReporterConfig{
			TetragonTimeout: cfg.Tetragon.Timeout,
			APITimeout:      cfg.ManagementAPI.Timeout,
		},
	)

	if cfg.Metrics.Enabled {
		c.metricsPublisher = NewMetricsPublisher(
			c.apiClient,
			c.cache,
			log,
			MetricsPublisherConfig{
				Endpoint:              cfg.Metrics.Endpoint,
				Format:                cfg.Metrics.Format,
				RequestTimeout:        cfg.Metrics.RequestTimeout,
				InsecureSkipTLSVerify: cfg.Metrics.InsecureSkipTLSVerify,
			},
		)
	}

	return c, nil
}

// Start starts the control plane client
func (c *ControlPlaneClient) Start(ctx context.Context) error {
	c.logger.Info("starting control plane client...")
	defer c.tetragonClient.Close()

	// Register with management API
	clientID, err := c.registrationManager.Register(ctx)
	if err != nil {
		return err
	}
	c.clientID = clientID

	// Update logger with client ID for better tracing
	c.logger = c.logger.WithField("client_id", c.clientID)
	c.logger.Info("client registered and ready")

	// Cleanup existing policies on startup if configured
	if c.cfg.PolicySync.CleanupExisting {
		if err := c.policySyncManager.CleanupExisting(ctx); err != nil {
			c.logger.Warn("failed to cleanup existing policies: %v", err)
		}
	} else if c.cfg.PolicySync.Incremental {
		// When using incremental sync without cleanup, seed the local
		// inventory cache from policies already loaded in Tetragon so we
		// don't attempt to re-add existing policies on the first sync.
		if err := c.policySyncManager.SeedInventoryFromTetragon(ctx); err != nil {
			c.logger.Warn("failed to seed policy inventory from Tetragon: %v", err)
		}
	}

	// Initial policy sync
	if err := c.policySyncManager.Sync(ctx, c.clientID); err != nil {
		c.logger.Warn("initial policy sync failed: %v", err)
	}

	// Start background loops
	go c.policySyncLoop(ctx)
	go c.healthReportingLoop(ctx)
	if c.cfg.Metrics.Enabled {
		if c.metricsPublisher == nil {
			return cperrors.NewConfigError("metrics publishing enabled but publisher is not configured", nil)
		}
		go c.metricsPublishingLoop(ctx)
	} else {
		c.logger.Info("metrics publishing disabled via configuration")
	}
	go c.configReloadLoop(ctx)

	// Wait for shutdown signal
	<-ctx.Done()
	close(c.stopCh)
	c.logger.Info("control plane client shutting down...")

	return nil
}

// policySyncLoop periodically syncs policies
func (c *ControlPlaneClient) policySyncLoop(ctx context.Context) {
	// Add initial jitter to prevent thundering herd
	initialInterval := addJitter(c.cfg.PolicySync.Interval)
	c.logger.Debug("policy sync interval with jitter: %v (base: %v)", initialInterval, c.cfg.PolicySync.Interval)

	ticker := time.NewTicker(initialInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("policy sync loop stopping due to context cancellation")
			return
		case <-c.stopCh:
			c.logger.Info("policy sync loop stopping due to stop signal")
			return
		case <-ticker.C:
			// Create a timeout context for this sync operation
			syncCtx, cancel := context.WithTimeout(ctx, c.cfg.ManagementAPI.Timeout*2)

			if err := c.policySyncManager.Sync(syncCtx, c.clientID); err != nil {
				c.logger.Error("policy sync error: %v", err)

				// Apply backpressure based on consecutive errors
				consecutiveErrors := c.policySyncManager.GetConsecutiveErrors()
				if consecutiveErrors > 0 {
					backoff := calculateBackoffDuration(consecutiveErrors, c.cfg.PolicySync.Interval)
					c.logger.Warn("backing off due to %d consecutive errors, additional delay: %v",
						consecutiveErrors, backoff)

					// Reset ticker with backoff
					ticker.Reset(c.cfg.PolicySync.Interval + backoff)
				}
			} else {
				// Reset to normal interval with jitter on success
				ticker.Reset(addJitter(c.cfg.PolicySync.Interval))
			}

			cancel()
		}
	}
}

// healthReportingLoop periodically reports health
func (c *ControlPlaneClient) healthReportingLoop(ctx context.Context) {
	// Add initial jitter to prevent thundering herd
	initialInterval := addJitter(c.cfg.HealthReporting.Interval)
	c.logger.Debug("health reporting interval with jitter: %v (base: %v)", initialInterval, c.cfg.HealthReporting.Interval)

	ticker := time.NewTicker(initialInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("health reporting loop stopping due to context cancellation")
			return
		case <-c.stopCh:
			c.logger.Info("health reporting loop stopping due to stop signal")
			return
		case <-ticker.C:
			if err := c.healthReporter.Report(ctx, c.clientID); err != nil {
				c.logger.Error("health reporting error: %v", err)

				// Apply backpressure based on consecutive errors
				consecutiveErrors := c.healthReporter.GetConsecutiveErrors()
				if consecutiveErrors > 0 {
					backoff := calculateBackoffDuration(consecutiveErrors, c.cfg.HealthReporting.Interval)
					c.logger.Warn("backing off due to %d consecutive errors, additional delay: %v",
						consecutiveErrors, backoff)

					// Reset ticker with backoff
					ticker.Reset(c.cfg.HealthReporting.Interval + backoff)
				}
			} else {
				// Reset to normal interval with jitter on success
				ticker.Reset(addJitter(c.cfg.HealthReporting.Interval))
			}
		}
	}
}

// metricsPublishingLoop periodically sends Prometheus metrics payloads to the management API
func (c *ControlPlaneClient) metricsPublishingLoop(ctx context.Context) {
	if c.metricsPublisher == nil {
		c.logger.Warn("metrics publishing loop requested but publisher is nil")
		return
	}

	initialInterval := addJitter(c.cfg.Metrics.Interval)
	c.logger.Debug("metrics publishing interval with jitter: %v (base: %v)", initialInterval, c.cfg.Metrics.Interval)

	ticker := time.NewTicker(initialInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("metrics publishing loop stopping due to context cancellation")
			return
		case <-c.stopCh:
			c.logger.Info("metrics publishing loop stopping due to stop signal")
			return
		case <-ticker.C:
			timeout := c.cfg.ManagementAPI.Timeout + c.cfg.Metrics.RequestTimeout
			publishCtx, cancel := context.WithTimeout(ctx, timeout)

			if err := c.metricsPublisher.Publish(publishCtx, c.clientID); err != nil {
				c.logger.Error("metrics publishing error: %v", err)

				consecutiveErrors := c.metricsPublisher.GetConsecutiveErrors()
				if consecutiveErrors > 0 {
					backoff := calculateBackoffDuration(consecutiveErrors, c.cfg.Metrics.Interval)
					c.logger.Warn("metrics publishing backing off due to %d consecutive errors, additional delay: %v",
						consecutiveErrors, backoff)
					ticker.Reset(c.cfg.Metrics.Interval + backoff)
				}
			} else {
				ticker.Reset(addJitter(c.cfg.Metrics.Interval))
			}

			cancel()
		}
	}
}

// configReloadLoop handles configuration reload signals
func (c *ControlPlaneClient) configReloadLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case <-c.reloadCh:
			c.logger.Info("received SIGHUP, reloading configuration...")
			if err := c.reloadConfig(); err != nil {
				c.logger.Error("failed to reload configuration: %v", err)
			} else {
				c.logger.Info("configuration reloaded successfully")
			}
		}
	}
}

// reloadConfig reloads non-destructive configuration changes and handles log rotation
func (c *ControlPlaneClient) reloadConfig() error {
	c.logger.Info("configuration reload requested - reopening log files for rotation...")

	// Reopen log files (for logrotate support)
	if err := c.logger.Reopen(); err != nil {
		return fmt.Errorf("failed to reopen log files: %w", err)
	}

	c.logger.Info("log files reopened successfully")
	return nil
}
