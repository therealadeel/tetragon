package client

import (
	"context"
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

	// Create logger
	log := logger.NewStandardLogger(cfg.Logging.Level)

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
	)

	return c, nil
}

// Start starts the control plane client
func (c *ControlPlaneClient) Start(ctx context.Context) error {
	c.logger.Info("starting control plane client...")

	if err := c.tetragonClient.Connect(ctx); err != nil {
		return cperrors.NewTetragonError("failed to connect to Tetragon", err)
	}
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
	}

	// Initial policy sync
	if err := c.policySyncManager.Sync(ctx, c.clientID); err != nil {
		c.logger.Warn("initial policy sync failed: %v", err)
	}

	// Start background loops
	go c.policySyncLoop(ctx)
	go c.healthReportingLoop(ctx)
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
			// Create a timeout context for this health report operation
			healthCtx, cancel := context.WithTimeout(ctx, c.cfg.ManagementAPI.Timeout)

			if err := c.healthReporter.Report(healthCtx, c.clientID); err != nil {
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

// reloadConfig reloads non-destructive configuration changes
func (c *ControlPlaneClient) reloadConfig() error {
	// For now, only reload logging level (non-destructive)
	// Future: could reload intervals, retry settings, etc.
	c.logger.Info("configuration reload requested - updating log level to: %s", c.cfg.Logging.Level)

	// Create new logger with updated level
	newLogger := logger.NewStandardLogger(c.cfg.Logging.Level)
	if c.clientID != "" {
		newLogger = newLogger.WithField("client_id", c.clientID)
	}
	c.logger = newLogger

	c.logger.Info("log level updated successfully")
	return nil
}
