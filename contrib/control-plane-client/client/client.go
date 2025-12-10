package client

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/cilium/tetragon/contrib/control-plane-client/apiclient"
	"github.com/cilium/tetragon/contrib/control-plane-client/cache"
	"github.com/cilium/tetragon/contrib/control-plane-client/config"
	"github.com/cilium/tetragon/contrib/control-plane-client/metadata"
	"github.com/cilium/tetragon/contrib/control-plane-client/retry"
	"github.com/cilium/tetragon/contrib/control-plane-client/tetragon"
	"github.com/cilium/tetragon/contrib/control-plane-client/types"
)

type ControlPlaneClient struct {
	cfg               *config.Config
	cache             *cache.Cache
	apiClient         *apiclient.Client
	tetragonClient    *tetragon.Client
	metadataCollector *metadata.Collector
	retryer           *retry.Retryer
	clientID          string
	policyVersion     string
	policySha256      string
	stopCh            chan struct{}
	logger            *logger
}

// logger provides centralized logging with automatic level checking
type logger struct {
	level string
}

func newLogger(level string) *logger {
	return &logger{level: level}
}

func (l *logger) debug(format string, args ...interface{}) {
	if l.level == "debug" {
		log.Printf("[DEBUG] "+format, args...)
	}
}

func (l *logger) info(format string, args ...interface{}) {
	log.Printf("[INFO] "+format, args...)
}

func (l *logger) warn(format string, args ...interface{}) {
	log.Printf("[WARN] "+format, args...)
}

func (l *logger) error(format string, args ...interface{}) {
	log.Printf("[ERROR] "+format, args...)
}

func NewControlPlaneClient(cfg *config.Config) (*ControlPlaneClient, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	c := &ControlPlaneClient{
		cfg:    cfg,
		stopCh: make(chan struct{}),
		logger: newLogger(cfg.Logging.Level),
	}

	c.cache = cache.NewCache()
	c.retryer = retry.NewRetryerWithLogLevel(cfg.ManagementAPI.Retry, cfg.Logging.Level)
	c.apiClient = apiclient.NewClient(cfg.ManagementAPI, cfg.Logging.Level)

	var err error
	c.tetragonClient, err = tetragon.NewClient(cfg.Tetragon)
	if err != nil {
		return nil, fmt.Errorf("failed to create Tetragon client: %w", err)
	}

	c.metadataCollector = metadata.NewCollector(cfg.Registration.UseIMDS, cfg.Registration.IMDSTimeout)

	return c, nil
}

func (c *ControlPlaneClient) Start(ctx context.Context) error {
	c.logger.info("Starting control plane client...")

	if err := c.tetragonClient.Connect(ctx); err != nil {
		return fmt.Errorf("failed to connect to Tetragon: %w", err)
	}
	defer c.tetragonClient.Close()

	if err := c.register(ctx); err != nil {
		return fmt.Errorf("failed to register with management API: %w", err)
	}

	if err := c.syncPolicies(ctx); err != nil {
		c.logger.warn("Initial policy sync failed: %v", err)
	}

	go c.policySyncLoop(ctx)
	go c.healthReportingLoop(ctx)

	<-ctx.Done()
	close(c.stopCh)
	c.logger.info("Control plane client shutting down...")

	return nil
}

func (c *ControlPlaneClient) register(ctx context.Context) error {
	clientID, err := c.cache.GetClientID()
	if err == nil && clientID != "" {
		c.clientID = clientID
		c.logger.info("Using cached client ID: %s", c.clientID)
		return nil
	}

	c.logger.info("Registering with management API...")
	c.logger.debug("[client] Starting registration with retry logic")

	hostname, _ := c.metadataCollector.GetHostname()
	instanceID, _ := c.metadataCollector.GetInstanceID(ctx)
	ipAddress, _ := c.metadataCollector.GetIPAddress()

	c.logger.debug("[client] Registration metadata: hostname=%s, instance_id=%s, ip=%s, env=%s, arch=%s, tags=%v",
		hostname, instanceID, ipAddress, c.cfg.Registration.Environment,
		c.metadataCollector.GetArchitecture(), c.cfg.Registration.Tags)

	req := types.RegistrationRequest{
		Hostname:     hostname,
		InstanceID:   instanceID,
		Environment:  c.cfg.Registration.Environment,
		Architecture: c.metadataCollector.GetArchitecture(),
		IPAddress:    ipAddress,
		Tags:         c.cfg.Registration.Tags,
	}

	resp, err := c.apiClient.Register(ctx, req)
	if err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}

	c.logger.debug("[client] Registration successful, received client ID: %s", resp.ClientID)

	c.clientID = resp.ClientID
	if err := c.cache.SetClientID(c.clientID); err != nil {
		c.logger.warn("Failed to cache client ID: %v", err)
	}

	c.logger.info("Successfully registered with client ID: %s", c.clientID)
	return nil
}

func (c *ControlPlaneClient) syncPolicies(ctx context.Context) error {
	c.logger.info("Syncing policies...")
	c.logger.debug("[client] Starting policy sync with retry logic")

	resp, err := c.apiClient.GetPolicies(ctx, c.clientID)
	if err != nil {
		return fmt.Errorf("failed to get policies: %w", err)
	}

	if resp.Version == c.policyVersion {
		c.logger.info("Policies already at version %s, no update needed", c.policyVersion)
		return nil
	}

	c.logger.info("Applying new policy version %s (previous: %s)", resp.Version, c.policyVersion)

	if err := c.applyPolicies(ctx, resp); err != nil {
		return err
	}

	c.updatePolicyState(resp)
	c.logger.info("Successfully applied policy version %s (sha256: %s)", c.policyVersion, c.policySha256)
	return nil
}

func (c *ControlPlaneClient) applyPolicies(ctx context.Context, resp *types.PoliciesResponse) error {
	if err := c.tetragonClient.DeleteAllPolicies(ctx); err != nil {
		return fmt.Errorf("failed to delete existing policies: %w", err)
	}

	if err := c.tetragonClient.ApplyPoliciesFromBase64(ctx, resp.Policies); err != nil {
		return fmt.Errorf("failed to apply new policies: %w", err)
	}

	return nil
}

func (c *ControlPlaneClient) updatePolicyState(resp *types.PoliciesResponse) {
	c.policyVersion = resp.Version
	if err := c.cache.SetPolicyVersion(c.policyVersion); err != nil {
		c.logger.warn("Failed to cache policy version: %v", err)
	}

	c.policySha256 = resp.Sha256
	if err := c.cache.SetPolicySha256(c.policySha256); err != nil {
		c.logger.warn("Failed to cache policy sha256: %v", err)
	}
}

func (c *ControlPlaneClient) reportHealth(ctx context.Context) error {
	statuses, err := c.tetragonClient.GetPolicyStatuses(ctx)
	if err != nil {
		return fmt.Errorf("failed to get policy statuses: %w", err)
	}

	tetragonVersion := c.getTetragonVersion(ctx)
	report := c.buildHealthReport(statuses, tetragonVersion)

	c.logger.info("Reporting health: status=%s, policy_version=%s, tetragon_version=%s, policies=%d",
		report.Status, report.PolicyVersion, report.TetragonVersion, len(report.Policies))

	c.logger.debug("[client] Starting health report with retry logic")

	return c.apiClient.ReportHealth(ctx, c.clientID, report)
}

func (c *ControlPlaneClient) getTetragonVersion(ctx context.Context) string {
	tetragonVersion, err := c.tetragonClient.GetVersion(ctx)
	if err != nil {
		c.logger.warn("Failed to get Tetragon version: %v", err)
		return "unknown"
	}
	return tetragonVersion
}

func (c *ControlPlaneClient) buildHealthReport(statuses []types.PolicyStatus, tetragonVersion string) types.HealthReport {
	report := types.HealthReport{
		Timestamp:       time.Now(),
		Status:          "healthy",
		PolicyVersion:   c.policyVersion,
		PolicySha256:    c.policySha256,
		TetragonVersion: tetragonVersion,
		Policies:        statuses,
	}

	for i, status := range statuses {
		c.logger.debug("Policy %d: name=%s, state=%s, error=%s", i, status.Name, status.State, status.Error)
		if status.State != "TP_STATE_ENABLED" {
			c.logger.warn("Policy %s state is %s (not TP_STATE_ENABLED), marking as degraded", status.Name, status.State)
			report.Status = "degraded"
			break
		}
	}

	return report
}

func (c *ControlPlaneClient) policySyncLoop(ctx context.Context) {
	ticker := time.NewTicker(c.cfg.PolicySync.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case <-ticker.C:
			if err := c.syncPolicies(ctx); err != nil {
				c.logger.error("Policy sync error: %v", err)
			}
		}
	}
}

func (c *ControlPlaneClient) healthReportingLoop(ctx context.Context) {
	ticker := time.NewTicker(c.cfg.HealthReporting.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case <-ticker.C:
			if err := c.reportHealth(ctx); err != nil {
				c.logger.error("Health reporting error: %v", err)
			}
		}
	}
}
