package client

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/cilium/tetragon/contrib/control-plane-client/apiclient"
	"github.com/cilium/tetragon/contrib/control-plane-client/cache"
	"github.com/cilium/tetragon/contrib/control-plane-client/config"
	cperrors "github.com/cilium/tetragon/contrib/control-plane-client/errors"
	"github.com/cilium/tetragon/contrib/control-plane-client/logger"
	"github.com/cilium/tetragon/contrib/control-plane-client/metadata"
	"github.com/cilium/tetragon/contrib/control-plane-client/policy"
	"github.com/cilium/tetragon/contrib/control-plane-client/tetragon"
	"github.com/cilium/tetragon/contrib/control-plane-client/types"
)

type ControlPlaneClient struct {
	cfg               *config.Config
	cache             *cache.Cache
	apiClient         *apiclient.Client
	tetragonClient    *tetragon.Client
	metadataCollector *metadata.Collector
	clientID          string
	policyVersion     string
	policySha256      string
	stopCh            chan struct{}
	logger            logger.Logger
}

func NewControlPlaneClient(cfg *config.Config) (*ControlPlaneClient, error) {
	if err := cfg.Validate(); err != nil {
		return nil, cperrors.NewConfigError("invalid configuration", err)
	}

	// Create logger
	log := logger.NewStandardLogger(cfg.Logging.Level)

	c := &ControlPlaneClient{
		cfg:    cfg,
		stopCh: make(chan struct{}),
		logger: log,
	}

	c.cache = cache.NewCache()
	c.apiClient = apiclient.NewClient(cfg.ManagementAPI, log)

	var err error
	c.tetragonClient, err = tetragon.NewClient(cfg.Tetragon)
	if err != nil {
		return nil, cperrors.NewTetragonError("failed to create Tetragon client", err)
	}

	c.metadataCollector = metadata.NewCollector(cfg.Registration.UseIMDS, cfg.Registration.IMDSTimeout)

	return c, nil
}

func (c *ControlPlaneClient) Start(ctx context.Context) error {
	c.logger.Info("Starting control plane client...")

	if err := c.tetragonClient.Connect(ctx); err != nil {
		return fmt.Errorf("failed to connect to Tetragon: %w", err)
	}
	defer c.tetragonClient.Close()

	if err := c.register(ctx); err != nil {
		return fmt.Errorf("failed to register with management API: %w", err)
	}

	// Cleanup existing policies on startup if configured
	if c.cfg.PolicySync.CleanupExisting {
		c.logger.Info("Cleaning up existing policies...")
		if err := c.tetragonClient.DeleteAllPolicies(ctx); err != nil {
			c.logger.Warn("Failed to cleanup existing policies: %v", err)
		} else {
			c.logger.Info("Successfully cleaned up existing policies")
		}
	}

	if err := c.syncPolicies(ctx); err != nil {
		c.logger.Warn("Initial policy sync failed: %v", err)
	}

	go c.policySyncLoop(ctx)
	go c.healthReportingLoop(ctx)

	<-ctx.Done()
	close(c.stopCh)
	c.logger.Info("Control plane client shutting down...")

	return nil
}

func (c *ControlPlaneClient) register(ctx context.Context) error {
	clientID, err := c.cache.GetClientID()
	if err == nil && clientID != "" {
		c.clientID = clientID
		c.logger.Info("Using cached client ID: %s", c.clientID)
		return nil
	}

	c.logger.Info("Registering with management API...")
	c.logger.Debug("[client] Starting registration with retry logic")

	hostname, _ := c.metadataCollector.GetHostname()
	instanceID, _ := c.metadataCollector.GetInstanceID(ctx)
	ipAddress, _ := c.metadataCollector.GetIPAddress()

	c.logger.Debug("[client] Registration metadata: hostname=%s, instance_id=%s, ip=%s, env=%s, arch=%s, tags=%v",
		hostname, instanceID, ipAddress, c.cfg.Registration.Environment,
		c.metadataCollector.GetArchitecture(), c.cfg.Registration.Tags)

	req := types.RegistrationRequest{
		Hostname:       hostname,
		InstanceID:     instanceID,
		Environment:    c.cfg.Registration.Environment,
		Architecture:   c.metadataCollector.GetArchitecture(),
		IPAddress:      ipAddress,
		DeploymentType: c.cfg.Registration.DeploymentType,
		Tags:           c.cfg.Registration.Tags,
	}

	resp, err := c.apiClient.Register(ctx, req)
	if err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}

	c.logger.Debug("[client] Registration successful, received client ID: %s", resp.ClientID)

	c.clientID = resp.ClientID
	if err := c.cache.SetClientID(c.clientID); err != nil {
		c.logger.Warn("Failed to cache client ID: %v", err)
	}

	c.logger.Info("Successfully registered with client ID: %s", c.clientID)
	return nil
}

func (c *ControlPlaneClient) syncPolicies(ctx context.Context) error {
	c.logger.Info("Syncing policies...")
	c.logger.Debug("[client] Starting policy sync with retry logic")

	resp, err := c.apiClient.GetPolicies(ctx, c.clientID)
	if err != nil {
		return fmt.Errorf("failed to get policies: %w", err)
	}

	if resp.Version == c.policyVersion && resp.Sha256 == c.policySha256 {
		c.logger.Info("Policies already at version %s (sha256: %s), no update needed", c.policyVersion, c.policySha256)
		return nil
	}

	c.logger.Info("Applying new policy version %s (previous: %s)", resp.Version, c.policyVersion)

	if err := c.applyPolicies(ctx, resp); err != nil {
		return err
	}

	c.updatePolicyState(resp)
	c.logger.Info("Successfully applied policy version %s (sha256: %s)", c.policyVersion, c.policySha256)
	return nil
}

func (c *ControlPlaneClient) applyPolicies(ctx context.Context, resp *types.PoliciesResponse) error {
	// Use incremental updates if configured
	if c.cfg.PolicySync.Incremental {
		return c.applyPoliciesIncremental(ctx, resp)
	}

	// Fall back to delete-all approach
	if err := c.tetragonClient.DeleteAllPolicies(ctx); err != nil {
		return fmt.Errorf("failed to delete existing policies: %w", err)
	}

	if err := c.tetragonClient.ApplyPoliciesFromBase64(ctx, resp.Policies); err != nil {
		return fmt.Errorf("failed to apply new policies: %w", err)
	}

	return nil
}

func (c *ControlPlaneClient) applyPoliciesIncremental(ctx context.Context, resp *types.PoliciesResponse) error {
	c.logger.Debug("Using incremental policy updates")

	// Decode base64 policies
	yamlBytes, err := base64.StdEncoding.DecodeString(resp.Policies)
	if err != nil {
		return fmt.Errorf("failed to decode base64 policies: %w", err)
	}

	// Parse desired policies
	desired, err := policy.ParsePolicies(string(yamlBytes))
	if err != nil {
		return fmt.Errorf("failed to parse policies: %w", err)
	}

	// Get current policy inventory from cache
	current := c.cache.GetPolicyInventory()

	// Compute diff
	diff := policy.ComputeDiff(current, desired)
	c.logger.Info("Policy diff: %s", diff.Summary())

	if diff.IsEmpty() {
		c.logger.Debug("No policy changes detected")
		return nil
	}

	// Apply diff
	if err := c.applyPolicyDiff(ctx, diff); err != nil {
		return err
	}

	// Update inventory cache
	newInventory := make(map[string]policy.Metadata)
	for _, doc := range desired {
		newInventory[doc.Key()] = policy.Metadata{
			Name:      doc.Name,
			Namespace: doc.Namespace,
			Hash:      doc.Hash,
		}
	}
	if err := c.cache.SetPolicyInventory(newInventory); err != nil {
		c.logger.Warn("Failed to cache policy inventory: %v", err)
	}

	return nil
}

func (c *ControlPlaneClient) applyPolicyDiff(ctx context.Context, diff *policy.Diff) error {
	var errors []string

	// Delete removed policies first
	for _, policyKey := range diff.ToDelete {
		c.logger.Info("Deleting policy: %s", policyKey)

		// Parse namespace/name from key
		parts := strings.Split(policyKey, "/")
		var name, namespace string
		if len(parts) == 2 {
			namespace = parts[0]
			name = parts[1]
		} else {
			name = policyKey
		}

		if err := c.tetragonClient.DeletePolicy(ctx, name, namespace); err != nil {
			errors = append(errors, fmt.Sprintf("delete %s: %v", policyKey, err))
		}
	}

	// Update changed policies (delete old + add new)
	for _, doc := range diff.ToUpdate {
		c.logger.Info("Updating policy: %s", doc.Key())

		// Delete old version
		if err := c.tetragonClient.DeletePolicy(ctx, doc.Name, doc.Namespace); err != nil {
			c.logger.Warn("Failed to delete old version of %s: %v", doc.Key(), err)
		}

		// Add new version
		if err := c.tetragonClient.AddPolicy(ctx, doc.Content); err != nil {
			errors = append(errors, fmt.Sprintf("update %s: %v", doc.Key(), err))
		}
	}

	// Add new policies
	for _, doc := range diff.ToAdd {
		c.logger.Info("Adding policy: %s", doc.Key())

		if err := c.tetragonClient.AddPolicy(ctx, doc.Content); err != nil {
			errors = append(errors, fmt.Sprintf("add %s: %v", doc.Key(), err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to apply policy changes: %s", strings.Join(errors, "; "))
	}

	return nil
}

func (c *ControlPlaneClient) updatePolicyState(resp *types.PoliciesResponse) {
	c.policyVersion = resp.Version
	if err := c.cache.SetPolicyVersion(c.policyVersion); err != nil {
		c.logger.Warn("Failed to cache policy version: %v", err)
	}

	c.policySha256 = resp.Sha256
	if err := c.cache.SetPolicySha256(c.policySha256); err != nil {
		c.logger.Warn("Failed to cache policy sha256: %v", err)
	}
}

func (c *ControlPlaneClient) reportHealth(ctx context.Context) error {
	statuses, err := c.tetragonClient.GetPolicyStatuses(ctx)
	if err != nil {
		return fmt.Errorf("failed to get policy statuses: %w", err)
	}

	tetragonVersion := c.getTetragonVersion(ctx)
	report := c.buildHealthReport(statuses, tetragonVersion)

	c.logger.Info("Reporting health: status=%s, policy_version=%s, tetragon_version=%s, policies=%d",
		report.Status, report.PolicyVersion, report.TetragonVersion, len(report.Policies))

	c.logger.Debug("[client] Starting health report with retry logic")

	return c.apiClient.ReportHealth(ctx, c.clientID, report)
}

func (c *ControlPlaneClient) getTetragonVersion(ctx context.Context) string {
	tetragonVersion, err := c.tetragonClient.GetVersion(ctx)
	if err != nil {
		c.logger.Warn("Failed to get Tetragon version: %v", err)
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
		c.logger.Debug("Policy %d: name=%s, state=%s, error=%s", i, status.Name, status.State, status.Error)
		if status.State != "TP_STATE_ENABLED" {
			c.logger.Warn("Policy %s state is %s (not TP_STATE_ENABLED), marking as degraded", status.Name, status.State)
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
			c.logger.Info("Policy sync loop stopping due to context cancellation")
			return
		case <-c.stopCh:
			c.logger.Info("Policy sync loop stopping due to stop signal")
			return
		case <-ticker.C:
			// Create a timeout context for this sync operation
			syncCtx, cancel := context.WithTimeout(ctx, c.cfg.ManagementAPI.Timeout*2)
			if err := c.syncPolicies(syncCtx); err != nil {
				c.logger.Error("Policy sync error: %v", err)
			}
			cancel()
		}
	}
}

func (c *ControlPlaneClient) healthReportingLoop(ctx context.Context) {
	ticker := time.NewTicker(c.cfg.HealthReporting.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("Health reporting loop stopping due to context cancellation")
			return
		case <-c.stopCh:
			c.logger.Info("Health reporting loop stopping due to stop signal")
			return
		case <-ticker.C:
			// Create a timeout context for this health report operation
			healthCtx, cancel := context.WithTimeout(ctx, c.cfg.ManagementAPI.Timeout)
			if err := c.reportHealth(healthCtx); err != nil {
				c.logger.Error("Health reporting error: %v", err)
			}
			cancel()
		}
	}
}
