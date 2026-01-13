package client

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/cilium/tetragon/contrib/control-plane-client/apiclient"
	"github.com/cilium/tetragon/contrib/control-plane-client/cache"
	cperrors "github.com/cilium/tetragon/contrib/control-plane-client/errors"
	"github.com/cilium/tetragon/contrib/control-plane-client/logger"
	"github.com/cilium/tetragon/contrib/control-plane-client/policy"
	"github.com/cilium/tetragon/contrib/control-plane-client/tetragon"
	"github.com/cilium/tetragon/contrib/control-plane-client/types"
)

// shortHash returns first 12 characters of a SHA256 hash for display
func shortHash(sha256 string) string {
	if len(sha256) > 12 {
		return sha256[:12]
	}
	return sha256
}

// getDisplayName returns the display name, falling back to short hash if empty
func getDisplayName(resp *types.PoliciesResponse) string {
	if resp.DisplayName != "" {
		return resp.DisplayName
	}
	return shortHash(resp.Sha256)
}

// PolicySyncManager handles policy synchronization with the management API
type PolicySyncManager struct {
	apiClient         apiclient.ClientInterface
	tetragonClient    tetragon.ClientInterface
	cache             *cache.Cache
	logger            logger.Logger
	config            PolicySyncConfig
	consecutiveErrors int
}

// PolicySyncConfig holds policy sync-specific configuration
type PolicySyncConfig struct {
	Incremental     bool
	CleanupExisting bool
}

// NewPolicySyncManager creates a new policy sync manager
func NewPolicySyncManager(
	apiClient apiclient.ClientInterface,
	tetragonClient tetragon.ClientInterface,
	cache *cache.Cache,
	logger logger.Logger,
	config PolicySyncConfig,
) *PolicySyncManager {
	return &PolicySyncManager{
		apiClient:      apiClient,
		tetragonClient: tetragonClient,
		cache:          cache,
		logger:         logger.WithField("component", "policy_sync"),
		config:         config,
	}
}

// CleanupExisting deletes all existing policies from Tetragon
func (p *PolicySyncManager) CleanupExisting(ctx context.Context) error {
	p.logger.Info("cleaning up existing policies...")
	if err := p.tetragonClient.DeleteAllPolicies(ctx); err != nil {
		return cperrors.NewTetragonError("failed to cleanup existing policies", err)
	}
	p.logger.Info("successfully cleaned up existing policies")
	return nil
}

// Sync synchronizes policies from the management API
func (p *PolicySyncManager) Sync(ctx context.Context, clientID string) error {
	p.logger.Info("syncing policies...")
	p.logger.Debug("starting policy sync with retry logic")

	resp, err := p.apiClient.GetPolicies(ctx, clientID)
	if err != nil {
		p.consecutiveErrors++
		return cperrors.NewAPIError("failed to get policies", 0, err)
	}

	currentDisplayName := p.cache.GetPolicyDisplayName()
	currentSha256 := p.cache.GetPolicySha256()
	newDisplayName := getDisplayName(resp)

	// Use SHA256 as authoritative source for change detection
	if resp.Sha256 == currentSha256 {
		p.logger.Info("policies unchanged at %s (sha256: %s...)", newDisplayName, shortHash(currentSha256))
		p.consecutiveErrors = 0 // Reset on success
		return nil
	}

	p.logger.Info("applying new policies: %s (previous: %s, sha256: %s...)", newDisplayName, currentDisplayName, shortHash(resp.Sha256))

	if err := p.applyPolicies(ctx, resp); err != nil {
		p.consecutiveErrors++
		return err
	}

	p.updatePolicyState(resp)
	p.logger.Info("successfully applied policies: %s (sha256: %s...)", newDisplayName, shortHash(resp.Sha256))
	p.consecutiveErrors = 0 // Reset on success
	return nil
}

// GetConsecutiveErrors returns the number of consecutive sync errors
func (p *PolicySyncManager) GetConsecutiveErrors() int {
	return p.consecutiveErrors
}

func (p *PolicySyncManager) applyPolicies(ctx context.Context, resp *types.PoliciesResponse) error {
	// Use incremental updates if configured
	if p.config.Incremental {
		return p.applyPoliciesIncremental(ctx, resp)
	}

	// Fall back to delete-all approach
	// Decode and parse policies so we can track the expected policy count
	yamlBytes, err := base64.StdEncoding.DecodeString(resp.Policies)
	if err != nil {
		return cperrors.NewPolicyError("failed to decode base64 policies", err)
	}

	desired, err := policy.ParsePolicies(string(yamlBytes))
	if err != nil {
		return cperrors.NewPolicyError("failed to parse policies", err)
	}

	// Track expected number of policies from the control plane
	p.cache.SetPolicyCount(len(desired))

	if err := p.tetragonClient.DeleteAllPolicies(ctx); err != nil {
		return cperrors.NewTetragonError("failed to delete existing policies", err)
	}

	if err := p.tetragonClient.ApplyPoliciesFromBase64(ctx, resp.Policies); err != nil {
		return cperrors.NewTetragonError("failed to apply new policies", err)
	}

	return nil
}

func (p *PolicySyncManager) applyPoliciesIncremental(ctx context.Context, resp *types.PoliciesResponse) error {
	p.logger.Debug("using incremental policy updates")

	// Decode base64 policies
	yamlBytes, err := base64.StdEncoding.DecodeString(resp.Policies)
	if err != nil {
		return cperrors.NewPolicyError("failed to decode base64 policies", err)
	}

	// Parse desired policies
	desired, err := policy.ParsePolicies(string(yamlBytes))
	if err != nil {
		return cperrors.NewPolicyError("failed to parse policies", err)
	}

	// Track expected number of policies from the control plane
	p.cache.SetPolicyCount(len(desired))

	// Get current policy inventory from cache
	current := p.cache.GetPolicyInventory()

	// Compute diff
	diff := policy.ComputeDiff(current, desired)
	p.logger.Info("policy diff: %s", diff.Summary())

	if diff.IsEmpty() {
		p.logger.Debug("no policy changes detected")
		return nil
	}

	// Apply diff
	if err := p.applyPolicyDiff(ctx, diff); err != nil {
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
	p.cache.SetPolicyInventory(newInventory)

	return nil
}

func (p *PolicySyncManager) applyPolicyDiff(ctx context.Context, diff *policy.Diff) error {
	var errors []string

	// Delete removed policies first
	for _, policyKey := range diff.ToDelete {
		p.logger.Info("deleting policy: %s", policyKey)

		// Parse namespace/name from key
		parts := strings.Split(policyKey, "/")
		var name, namespace string
		if len(parts) == 2 {
			namespace = parts[0]
			name = parts[1]
		} else {
			name = policyKey
		}

		if err := p.tetragonClient.DeletePolicy(ctx, name, namespace); err != nil {
			errors = append(errors, fmt.Sprintf("delete %s: %v", policyKey, err))
		}
	}

	// Update modified policies (delete + add)
	for _, doc := range diff.ToUpdate {
		p.logger.Info("updating policy: %s", doc.Key())
		p.logger.Debug("policy content hash: %s", doc.Hash)

		if err := p.tetragonClient.DeletePolicy(ctx, doc.Name, doc.Namespace); err != nil {
			errors = append(errors, fmt.Sprintf("update-delete %s: %v", doc.Key(), err))
			continue
		}

		if err := p.tetragonClient.AddPolicy(ctx, doc.Content); err != nil {
			errors = append(errors, fmt.Sprintf("update-add %s: %v", doc.Key(), err))
		}
	}

	// Add new policies
	for _, doc := range diff.ToAdd {
		p.logger.Info("adding policy: %s", doc.Key())
		p.logger.Debug("policy content hash: %s", doc.Hash)

		if err := p.tetragonClient.AddPolicy(ctx, doc.Content); err != nil {
			errors = append(errors, fmt.Sprintf("add %s: %v", doc.Key(), err))
		}
	}

	if len(errors) > 0 {
		return cperrors.NewPolicyError(
			fmt.Sprintf("failed to apply some policy changes: %s", strings.Join(errors, "; ")),
			nil,
		)
	}

	return nil
}

func (p *PolicySyncManager) updatePolicyState(resp *types.PoliciesResponse) {
	p.cache.SetPolicyDisplayName(getDisplayName(resp))
	p.cache.SetPolicySha256(resp.Sha256)
}
