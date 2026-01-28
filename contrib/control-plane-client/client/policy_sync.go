package client

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cilium/tetragon/contrib/control-plane-client/apiclient"
	"github.com/cilium/tetragon/contrib/control-plane-client/cache"
	cperrors "github.com/cilium/tetragon/contrib/control-plane-client/errors"
	"github.com/cilium/tetragon/contrib/control-plane-client/logger"
	"github.com/cilium/tetragon/contrib/control-plane-client/policy"
	"github.com/cilium/tetragon/contrib/control-plane-client/retry"
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

// shouldBackoffForError determines if a given error should contribute to
// backoff calculations. From the client's perspective we only want to
// back off when talking to a server is failing (e.g. management API or
// Tetragon connectivity issues), not when there are policy content or
// validation problems.
func shouldBackoffForError(err error) bool {
	if err == nil {
		return false
	}

	var cpErr *cperrors.ControlPlaneError
	if errors.As(err, &cpErr) {
		// Do NOT back off on policy errors – these indicate invalid
		// or unsupported policies rather than server unavailability.
		if cpErr.Type == cperrors.ErrorTypePolicy {
			return false
		}
	}

	// Default: back off for all other error types, which typically
	// represent API, network, or Tetragon connectivity issues.
	return true
}

func httpStatusCodeFromError(err error) int {
	var httpErr *retry.HTTPError
	if errors.As(err, &httpErr) {
		return httpErr.StatusCode
	}
	return 0
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

// SeedInventoryFromTetragon initializes the local policy inventory cache
// from the policies currently loaded in Tetragon. This helps incremental
// syncs avoid attempting to add policies that already exist.
func (p *PolicySyncManager) SeedInventoryFromTetragon(ctx context.Context) error {
	policies, err := p.tetragonClient.ListPolicies(ctx)
	if err != nil {
		return cperrors.NewTetragonError("failed to list policies for inventory seeding", err)
	}

	if len(policies) == 0 {
		p.logger.Debug("no existing policies found in Tetragon when seeding inventory")
		return nil
	}

	inventory := make(map[string]policy.Metadata, len(policies))
	for _, pol := range policies {
		if pol == nil {
			continue
		}

		key := pol.Name
		if pol.Namespace != "" {
			key = pol.Namespace + "/" + pol.Name
		}

		inventory[key] = policy.Metadata{
			Name:      pol.Name,
			Namespace: pol.Namespace,
			Hash:      "",
		}
	}

	p.cache.SetPolicyInventory(inventory)
	p.logger.Info("seeded policy inventory from Tetragon with %d policies", len(inventory))
	return nil
}

// Sync synchronizes policies from the management API
func (p *PolicySyncManager) Sync(ctx context.Context, clientID string) error {
	p.logger.Info("syncing policies...")
	p.logger.Debug("starting policy sync with retry logic")

	resp, err := p.apiClient.GetPolicies(ctx, clientID)
	if err != nil {
		statusCode := httpStatusCodeFromError(err)
		if statusCode != 0 {
			p.cache.SetPolicySyncError(cache.PolicySyncError{
				StatusCode: statusCode,
				Message:    err.Error(),
				Timestamp:  time.Now(),
			})
		} else if _, ok := p.cache.GetPolicySyncError(); !ok {
			p.cache.SetPolicySyncError(cache.PolicySyncError{
				StatusCode: 0,
				Message:    err.Error(),
				Timestamp:  time.Now(),
			})
		}

		wrapped := cperrors.NewAPIError("failed to get policies", statusCode, err)
		if shouldBackoffForError(wrapped) {
			p.consecutiveErrors++
		} else {
			p.consecutiveErrors = 0
		}
		return wrapped
	}
	p.cache.ClearPolicySyncError()

	currentDisplayName := p.cache.GetPolicyDisplayName()
	currentSha256 := p.cache.GetPolicySha256()
	currentCount := p.cache.GetPolicyCount()
	newDisplayName := getDisplayName(resp)
	newCount := resp.PolicyCount

	// Use SHA256 as authoritative source for change detection
	// and also factor in the server-provided policy count. Both must
	// match the cached values for us to treat the bundle as unchanged.
	if resp.Sha256 == currentSha256 && newCount == currentCount {
		p.logger.Info("policies unchanged at %s (sha256: %s..., count: %d)", newDisplayName, shortHash(currentSha256), newCount)
		p.consecutiveErrors = 0 // Reset on success
		return nil
	}

	p.logger.Info("applying new policies: %s (previous: %s, sha256: %s...)", newDisplayName, currentDisplayName, shortHash(resp.Sha256))

	if err := p.applyPolicies(ctx, resp); err != nil {
		if shouldBackoffForError(err) {
			p.consecutiveErrors++
		} else {
			p.consecutiveErrors = 0
		}
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
		// Some policy operations may have succeeded even though others
		// failed. Refresh the local inventory from Tetragon so we don't
		// keep trying to re-add policies that are already loaded.
		p.logger.Warn("failed to apply some policy changes, refreshing inventory from Tetragon: %v", err)
		if seedErr := p.SeedInventoryFromTetragon(ctx); seedErr != nil {
			p.logger.Warn("failed to refresh policy inventory after error: %v", seedErr)
		}
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
	p.cache.SetPolicyCount(resp.PolicyCount)
}
