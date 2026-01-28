package client

import (
	"context"
	"net/http"
	"time"

	"github.com/cilium/tetragon/contrib/control-plane-client/apiclient"
	"github.com/cilium/tetragon/contrib/control-plane-client/cache"
	cperrors "github.com/cilium/tetragon/contrib/control-plane-client/errors"
	"github.com/cilium/tetragon/contrib/control-plane-client/logger"
	"github.com/cilium/tetragon/contrib/control-plane-client/tetragon"
	"github.com/cilium/tetragon/contrib/control-plane-client/types"
)

// HealthReporter handles health reporting to the management API
type HealthReporter struct {
	apiClient         apiclient.ClientInterface
	tetragonClient    tetragon.ClientInterface
	cache             *cache.Cache
	logger            logger.Logger
	consecutiveErrors int
}

// NewHealthReporter creates a new health reporter
func NewHealthReporter(
	apiClient apiclient.ClientInterface,
	tetragonClient tetragon.ClientInterface,
	cache *cache.Cache,
	logger logger.Logger,
) *HealthReporter {
	return &HealthReporter{
		apiClient:      apiClient,
		tetragonClient: tetragonClient,
		cache:          cache,
		logger:         logger.WithField("component", "health_reporter"),
	}
}

// Report sends a health report to the management API
func (h *HealthReporter) Report(ctx context.Context, clientID string) error {
	h.logger.Debug("reporting health...")

	version, err := h.getTetragonVersion(ctx)
	if err != nil {
		h.logger.Warn("failed to get Tetragon version: %v", err)
		version = "unknown"
	}

	statuses, err := h.tetragonClient.GetPolicyStatuses(ctx)
	if err != nil {
		h.consecutiveErrors++
		return cperrors.NewTetragonError("failed to get policy statuses", err)
	}

	report := h.buildHealthReport(statuses, version)

	h.logger.Info("sending health report to management API: client_id=%s, status=%s, policy_display_name=%s, policy_sha256=%s..., tetragon_version=%s, policies_count=%d",
		clientID, report.Status, report.PolicyDisplayName, shortHash(report.PolicySha256), report.TetragonVersion, len(report.Policies))

	if err := h.apiClient.ReportHealth(ctx, clientID, report); err != nil {
		h.consecutiveErrors++
		return cperrors.NewAPIError("failed to report health", 0, err)
	}

	h.logger.Info("health report successfully sent: status=%s, policies=%d", report.Status, len(report.Policies))
	h.consecutiveErrors = 0 // Reset on success
	return nil
}

// GetConsecutiveErrors returns the number of consecutive health report errors
func (h *HealthReporter) GetConsecutiveErrors() int {
	return h.consecutiveErrors
}

func (h *HealthReporter) getTetragonVersion(ctx context.Context) (string, error) {
	return h.tetragonClient.GetVersion(ctx)
}

func (h *HealthReporter) buildHealthReport(statuses []types.PolicyStatus, tetragonVersion string) types.HealthReport {
	report := types.HealthReport{
		Timestamp:         time.Now(),
		Status:            "healthy",
		PolicyDisplayName: h.cache.GetPolicyDisplayName(),
		PolicySha256:      h.cache.GetPolicySha256(),
		TetragonVersion:   tetragonVersion,
		Policies:          statuses,
	}

	for i, status := range statuses {
		h.logger.Debug("policy %d: name=%s, state=%s, error=%s", i, status.Name, status.State, status.Error)
		if status.State != "TP_STATE_ENABLED" {
			h.logger.Warn("policy %s state is %s (not TP_STATE_ENABLED), marking as degraded", status.Name, status.State)
			report.Status = "degraded"
		}
	}

	expected := h.cache.GetPolicyCount()
	actual := len(statuses)
	if expected > 0 && actual != expected && report.Status == "healthy" {
		h.logger.Warn("policy count mismatch: expected=%d, actual=%d; marking as degraded", expected, actual)
		report.Status = "degraded"
	}

	if syncErr, ok := h.cache.GetPolicySyncError(); ok && syncErr.StatusCode == http.StatusNotFound {
		if report.Status == "healthy" {
			h.logger.Warn("policy sync returned HTTP %d (%s); marking as degraded", syncErr.StatusCode, syncErr.Message)
		}
		report.Status = "degraded"
	}

	return report
}
