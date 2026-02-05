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

const (
	healthStatusHealthy                     = "healthy"
	healthStatusDegradedPolicyStateErr      = "degraded:policy_state_err"
	healthStatusDegradedPolicyCount         = "degraded:policy_count_mismatch"
	healthStatusDegradedPolicySyncMissing   = "degraded:policy_sync_not_found"
	healthStatusDegradedPolicyLoadErr       = "degraded:policy_load_err"
	healthStatusDegradedTetragonUnavailable = "degraded:tetragon_unavailable"
	healthStatusDegradedMetricsScrapeErr    = "degraded:metrics_scrape_err"
)

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

	statuses, statusErr := h.tetragonClient.GetPolicyStatuses(ctx)
	if statusErr != nil {
		h.logger.Warn("failed to get policy statuses: %v", statusErr)
		statuses = []types.PolicyStatus{}
	}

	report := h.buildHealthReport(statuses, version, statusErr)

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

func (h *HealthReporter) buildHealthReport(statuses []types.PolicyStatus, tetragonVersion string, statusErr error) types.HealthReport {
	report := types.HealthReport{
		Timestamp:         time.Now(),
		Status:            healthStatusHealthy,
		PolicyDisplayName: h.cache.GetPolicyDisplayName(),
		PolicySha256:      h.cache.GetPolicySha256(),
		TetragonVersion:   tetragonVersion,
		Policies:          statuses,
	}

	if loadErr, ok := h.cache.GetPolicyLoadError(); ok {
		h.logger.Warn("policy load error at %s: %s; marking as %s", loadErr.Timestamp.Format(time.RFC3339), loadErr.Message, healthStatusDegradedPolicyLoadErr)
		report.Status = healthStatusDegradedPolicyLoadErr
	}

	if statusErr != nil && report.Status == healthStatusHealthy {
		h.logger.Warn("tetragon policy status unavailable: %v; marking as %s", statusErr, healthStatusDegradedTetragonUnavailable)
		report.Status = healthStatusDegradedTetragonUnavailable
	}

	for i, status := range statuses {
		h.logger.Debug("policy %d: name=%s, state=%s, error=%s", i, status.Name, status.State, status.Error)
		if status.State != "TP_STATE_ENABLED" {
			if report.Status == healthStatusHealthy {
				h.logger.Warn("policy %s state is %s (not TP_STATE_ENABLED), marking as %s", status.Name, status.State, healthStatusDegradedPolicyStateErr)
				report.Status = healthStatusDegradedPolicyStateErr
			} else {
				h.logger.Warn("policy %s state is %s (not TP_STATE_ENABLED)", status.Name, status.State)
			}
		}
	}

	expected := h.cache.GetPolicyCount()
	actual := len(statuses)
	if expected > 0 && actual != expected && report.Status == healthStatusHealthy {
		h.logger.Warn("policy count mismatch: expected=%d, actual=%d; marking as %s", expected, actual, healthStatusDegradedPolicyCount)
		report.Status = healthStatusDegradedPolicyCount
	}

	if syncErr, ok := h.cache.GetPolicySyncError(); ok && syncErr.StatusCode == http.StatusNotFound {
		if report.Status == healthStatusHealthy {
			h.logger.Warn("policy sync returned HTTP %d (%s); marking as %s", syncErr.StatusCode, syncErr.Message, healthStatusDegradedPolicySyncMissing)
			report.Status = healthStatusDegradedPolicySyncMissing
		}
	}

	if metricsErr, ok := h.cache.GetMetricsScrapeError(); ok && report.Status == healthStatusHealthy {
		h.logger.Warn("metrics scrape error at %s: %s; marking as %s", metricsErr.Timestamp.Format(time.RFC3339), metricsErr.Message, healthStatusDegradedMetricsScrapeErr)
		report.Status = healthStatusDegradedMetricsScrapeErr
	}

	return report
}
