package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/cilium/tetragon/contrib/control-plane-client/apiclient"
	"github.com/cilium/tetragon/contrib/control-plane-client/cache"
	cperrors "github.com/cilium/tetragon/contrib/control-plane-client/errors"
	"github.com/cilium/tetragon/contrib/control-plane-client/logger"
	"github.com/cilium/tetragon/contrib/control-plane-client/types"
)

// MetricsPublisher is responsible for collecting and publishing Prometheus metrics to the management API.
type MetricsPublisher struct {
	apiClient         apiclient.ClientInterface
	cache             *cache.Cache
	logger            logger.Logger
	httpClient        *http.Client
	cfg               MetricsPublisherConfig
	consecutiveErrors int
}

// MetricsPublisherConfig captures runtime settings for the metrics publisher.
type MetricsPublisherConfig struct {
	Endpoint              string
	Format                string
	RequestTimeout        time.Duration
	InsecureSkipTLSVerify bool
}

// NewMetricsPublisher sets up a new metrics publisher with its own HTTP client for scraping endpoints.
func NewMetricsPublisher(apiClient apiclient.ClientInterface, cache *cache.Cache, log logger.Logger, cfg MetricsPublisherConfig) *MetricsPublisher {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.InsecureSkipTLSVerify,
		},
	}

	return &MetricsPublisher{
		apiClient:  apiClient,
		cache:      cache,
		logger:     log.WithField("component", "metrics_publisher"),
		cfg:        cfg,
		httpClient: &http.Client{Timeout: cfg.RequestTimeout, Transport: transport},
	}
}

// Publish collects metrics from the configured endpoint and posts them to the management API.
func (m *MetricsPublisher) Publish(ctx context.Context, clientID string) error {
	payload, err := m.scrapeMetrics(ctx)
	if err != nil {
		m.logger.Warn("failed to scrape metrics: %v", err)
		if m.cache != nil {
			m.cache.SetMetricsScrapeError(cache.MetricsScrapeError{
				Message:   err.Error(),
				Timestamp: time.Now(),
			})
		}
		payload = ""
	} else if m.cache != nil {
		m.cache.ClearMetricsScrapeError()
	}

	report := types.MetricsReport{
		Format:    m.cfg.Format,
		Endpoint:  m.cfg.Endpoint,
		Payload:   payload,
		Timestamp: time.Now(),
	}

	m.logger.Info("sending metrics report to management API: client_id=%s, endpoint=%s, payload_bytes=%d",
		clientID, m.cfg.Endpoint, len(report.Payload))

	if err := m.apiClient.PublishMetrics(ctx, clientID, report); err != nil {
		m.consecutiveErrors++
		return cperrors.NewAPIError("failed to publish metrics", 0, err)
	}

	m.logger.Debug("metrics report successfully sent: endpoint=%s, payload_bytes=%d", m.cfg.Endpoint, len(report.Payload))
	m.consecutiveErrors = 0
	return nil
}

// GetConsecutiveErrors returns the number of consecutive publishing failures.
func (m *MetricsPublisher) GetConsecutiveErrors() int {
	return m.consecutiveErrors
}

func (m *MetricsPublisher) scrapeMetrics(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.cfg.Endpoint, nil)
	if err != nil {
		return "", cperrors.NewNetworkError("failed to create metrics request", err)
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return "", cperrors.NewNetworkError("failed to collect metrics", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", cperrors.NewNetworkError(
			fmt.Sprintf("metrics endpoint returned status %d: %s", resp.StatusCode, string(body)), nil)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", cperrors.NewNetworkError("failed to read metrics payload", err)
	}

	return string(data), nil
}
