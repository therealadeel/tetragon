package apiclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/cilium/tetragon/contrib/control-plane-client/config"
	"github.com/cilium/tetragon/contrib/control-plane-client/logger"
	"github.com/cilium/tetragon/contrib/control-plane-client/retry"
	"github.com/cilium/tetragon/contrib/control-plane-client/types"
)

type Client struct {
	baseURL    string
	authToken  string
	httpClient *http.Client
	retryer    *retry.Retryer
	logger     logger.Logger
}

// NewClient creates a new API client with configurable HTTP client
func NewClient(cfg config.ManagementAPIConfig, log logger.Logger) *Client {
	return NewClientWithHTTPClient(cfg, log, nil)
}

// NewClientWithHTTPClient creates a new API client with a custom HTTP client
func NewClientWithHTTPClient(cfg config.ManagementAPIConfig, log logger.Logger, httpClient *http.Client) *Client {
	if httpClient == nil {
		// Create default HTTP client with configured transport
		transport := &http.Transport{
			MaxIdleConns:        cfg.HTTPClient.MaxIdleConns,
			MaxIdleConnsPerHost: cfg.HTTPClient.MaxIdleConnsPerHost,
			IdleConnTimeout:     cfg.HTTPClient.IdleConnTimeout,
			TLSHandshakeTimeout: cfg.HTTPClient.TLSHandshakeTimeout,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: cfg.HTTPClient.InsecureSkipTLSVerify,
			},
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		}

		httpClient = &http.Client{
			Timeout:   cfg.Timeout,
			Transport: transport,
		}
	}

	return &Client{
		baseURL:    cfg.BaseURL,
		authToken:  cfg.AuthToken,
		httpClient: httpClient,
		retryer:    retry.NewRetryer(cfg.Retry, log),
		logger:     log,
	}
}

func (c *Client) Register(ctx context.Context, req types.RegistrationRequest) (*types.RegistrationResponse, error) {
	var response types.RegistrationResponse

	err := c.retryer.DoHTTP(ctx, func(ctx context.Context) (int, error) {
		jsonData, err := json.Marshal(req)
		if err != nil {
			return 0, fmt.Errorf("failed to marshal registration request: %w", err)
		}

		httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/clients/register", bytes.NewBuffer(jsonData))
		if err != nil {
			return 0, fmt.Errorf("failed to create request: %w", err)
		}
		httpReq.Header.Set("Content-Type", "application/json")
		if c.authToken != "" {
			httpReq.Header.Set("Authorization", "Bearer "+c.authToken)
		}

		resp, err := c.httpClient.Do(httpReq)
		if err != nil {
			return 0, fmt.Errorf("failed to send request: %w", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return resp.StatusCode, fmt.Errorf("failed to read response: %w", err)
		}

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
			return resp.StatusCode, fmt.Errorf("registration failed: %s", string(body))
		}

		if err := json.Unmarshal(body, &response); err != nil {
			return resp.StatusCode, fmt.Errorf("failed to unmarshal response: %w", err)
		}

		return resp.StatusCode, nil
	})

	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (c *Client) GetPolicies(ctx context.Context, clientID string) (*types.PoliciesResponse, error) {
	var response types.PoliciesResponse

	err := c.retryer.DoHTTP(ctx, func(ctx context.Context) (int, error) {
		url := fmt.Sprintf("%s/clients/%s/policies", c.baseURL, clientID)
		httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return 0, fmt.Errorf("failed to create request: %w", err)
		}
		if c.authToken != "" {
			httpReq.Header.Set("Authorization", "Bearer "+c.authToken)
		}

		resp, err := c.httpClient.Do(httpReq)
		if err != nil {
			return 0, fmt.Errorf("failed to send request: %w", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return resp.StatusCode, fmt.Errorf("failed to read response: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			return resp.StatusCode, fmt.Errorf("get policies failed: %s", string(body))
		}

		if err := json.Unmarshal(body, &response); err != nil {
			return resp.StatusCode, fmt.Errorf("failed to unmarshal response: %w", err)
		}

		return resp.StatusCode, nil
	})

	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (c *Client) ReportHealth(ctx context.Context, clientID string, report types.HealthReport) error {
	if report.Timestamp.IsZero() {
		report.Timestamp = time.Now()
	}

	err := c.retryer.DoHTTP(ctx, func(ctx context.Context) (int, error) {
		jsonData, err := json.Marshal(report)
		if err != nil {
			return 0, fmt.Errorf("failed to marshal health report: %w", err)
		}

		url := fmt.Sprintf("%s/clients/%s/health", c.baseURL, clientID)
		httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
		if err != nil {
			return 0, fmt.Errorf("failed to create request: %w", err)
		}
		httpReq.Header.Set("Content-Type", "application/json")
		if c.authToken != "" {
			httpReq.Header.Set("Authorization", "Bearer "+c.authToken)
		}

		resp, err := c.httpClient.Do(httpReq)
		if err != nil {
			return 0, fmt.Errorf("failed to send request: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
			body, _ := io.ReadAll(resp.Body)
			return resp.StatusCode, fmt.Errorf("health report failed: %s", string(body))
		}

		return resp.StatusCode, nil
	})

	return err
}
