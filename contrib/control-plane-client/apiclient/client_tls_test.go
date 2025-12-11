package apiclient

import (
	"crypto/tls"
	"net/http"
	"testing"
	"time"

	"github.com/cilium/tetragon/contrib/control-plane-client/config"
	"github.com/cilium/tetragon/contrib/control-plane-client/logger"
)

func TestNewClient_InsecureSkipVerify(t *testing.T) {
	cfg := config.ManagementAPIConfig{
		BaseURL:   "https://example.com",
		AuthToken: "test-token",
		Timeout:   30 * time.Second,
		HTTPClient: config.HTTPClientConfig{
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			InsecureSkipTLSVerify: true,
		},
		Retry: config.RetryConfig{
			MaxAttempts:    3,
			InitialBackoff: 1 * time.Second,
			MaxBackoff:     10 * time.Second,
		},
	}

	log := logger.NewStandardLogger("info")
	client := NewClient(cfg, log)

	if client == nil {
		t.Fatal("Expected client to be created")
	}

	transport, ok := client.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatal("Expected http.Transport")
	}

	if transport.TLSClientConfig == nil {
		t.Fatal("Expected TLSClientConfig to be set")
	}

	if !transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("Expected InsecureSkipVerify to be true")
	}
}

func TestNewClient_SecureByDefault(t *testing.T) {
	cfg := config.ManagementAPIConfig{
		BaseURL:   "https://example.com",
		AuthToken: "test-token",
		Timeout:   30 * time.Second,
		HTTPClient: config.HTTPClientConfig{
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			InsecureSkipTLSVerify: false,
		},
		Retry: config.RetryConfig{
			MaxAttempts:    3,
			InitialBackoff: 1 * time.Second,
			MaxBackoff:     10 * time.Second,
		},
	}

	log := logger.NewStandardLogger("info")
	client := NewClient(cfg, log)

	transport, ok := client.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatal("Expected http.Transport")
	}

	if transport.TLSClientConfig == nil {
		t.Fatal("Expected TLSClientConfig to be set")
	}

	if transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("Expected InsecureSkipVerify to be false by default")
	}
}

func TestNewClient_CustomHTTPClient(t *testing.T) {
	cfg := config.ManagementAPIConfig{
		BaseURL:   "https://example.com",
		AuthToken: "test-token",
		Timeout:   30 * time.Second,
		HTTPClient: config.HTTPClientConfig{
			InsecureSkipTLSVerify: true,
		},
	}

	log := logger.NewStandardLogger("info")

	customTransport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
		},
	}
	customClient := &http.Client{
		Transport: customTransport,
	}

	client := NewClientWithHTTPClient(cfg, log, customClient)

	transport, ok := client.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatal("Expected http.Transport")
	}

	if transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("Expected custom client TLS config to be preserved (false)")
	}
}
