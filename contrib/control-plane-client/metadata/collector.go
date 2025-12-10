package metadata

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
)

type Collector struct {
	useIMDS     bool
	imdsTimeout time.Duration
}

func NewCollector(useIMDS bool, imdsTimeout time.Duration) *Collector {
	return &Collector{
		useIMDS:     useIMDS,
		imdsTimeout: imdsTimeout,
	}
}

func (c *Collector) GetHostname() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("failed to get hostname: %w", err)
	}
	return hostname, nil
}

func (c *Collector) GetInstanceID(ctx context.Context) (string, error) {
	if c.useIMDS {
		instanceID, err := c.getIMDSv2InstanceID(ctx)
		if err == nil && instanceID != "" {
			return instanceID, nil
		}
	}

	return c.getHostID()
}

func (c *Collector) getIMDSv2InstanceID(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, c.imdsTimeout)
	defer cancel()

	tokenURL := "http://169.254.169.254/latest/api/token"
	tokenReq, err := http.NewRequestWithContext(ctx, "PUT", tokenURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}
	tokenReq.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")

	client := &http.Client{Timeout: c.imdsTimeout}
	tokenResp, err := client.Do(tokenReq)
	if err != nil {
		return "", fmt.Errorf("failed to get IMDS token: %w", err)
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("IMDS token request failed with status: %d", tokenResp.StatusCode)
	}

	tokenBytes, err := io.ReadAll(tokenResp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read IMDS token: %w", err)
	}
	token := string(tokenBytes)

	instanceIDURL := "http://169.254.169.254/latest/meta-data/instance-id"
	instanceReq, err := http.NewRequestWithContext(ctx, "GET", instanceIDURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create instance-id request: %w", err)
	}
	instanceReq.Header.Set("X-aws-ec2-metadata-token", token)

	instanceResp, err := client.Do(instanceReq)
	if err != nil {
		return "", fmt.Errorf("failed to get instance-id: %w", err)
	}
	defer instanceResp.Body.Close()

	if instanceResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("instance-id request failed with status: %d", instanceResp.StatusCode)
	}

	instanceIDBytes, err := io.ReadAll(instanceResp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read instance-id: %w", err)
	}

	return strings.TrimSpace(string(instanceIDBytes)), nil
}

func (c *Collector) getHostID() (string, error) {
	if data, err := os.ReadFile("/etc/machine-id"); err == nil {
		return strings.TrimSpace(string(data)), nil
	}

	if data, err := os.ReadFile("/var/lib/dbus/machine-id"); err == nil {
		return strings.TrimSpace(string(data)), nil
	}

	hostname, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("failed to get fallback hostid: %w", err)
	}
	return hostname, nil
}

func (c *Collector) GetArchitecture() string {
	return runtime.GOARCH
}

func (c *Collector) GetIPAddress() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", fmt.Errorf("failed to get network interfaces: %w", err)
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String(), nil
			}
		}
	}

	return "", fmt.Errorf("no non-loopback IPv4 address found")
}
