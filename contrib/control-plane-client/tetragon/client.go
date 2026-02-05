package tetragon

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"gopkg.in/yaml.v3"

	tetragonapi "github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/contrib/control-plane-client/config"
	"github.com/cilium/tetragon/contrib/control-plane-client/types"
)

type Client struct {
	address string
	timeout time.Duration
	mu      sync.Mutex
	conn    *grpc.ClientConn
	client  tetragonapi.FineGuidanceSensorsClient
}

func NewClient(cfg config.TetragonConfig) (*Client, error) {
	return &Client{
		address: cfg.ServerAddress,
		timeout: cfg.Timeout,
	}, nil
}

func (c *Client) Connect(ctx context.Context) error {
	return c.ensureConnected(ctx)
}

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		c.client = nil
		return err
	}
	return nil
}

func (c *Client) GetVersion(ctx context.Context) (string, error) {
	if err := c.ensureConnected(ctx); err != nil {
		return "", err
	}
	callCtx, cancel := c.withTimeout(ctx)
	defer cancel()

	resp, err := c.client.GetVersion(callCtx, &tetragonapi.GetVersionRequest{})
	if err != nil {
		return "", fmt.Errorf("failed to get version: %w", err)
	}
	return resp.Version, nil
}

func (c *Client) ListPolicies(ctx context.Context) ([]*tetragonapi.TracingPolicyStatus, error) {
	if err := c.ensureConnected(ctx); err != nil {
		return nil, err
	}
	callCtx, cancel := c.withTimeout(ctx)
	defer cancel()

	resp, err := c.client.ListTracingPolicies(callCtx, &tetragonapi.ListTracingPoliciesRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to list tracing policies: %w", err)
	}
	return resp.Policies, nil
}

func (c *Client) AddPolicy(ctx context.Context, yamlContent string) error {
	if err := c.ensureConnected(ctx); err != nil {
		return err
	}
	callCtx, cancel := c.withTimeout(ctx)
	defer cancel()

	_, err := c.client.AddTracingPolicy(callCtx, &tetragonapi.AddTracingPolicyRequest{
		Yaml: yamlContent,
	})
	if err != nil {
		return fmt.Errorf("failed to add tracing policy: %w", err)
	}
	return nil
}

func (c *Client) DeletePolicy(ctx context.Context, name, namespace string) error {
	if err := c.ensureConnected(ctx); err != nil {
		return err
	}
	callCtx, cancel := c.withTimeout(ctx)
	defer cancel()

	_, err := c.client.DeleteTracingPolicy(callCtx, &tetragonapi.DeleteTracingPolicyRequest{
		Name:      name,
		Namespace: namespace,
	})
	if err != nil {
		return fmt.Errorf("failed to delete tracing policy %s: %w", name, err)
	}
	return nil
}

func (c *Client) DeleteAllPolicies(ctx context.Context) error {
	policies, err := c.ListPolicies(ctx)
	if err != nil {
		return fmt.Errorf("failed to list policies for deletion: %w", err)
	}

	var errors []string
	for _, policy := range policies {
		if err := c.DeletePolicy(ctx, policy.Name, policy.Namespace); err != nil {
			errors = append(errors, fmt.Sprintf("%s/%s: %v", policy.Namespace, policy.Name, err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to delete some policies: %s", strings.Join(errors, "; "))
	}

	return nil
}

func (c *Client) ApplyPoliciesFromBase64(ctx context.Context, base64Content string) error {
	yamlBytes, err := base64.StdEncoding.DecodeString(base64Content)
	if err != nil {
		return fmt.Errorf("failed to decode base64 policies: %w", err)
	}

	yamlDocs := strings.Split(string(yamlBytes), "\n---\n")

	var errors []string
	for i, yamlDoc := range yamlDocs {
		yamlDoc = strings.TrimSpace(yamlDoc)
		if yamlDoc == "" {
			continue
		}

		var policy types.TracingPolicyDoc
		if err := yaml.Unmarshal([]byte(yamlDoc), &policy); err != nil {
			errors = append(errors, fmt.Sprintf("doc %d: failed to parse: %v", i, err))
			continue
		}

		if err := c.AddPolicy(ctx, yamlDoc); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", policy.Metadata.Name, err))
			continue
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to apply some policies: %s", strings.Join(errors, "; "))
	}

	return nil
}

func (c *Client) GetPolicyStatuses(ctx context.Context) ([]types.PolicyStatus, error) {
	policies, err := c.ListPolicies(ctx)
	if err != nil {
		return nil, err
	}

	statuses := make([]types.PolicyStatus, 0, len(policies))
	for _, policy := range policies {
		statuses = append(statuses, types.PolicyStatus{
			Name:      policy.Name,
			Namespace: policy.Namespace,
			State:     policy.State.String(),
			Error:     policy.Error,
		})
	}

	return statuses, nil
}

func (c *Client) ensureConnected(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.client != nil {
		return nil
	}

	dialCtx, cancel := c.withTimeout(ctx)
	defer cancel()

	conn, err := grpc.DialContext(
		dialCtx,
		c.address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return fmt.Errorf("failed to connect to Tetragon at %s: %w", c.address, err)
	}

	c.conn = conn
	c.client = tetragonapi.NewFineGuidanceSensorsClient(conn)
	return nil
}

func (c *Client) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if c.timeout <= 0 {
		return ctx, func() {}
	}
	if deadline, ok := ctx.Deadline(); ok {
		if time.Until(deadline) <= c.timeout {
			return ctx, func() {}
		}
	}
	return context.WithTimeout(ctx, c.timeout)
}
