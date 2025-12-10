package tetragon

import (
	"context"

	tetragonapi "github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/contrib/control-plane-client/types"
)

// ClientInterface defines the interface for Tetragon gRPC client operations
type ClientInterface interface {
	Connect(ctx context.Context) error
	Close() error
	GetVersion(ctx context.Context) (string, error)
	ListPolicies(ctx context.Context) ([]*tetragonapi.TracingPolicyStatus, error)
	AddPolicy(ctx context.Context, yamlContent string) error
	DeletePolicy(ctx context.Context, name, namespace string) error
	DeleteAllPolicies(ctx context.Context) error
	ApplyPoliciesFromBase64(ctx context.Context, base64Content string) error
	GetPolicyStatuses(ctx context.Context) ([]types.PolicyStatus, error)
}
