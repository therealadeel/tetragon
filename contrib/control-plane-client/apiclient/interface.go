package apiclient

import (
	"context"

	"github.com/cilium/tetragon/contrib/control-plane-client/types"
)

// ClientInterface defines the interface for management API operations
type ClientInterface interface {
	Register(ctx context.Context, req types.RegistrationRequest) (*types.RegistrationResponse, error)
	GetPolicies(ctx context.Context, clientID string) (*types.PoliciesResponse, error)
	ReportHealth(ctx context.Context, clientID string, report types.HealthReport) error
	PublishMetrics(ctx context.Context, clientID string, report types.MetricsReport) error
}
