package metadata

import (
	"context"
)

// CollectorInterface defines the interface for system metadata collection
type CollectorInterface interface {
	GetHostname() (string, error)
	GetInstanceID(ctx context.Context) (string, error)
	GetIPAddress() (string, error)
	GetArchitecture() string
}
