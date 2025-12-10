package client

import (
	"context"

	"github.com/cilium/tetragon/contrib/control-plane-client/apiclient"
	"github.com/cilium/tetragon/contrib/control-plane-client/cache"
	cperrors "github.com/cilium/tetragon/contrib/control-plane-client/errors"
	"github.com/cilium/tetragon/contrib/control-plane-client/logger"
	"github.com/cilium/tetragon/contrib/control-plane-client/metadata"
	"github.com/cilium/tetragon/contrib/control-plane-client/types"
)

// RegistrationManager handles client registration with the management API
type RegistrationManager struct {
	apiClient apiclient.ClientInterface
	cache     *cache.Cache
	collector metadata.CollectorInterface
	logger    logger.Logger
	config    RegistrationConfig
}

// RegistrationConfig holds registration-specific configuration
type RegistrationConfig struct {
	Environment    string
	DeploymentType string
	Tags           []string
}

// NewRegistrationManager creates a new registration manager
func NewRegistrationManager(
	apiClient apiclient.ClientInterface,
	cache *cache.Cache,
	collector metadata.CollectorInterface,
	logger logger.Logger,
	config RegistrationConfig,
) *RegistrationManager {
	return &RegistrationManager{
		apiClient: apiClient,
		cache:     cache,
		collector: collector,
		logger:    logger.WithField("component", "registration"),
		config:    config,
	}
}

// Register performs client registration, using cached client ID if available
func (r *RegistrationManager) Register(ctx context.Context) (string, error) {
	clientID := r.cache.GetClientID()
	if clientID != "" {
		r.logger.Info("using cached client ID: %s", clientID)
		return clientID, nil
	}

	r.logger.Info("registering with management API...")
	r.logger.Debug("starting registration with retry logic")

	hostname, err := r.collector.GetHostname()
	if err != nil {
		return "", cperrors.NewMetadataError("failed to get hostname", err)
	}

	instanceID, err := r.collector.GetInstanceID(ctx)
	if err != nil {
		return "", cperrors.NewMetadataError("failed to get instance ID", err)
	}

	ipAddress, err := r.collector.GetIPAddress()
	if err != nil {
		return "", cperrors.NewMetadataError("failed to get IP address", err)
	}

	r.logger.Debug("registration metadata: hostname=%s, instance_id=%s, ip=%s, env=%s, arch=%s, tags=%v",
		hostname, instanceID, ipAddress, r.config.Environment,
		r.collector.GetArchitecture(), r.config.Tags)

	req := types.RegistrationRequest{
		Hostname:       hostname,
		InstanceID:     instanceID,
		Environment:    r.config.Environment,
		Architecture:   r.collector.GetArchitecture(),
		IPAddress:      ipAddress,
		DeploymentType: r.config.DeploymentType,
		Tags:           r.config.Tags,
	}

	resp, err := r.apiClient.Register(ctx, req)
	if err != nil {
		return "", cperrors.NewAPIError("registration failed", 0, err)
	}

	r.logger.Debug("registration successful, received client ID: %s", resp.ClientID)

	clientID = resp.ClientID
	r.cache.SetClientID(clientID)

	r.logger.Info("successfully registered with client ID: %s", clientID)
	return clientID, nil
}

// NewMetadataError creates a metadata-related error (added to errors package)
func NewMetadataError(message string, err error) *cperrors.ControlPlaneError {
	return cperrors.NewError(cperrors.ErrorTypeMetadata, message, err)
}
