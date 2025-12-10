package types

import "time"

// RegistrationRequest represents the client registration payload
type RegistrationRequest struct {
	Hostname     string   `json:"hostname"`
	InstanceID   string   `json:"instance_id"`
	Environment  string   `json:"environment"`
	Architecture string   `json:"architecture"`
	IPAddress    string   `json:"ip_address"`
	Tags         []string `json:"tags"`
}

// RegistrationResponse represents the response from client registration
type RegistrationResponse struct {
	ClientID string `json:"client_id"`
}

// PoliciesResponse represents the response from the policies endpoint
type PoliciesResponse struct {
	Version  string `json:"version"`
	Policies string `json:"policies"` // base64-encoded YAML
	Sha256   string `json:"sha256"`   // SHA256 hash of the policies content
}

// PolicyStatus represents the status of a single tracing policy
type PolicyStatus struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	State     string `json:"state"`
	Error     string `json:"error"`
}

// HealthReport represents the health status report
type HealthReport struct {
	Status          string         `json:"status"`
	PolicyVersion   string         `json:"policy_version"`
	PolicySha256    string         `json:"policy_sha256"`
	TetragonVersion string         `json:"tetragon_version"`
	Policies        []PolicyStatus `json:"policies"`
	Timestamp       time.Time      `json:"timestamp"`
}

// TracingPolicyMetadata represents metadata from a tracing policy YAML
type TracingPolicyMetadata struct {
	Name      string `yaml:"name"`
	Namespace string `yaml:"namespace,omitempty"`
}

// TracingPolicyDoc represents a tracing policy document
type TracingPolicyDoc struct {
	APIVersion string                 `yaml:"apiVersion"`
	Kind       string                 `yaml:"kind"`
	Metadata   TracingPolicyMetadata  `yaml:"metadata"`
	Spec       map[string]interface{} `yaml:"spec"`
}
