package cache

import (
	"sync"
	"time"

	"github.com/cilium/tetragon/contrib/control-plane-client/policy"
)

type PolicySyncError struct {
	StatusCode int
	Message    string
	Timestamp  time.Time
}

type Cache struct {
	mu                sync.RWMutex
	clientID          string
	policyDisplayName string
	policySha256      string
	policyInventory   map[string]policy.Metadata // key -> metadata
	policyCount       int
	policySyncError   *PolicySyncError
}

func NewCache() *Cache {
	return &Cache{}
}

func (c *Cache) GetClientID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.clientID
}

func (c *Cache) SetClientID(clientID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clientID = clientID
}

func (c *Cache) GetPolicyDisplayName() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.policyDisplayName
}

func (c *Cache) SetPolicyDisplayName(displayName string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.policyDisplayName = displayName
}

func (c *Cache) GetPolicySha256() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.policySha256
}

func (c *Cache) SetPolicySha256(sha256 string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.policySha256 = sha256
}

func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clientID = ""
	c.policyDisplayName = ""
	c.policySha256 = ""
	c.policyInventory = nil
	c.policyCount = 0
	c.policySyncError = nil
}

func (c *Cache) GetPolicyCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.policyCount
}

func (c *Cache) SetPolicyCount(count int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.policyCount = count
}

func (c *Cache) GetPolicyInventory() map[string]policy.Metadata {
	c.mu.RLock()
	defer c.mu.RUnlock()
	// Return a copy to avoid race conditions
	inventory := make(map[string]policy.Metadata, len(c.policyInventory))
	for k, v := range c.policyInventory {
		inventory[k] = v
	}
	return inventory
}

func (c *Cache) SetPolicyInventory(inventory map[string]policy.Metadata) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.policyInventory = make(map[string]policy.Metadata, len(inventory))
	for k, v := range inventory {
		c.policyInventory[k] = v
	}
}

func (c *Cache) GetPolicySyncError() (PolicySyncError, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.policySyncError == nil {
		return PolicySyncError{}, false
	}
	return *c.policySyncError, true
}

func (c *Cache) SetPolicySyncError(err PolicySyncError) {
	c.mu.Lock()
	defer c.mu.Unlock()
	copy := err
	c.policySyncError = &copy
}

func (c *Cache) ClearPolicySyncError() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.policySyncError = nil
}
