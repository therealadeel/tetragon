package cache

import (
	"sync"

	"github.com/cilium/tetragon/contrib/control-plane-client/policy"
)

type Cache struct {
	mu              sync.RWMutex
	clientID        string
	policyVersion   string
	policySha256    string
	policyInventory map[string]policy.Metadata // key -> metadata
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

func (c *Cache) GetPolicyVersion() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.policyVersion
}

func (c *Cache) SetPolicyVersion(version string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.policyVersion = version
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
	c.policyVersion = ""
	c.policySha256 = ""
	c.policyInventory = nil
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
