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

func (c *Cache) GetClientID() (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.clientID, nil
}

func (c *Cache) SetClientID(clientID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clientID = clientID
	return nil
}

func (c *Cache) GetPolicyVersion() (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.policyVersion, nil
}

func (c *Cache) SetPolicyVersion(version string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.policyVersion = version
	return nil
}

func (c *Cache) GetPolicySha256() (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.policySha256, nil
}

func (c *Cache) SetPolicySha256(sha256 string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.policySha256 = sha256
	return nil
}

func (c *Cache) Clear() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clientID = ""
	c.policyVersion = ""
	c.policySha256 = ""
	c.policyInventory = nil
	return nil
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

func (c *Cache) SetPolicyInventory(inventory map[string]policy.Metadata) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.policyInventory = make(map[string]policy.Metadata, len(inventory))
	for k, v := range inventory {
		c.policyInventory[k] = v
	}
	return nil
}
