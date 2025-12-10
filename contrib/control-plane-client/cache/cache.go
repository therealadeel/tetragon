package cache

import (
	"sync"
)

type Cache struct {
	mu            sync.RWMutex
	clientID      string
	policyVersion string
	policySha256  string
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
	return nil
}
