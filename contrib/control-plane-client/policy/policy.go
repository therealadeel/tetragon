package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Document represents a single TracingPolicy document
type Document struct {
	Name      string
	Namespace string
	Content   string // Original YAML content
	Hash      string // SHA256 hash of content
}

// Diff represents the changes needed to sync policies
type Diff struct {
	ToAdd    []Document
	ToUpdate []Document
	ToDelete []string // policy names (namespace/name format if namespace is set)
}

// Metadata represents minimal policy information for tracking
type Metadata struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Hash      string `json:"hash"`
}

// parsePolicy extracts name and namespace from a policy YAML document
type policyMeta struct {
	Metadata struct {
		Name      string `yaml:"name"`
		Namespace string `yaml:"namespace"`
	} `yaml:"metadata"`
}

// ParsePolicies parses a multi-document YAML string into individual policy documents
func ParsePolicies(yamlContent string) ([]Document, error) {
	var documents []Document

	// Split on document separator
	yamls := strings.Split(yamlContent, "\n---")

	for _, y := range yamls {
		y = strings.TrimSpace(y)
		if y == "" || y == "---" {
			continue
		}

		// Parse to extract metadata
		var meta policyMeta
		if err := yaml.Unmarshal([]byte(y), &meta); err != nil {
			return nil, fmt.Errorf("failed to parse policy metadata: %w", err)
		}

		if meta.Metadata.Name == "" {
			continue // Skip documents without a name
		}

		// Compute hash of the content
		hash := sha256.Sum256([]byte(y))
		hashStr := hex.EncodeToString(hash[:])

		doc := Document{
			Name:      meta.Metadata.Name,
			Namespace: meta.Metadata.Namespace,
			Content:   y,
			Hash:      hashStr,
		}

		documents = append(documents, doc)
	}

	return documents, nil
}

// Key returns the unique identifier for a policy (namespace/name or just name)
func (d *Document) Key() string {
	if d.Namespace != "" {
		return d.Namespace + "/" + d.Name
	}
	return d.Name
}

// ComputeDiff calculates the difference between current and desired policy states
// Optimized to pre-allocate slices based on potential maximum size and reuse desired map
func ComputeDiff(current map[string]Metadata, desired []Document) *Diff {
	// Pre-allocate slices with reasonable capacity to reduce reallocations
	// Worst case: all desired are new (ToAdd), all current are deleted (ToDelete)
	diff := &Diff{
		ToAdd:    make([]Document, 0, len(desired)),
		ToUpdate: make([]Document, 0, len(desired)/2), // Assume ~50% updates in worst case
		ToDelete: make([]string, 0, len(current)),
	}

	// Build map of desired policies for O(1) lookup
	// Reuse this map structure instead of rebuilding
	desiredMap := make(map[string]Document, len(desired))
	for i := range desired {
		// Use index to avoid copying struct
		doc := &desired[i]
		desiredMap[doc.Key()] = *doc
	}

	// Find policies to add or update (single pass through desired)
	for key, desiredDoc := range desiredMap {
		if currentMeta, exists := current[key]; !exists {
			// Policy doesn't exist, add it
			diff.ToAdd = append(diff.ToAdd, desiredDoc)
		} else if currentMeta.Hash != desiredDoc.Hash {
			// Policy exists but content changed, update it
			diff.ToUpdate = append(diff.ToUpdate, desiredDoc)
		}
		// else: Policy exists and hasn't changed, no action needed
	}

	// Find policies to delete (single pass through current)
	for key := range current {
		if _, exists := desiredMap[key]; !exists {
			diff.ToDelete = append(diff.ToDelete, key)
		}
	}

	return diff
}

// IsEmpty returns true if the diff has no changes
func (d *Diff) IsEmpty() bool {
	return len(d.ToAdd) == 0 && len(d.ToUpdate) == 0 && len(d.ToDelete) == 0
}

// Summary returns a human-readable summary of the diff
func (d *Diff) Summary() string {
	return fmt.Sprintf("add=%d, update=%d, delete=%d", len(d.ToAdd), len(d.ToUpdate), len(d.ToDelete))
}
