//go:build ignore
// +build ignore

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Authentication middleware
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get expected token from environment
		expectedToken := os.Getenv("API_AUTH_TOKEN")
		if expectedToken == "" {
			log.Println("Warning: API_AUTH_TOKEN not set, skipping authentication")
			next(w, r)
			return
		}

		// Extract Bearer token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			log.Println("Unauthorized: Missing Authorization header")
			http.Error(w, "Unauthorized: Missing Authorization header", http.StatusUnauthorized)
			return
		}

		// Check for Bearer prefix
		if !strings.HasPrefix(authHeader, "Bearer ") {
			log.Println("Unauthorized: Invalid Authorization header format")
			http.Error(w, "Unauthorized: Invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		// Extract and validate token
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token != expectedToken {
			log.Println("Unauthorized: Invalid token")
			http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
			return
		}

		log.Println("Authenticated request")
		next(w, r)
	}
}

type RegistrationRequest struct {
	Hostname     string   `json:"hostname"`
	InstanceID   string   `json:"instance_id"`
	Environment  string   `json:"environment"`
	Architecture string   `json:"architecture"`
	IPAddress    string   `json:"ip_address"`
	Tags         []string `json:"tags"`
}

type RegistrationResponse struct {
	ClientID string `json:"client_id"`
}

type PoliciesResponse struct {
	Version  string `json:"version"`
	Policies string `json:"policies"`
	Sha256   string `json:"sha256"`
}

// In-memory storage for client registrations (hostname+instance_id -> client_id)
var (
	clientRegistry   = make(map[string]string)
	clientRegistryMu sync.Mutex

	// Policy version tracking
	policyVersion    = 1
	policyVersionMu  sync.Mutex
	lastUpdateTime   = time.Now()
	hasVariantPolicy = false // Track if we added a variant policy
)

func main() {
	http.HandleFunc("/v1/clients/register", authMiddleware(handleRegister))
	http.HandleFunc("/v1/clients/", authMiddleware(handleClientRequests))

	log.Println("Mock Management API Server starting on :8080...")
	log.Println("Set API_AUTH_TOKEN environment variable to enable authentication")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	log.Printf("Registration: hostname=%s, instance_id=%s, env=%s, arch=%s, ip=%s, tags=%v",
		req.Hostname, req.InstanceID, req.Environment, req.Architecture, req.IPAddress, req.Tags)

	// Create a unique key based on hostname and instance_id
	clientKey := req.Hostname + "|" + req.InstanceID

	clientRegistryMu.Lock()
	clientID, exists := clientRegistry[clientKey]
	if !exists {
		// Generate new client ID for this unique client
		clientID = uuid.New().String()
		clientRegistry[clientKey] = clientID
		log.Printf("New client registered: %s -> %s", clientKey, clientID)
	} else {
		log.Printf("Returning existing client ID for: %s -> %s", clientKey, clientID)
	}
	clientRegistryMu.Unlock()

	resp := RegistrationResponse{
		ClientID: clientID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleClientRequests(w http.ResponseWriter, r *http.Request) {
	// Extract client ID from path
	path := r.URL.Path

	if r.Method == http.MethodGet && len(path) > 14 && path[len(path)-9:] == "/policies" {
		handleGetPolicies(w, r)
		return
	}

	if r.Method == http.MethodPost && len(path) > 14 && path[len(path)-7:] == "/health" {
		handleHealthReport(w, r)
		return
	}

	http.NotFound(w, r)
}

func handleGetPolicies(w http.ResponseWriter, r *http.Request) {
	// Read example policies from file
	yamlContent, err := os.ReadFile("example-policies.yaml")
	if err != nil {
		http.Error(w, "Failed to read policies", http.StatusInternalServerError)
		return
	}

	yamlString := string(yamlContent)

	// Randomly decide whether to inject a policy update (30% chance)
	// But only if at least 30 seconds have passed since last update
	policyVersionMu.Lock()
	shouldUpdate := false
	timeSinceUpdate := time.Since(lastUpdateTime)
	if timeSinceUpdate > 30*time.Second && rand.Float32() < 0.3 {
		shouldUpdate = true
		policyVersion++
		lastUpdateTime = time.Now()

		// Inject a timestamp annotation into the metadata to simulate policy updates
		timestamp := fmt.Sprintf("  annotations:\n    updated-at: \"%d\"\n", time.Now().Unix())

		// Find the first "metadata:" and inject after it
		metadataIndex := strings.Index(yamlString, "metadata:")
		if metadataIndex != -1 {
			// Find the end of the metadata line
			endOfLine := strings.Index(yamlString[metadataIndex:], "\n")
			if endOfLine != -1 {
				insertPos := metadataIndex + endOfLine + 1
				yamlString = yamlString[:insertPos] + timestamp + yamlString[insertPos:]
			}
		}

		// If we previously added a variant, remove it this time to simulate policy removal
		if hasVariantPolicy {
			log.Println("Removing variant policy to simulate policy deletion")
			hasVariantPolicy = false
		} else {
			// Randomly add a new policy based on an existing one (50% chance when updating)
			if rand.Float32() < 0.5 {
				// Split into individual policy documents
				docs := strings.Split(yamlString, "---")
				if len(docs) > 1 {
					// Pick a random policy (skip the first empty doc)
					sourceIdx := rand.Intn(len(docs)-1) + 1
					sourcePolicy := docs[sourceIdx]

					// Create a new policy by modifying the name
					newPolicy := sourcePolicy
					namePattern := "name: "
					nameIdx := strings.Index(newPolicy, namePattern)
					if nameIdx != -1 {
						nameStart := nameIdx + len(namePattern)
						nameEnd := strings.Index(newPolicy[nameStart:], "\n")
						if nameEnd != -1 {
							nameEnd += nameStart
							originalName := newPolicy[nameStart:nameEnd]
							// Remove quotes and trim whitespace
							originalName = strings.Trim(strings.TrimSpace(originalName), "\"'")
							newName := fmt.Sprintf("%s-variant-%d", originalName, time.Now().Unix()%10000)
							newPolicy = newPolicy[:nameStart] + newName + newPolicy[nameEnd:]

							// Append the new policy
							yamlString = yamlString + "\n---\n" + newPolicy
							hasVariantPolicy = true
							log.Printf("Added new policy variant: %s", newName)
						}
					}
				}
			}
		}

		log.Printf("Policy updated! New version: v1.0.%d", policyVersion)
	}
	currentVersion := policyVersion
	policyVersionMu.Unlock()

	yamlContent = []byte(yamlString)

	// Base64 encode the YAML
	encodedPolicies := base64.StdEncoding.EncodeToString(yamlContent)

	// Calculate SHA256 hash of the raw YAML content
	hash := sha256.Sum256(yamlContent)
	sha256Hash := hex.EncodeToString(hash[:])

	resp := PoliciesResponse{
		Version:  fmt.Sprintf("v1.0.%d", currentVersion),
		Policies: encodedPolicies,
		Sha256:   sha256Hash,
	}

	log.Printf("Serving policies version %s (sha256: %s, updated: %v)", resp.Version, resp.Sha256, shouldUpdate)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleHealthReport(w http.ResponseWriter, r *http.Request) {
	var report map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	log.Printf("Health report: %+v", report)

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, `{"status":"ok"}`)
}
