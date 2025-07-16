// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/cilium/tetragon/pkg/fieldfilters"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/option"

	"github.com/spf13/viper"
)

var (
	adminTgConfDir       = "/etc/tetragon/"
	adminTgConfDropIn    = "/etc/tetragon/tetragon.conf.d/"
	packageTgConfDropIns = []string{
		"/usr/lib/tetragon/tetragon.conf.d/",
		"/usr/local/lib/tetragon/tetragon.conf.d/",
	}
)

// reloadConfig reloads the configuration from files and environment variables
func reloadConfig() error {
	// Capture initial configuration state for comparison
	initialConfig := make(map[string]interface{})
	for key, value := range viper.AllSettings() {
		initialConfig[key] = value
	}

	// Instead of calling viper.Reset() which disrupts running sensors,
	// we reload configuration without clearing the existing state
	// This prevents sensor cleanup failures during reload
	log.Info("Reloading configuration without clearing existing state")
	log.Debug("config settings before reload", "config", initialConfig)

	// Reload configuration with the same logic as startup
	readConfigSettings(adminTgConfDir, adminTgConfDropIn, packageTgConfDropIns)

	// Validate critical configuration options
	if err := validateConfig(); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	// Compare final configuration state with initial state and log changes
	finalConfig := viper.AllSettings()
	logConfigChanges(initialConfig, finalConfig)

	// Apply configuration changes that can be safely updated without restart
	if err := applyDynamicConfigChanges(initialConfig, finalConfig); err != nil {
		log.Warn("Some configuration changes could not be applied", logfields.Error, err)
	}

	log.Info("Configuration reloaded and validated successfully")
	log.Debug("config settings after reload", "config", finalConfig)
	return nil
}

// validateConfig performs basic validation of critical configuration
func validateConfig() error {
	// Validate tracing policy directory - this may not be set when not properly configured but should exist if we reloading configs
	if viper.IsSet(option.KeyTracingPolicyDir) {
		if !filepath.IsAbs(viper.GetString(option.KeyTracingPolicyDir)) {
			return fmt.Errorf("tracing policy directory must be absolute path")
		}
		log.Info("Tracing policy directory is valid")
	}

	return nil
}

func readConfigSettings(defaultConfDir string, defaultConfDropIn string, dropInsDir []string) {
	viper.SetEnvPrefix("tetragon")
	replacer := strings.NewReplacer("-", "_")
	viper.SetEnvKeyReplacer(replacer)
	viper.AutomaticEnv()

	// First set default conf file and format
	viper.SetConfigName("tetragon")
	viper.SetConfigType("yaml")

	// Read default drop-ins directories
	for _, dir := range dropInsDir {
		option.ReadConfigDir(dir)
	}

	// Look into cwd first, this is needed for quick development only
	option.ReadConfigFile(".", "tetragon.yaml")

	// Look for /etc/tetragon/tetragon.yaml
	option.ReadConfigFile(defaultConfDir, "tetragon.yaml")

	// Look into default /etc/tetragon/tetragon.conf.d/ now
	option.ReadConfigDir(defaultConfDropIn)

	// Read now the passed key --config-dir
	if viper.IsSet(option.KeyConfigDir) {
		configDir := viper.GetString(option.KeyConfigDir)
		// viper.IsSet could return true on an empty string reset
		if configDir != "" {
			err := option.ReadConfigDir(configDir)
			if err != nil {
				logger.Fatal(log, "Failed to read config from directory", option.KeyConfigDir, configDir, logfields.Error, err)
			} else {
				log.Info("Loaded config from directory", option.KeyConfigDir, configDir)
			}
		}
	}
}

// logConfigChanges compares initial and final configuration states and logs the differences
func logConfigChanges(initialConfig, finalConfig map[string]interface{}) {
	var added []string
	var changed []string
	var removed []string

	// Check for added and changed keys
	for key, finalValue := range finalConfig {
		if initialValue, exists := initialConfig[key]; exists {
			// Key existed before, check if value changed
			if !configValuesEqual(initialValue, finalValue) {
				changed = append(changed, fmt.Sprintf("%s: %v -> %v", key, initialValue, finalValue))
			}
		} else {
			// Key is new
			added = append(added, fmt.Sprintf("%s: %v", key, finalValue))
		}
	}

	// Check for removed keys
	for key, initialValue := range initialConfig {
		if _, exists := finalConfig[key]; !exists {
			removed = append(removed, fmt.Sprintf("%s: %v", key, initialValue))
		}
	}

	// Log the changes
	if len(added) > 0 {
		log.Info("Configuration keys added during reload", "added", added)
	}
	if len(changed) > 0 {
		log.Info("Configuration keys changed during reload", "changed", changed)
	}
	if len(removed) > 0 {
		log.Info("Configuration keys removed during reload", "removed", removed)
	}
	if len(added) == 0 && len(changed) == 0 && len(removed) == 0 {
		log.Info("No configuration changes detected during reload")
	}
}

// configValuesEqual compares two configuration values for equality
func configValuesEqual(a, b interface{}) bool {
	// Simple comparison - for more complex cases, you might need deep comparison
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

// applyDynamicConfigChanges applies configuration changes that can be safely updated without restart
func applyDynamicConfigChanges(initialConfig, finalConfig map[string]interface{}) error {
	changeHandlers := []struct {
		name       string
		checkFunc  func(map[string]interface{}, map[string]interface{}) bool
		updateFunc func() error
		canApply   bool
	}{
		{
			name:       "logging configuration",
			checkFunc:  hasLoggingConfigChanged,
			updateFunc: updateLoggingConfig,
			canApply:   true,
		},
		{
			name:       "redaction filters",
			checkFunc:  hasRedactionFiltersChanged,
			updateFunc: updateRedactionFilters,
			canApply:   true,
		},
		{
			name:       "process cache configuration",
			checkFunc:  hasProcessCacheConfigChanged,
			updateFunc: func() error { return nil }, // No-op, just log
			canApply:   false,
		},
		{
			name:       "metrics configuration",
			checkFunc:  hasMetricsConfigChanged,
			updateFunc: func() error { return nil }, // No-op, just log
			canApply:   false,
		},
		{
			name:       "export configuration",
			checkFunc:  hasExportConfigChanged,
			updateFunc: func() error { return nil }, // No-op, just log
			canApply:   false,
		},
	}

	var errors []string
	for _, handler := range changeHandlers {
		if handler.checkFunc(initialConfig, finalConfig) {
			if handler.canApply {
				if err := handler.updateFunc(); err != nil {
					errors = append(errors, fmt.Sprintf("%s: %v", handler.name, err))
				} else {
					log.Info("Configuration updated successfully", "component", handler.name)
				}
			} else {
				log.Info("Configuration changed - requires restart to take effect", "component", handler.name)
			}
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to apply some configuration changes: %s", strings.Join(errors, "; "))
	}

	return nil
}

// configChangeChecker defines the interface for checking configuration changes
type configChangeChecker struct {
	keys []string
}

// hasChanged checks if any of the specified keys changed between initial and final config
func (c *configChangeChecker) hasChanged(initial, final map[string]interface{}) bool {
	for _, key := range c.keys {
		if !configValuesEqual(initial[key], final[key]) {
			return true
		}
	}
	return false
}

// Configuration change checkers
var (
	loggingChecker = &configChangeChecker{
		keys: []string{
			option.KeyLogLevel,
			option.KeyLogFormat,
			option.KeyDebug,
			option.KeyVerbosity,
		},
	}

	redactionFiltersChecker = &configChangeChecker{
		keys: []string{option.KeyRedactionFilters},
	}

	processCacheChecker = &configChangeChecker{
		keys: []string{
			option.KeyProcessCacheSize,
			option.KeyProcessCacheGCInterval,
		},
	}

	metricsChecker = &configChangeChecker{
		keys: []string{
			option.KeyMetricsServer,
			option.KeyMetricsLabelFilter,
		},
	}

	exportChecker = &configChangeChecker{
		keys: []string{
			option.KeyExportFilename,
			option.KeyExportFileMaxSizeMB,
			option.KeyExportFileMaxBackups,
			option.KeyExportFileCompress,
			option.KeyExportFileRotationInterval,
			option.KeyExportRateLimit,
			option.KeyExportAllowlist,
			option.KeyExportDenylist,
		},
	}
)

// hasLoggingConfigChanged checks if logging-related configuration changed
func hasLoggingConfigChanged(initial, final map[string]interface{}) bool {
	return loggingChecker.hasChanged(initial, final)
}

// hasRedactionFiltersChanged checks if redaction filters changed
func hasRedactionFiltersChanged(initial, final map[string]interface{}) bool {
	return redactionFiltersChecker.hasChanged(initial, final)
}

// hasProcessCacheConfigChanged checks if process cache configuration changed
func hasProcessCacheConfigChanged(initial, final map[string]interface{}) bool {
	return processCacheChecker.hasChanged(initial, final)
}

// hasMetricsConfigChanged checks if metrics configuration changed
func hasMetricsConfigChanged(initial, final map[string]interface{}) bool {
	return metricsChecker.hasChanged(initial, final)
}

// hasExportConfigChanged checks if export configuration changed
func hasExportConfigChanged(initial, final map[string]interface{}) bool {
	return exportChecker.hasChanged(initial, final)
}

// updateLoggingConfig updates the logging configuration
func updateLoggingConfig() error {
	logOpts := logger.LogOptions{
		logger.LevelOpt:  viper.GetString(option.KeyLogLevel),
		logger.FormatOpt: viper.GetString(option.KeyLogFormat),
	}

	if err := logger.SetupLogging(logOpts, viper.GetBool(option.KeyDebug)); err != nil {
		return fmt.Errorf("failed to update logging configuration: %w", err)
	}

	return nil
}

// updateRedactionFilters updates the redaction filters
func updateRedactionFilters() error {
	redactionFilters := viper.GetString(option.KeyRedactionFilters)

	var err error
	fieldfilters.RedactionFilters, err = fieldfilters.ParseRedactionFilterList(redactionFilters)
	if err != nil {
		return fmt.Errorf("failed to parse redaction filters: %w", err)
	}

	return nil
}
