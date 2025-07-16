// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"fmt"
	"path/filepath"
	"strings"

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
	// Preserve critical configuration values that might have been set via command line flags
	// These are essential for proper BPF program loading and kernel interface access
	procFS := viper.GetString(option.KeyProcFS)
	if procFS == "" {
		procFS = "/proc"
	}

	bpfDir := viper.GetString(option.KeyBpfDir)
	hubbleLib := viper.GetString(option.KeyHubbleLib)
	btf := viper.GetString(option.KeyBTF)

	// Clear existing config
	viper.Reset()

	// Restore critical defaults that are needed for BPF program loading
	viper.SetDefault(option.KeyProcFS, procFS)
	if bpfDir != "" {
		viper.SetDefault(option.KeyBpfDir, bpfDir)
	}
	if hubbleLib != "" {
		viper.SetDefault(option.KeyHubbleLib, hubbleLib)
	}
	if btf != "" {
		viper.SetDefault(option.KeyBTF, btf)
	}

	log.Info("Preserved critical configuration values during reload", "procFS", procFS, "bpfDir", bpfDir, "hubbleLib", hubbleLib, "btf", btf)

	// Reload configuration with the same logic as startup
	readConfigSettings(adminTgConfDir, adminTgConfDropIn, packageTgConfDropIns)

	// Validate critical configuration options
	if err := validateConfig(); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	log.Info("Configuration reloaded and validated successfully")
	return nil
}

// validateConfig performs basic validation of critical configuration
func validateConfig() error {
	// Validate tracing policy directory - this may not be set when not properly configured but should exist if we reloading configs
	if viper.IsSet(option.KeyTracingPolicyDir) {
		if !filepath.IsAbs(viper.GetString(option.KeyTracingPolicyDir)) {
			return fmt.Errorf("tracing policy directory must be absolute path")
		}
	}

	if viper.IsSet(option.KeyRBSize) && viper.IsSet(option.KeyRBSizeTotal) {
		return fmt.Errorf("cannot specify both --rb-size and --rb-size-total")
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
