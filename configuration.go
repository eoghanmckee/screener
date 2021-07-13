package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// ConfigurationJSON for serialized service configuration
type ConfigurationJSON struct {
	Listener      string   `json:"listener"`
	Port          string   `json:"port"`
	AllowList     []string `json:"allow"`
	WebhookPrefix string   `json:"webhookPrefix"`
	AuthToken     string   `json:"authToken"`
	Instance      string   `json:"instance"`
}

// SlackJSON for slack configuration
type SlackJSON struct {
	SlackWebhook string `json:"slackWebhook"`
}

type ThreatHunterJSON struct {
	FPAPIToken     string `json:"fpapiToken"`
}

// Load and parse service config file
func loadServiceConfig(cfg string) (ConfigurationJSON, error) {
	var config ConfigurationJSON
	configFile, err := os.Open(cfg)
	if err != nil {
		return config, fmt.Errorf("Could not load config - %v", err)
	}
	defer configFile.Close()
	if err := json.NewDecoder(configFile).Decode(&config); err != nil {
		return config, fmt.Errorf("Could not parse config - %v", err)
	}
	return config, nil
}

// Load and parse slack config file
func loadSlackConfig(cfg string) (SlackJSON, error) {
	var config SlackJSON
	configFile, err := os.Open(cfg)
	if err != nil {
		return config, fmt.Errorf("Could not load config - %v", err)
	}
	defer configFile.Close()
	if err := json.NewDecoder(configFile).Decode(&config); err != nil {
		return config, fmt.Errorf("Could not parse config - %v", err)
	}
	return config, nil
}

func loadThreatHunterConfig(cfg string) (ThreatHunterJSON, error) {
	var config ThreatHunterJSON
	configFile, err := os.Open(cfg)
	if err != nil {
		return config, fmt.Errorf("Could not load config - %v", err)
	}
	defer configFile.Close()
	if err := json.NewDecoder(configFile).Decode(&config); err != nil {
		return config, fmt.Errorf("Could not parse config - %v", err)
	}
	return config, nil
}
