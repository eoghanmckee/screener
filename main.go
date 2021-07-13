package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
)

// Constants for the service
const (
	// Service name
	serviceName = "Screener"
	// Service description
	serviceDescription = "Visitor Threat Analysis"
	// Service version
	serviceVersion = "1.0.0"
	// Service dev
	serviceDev = "dev"
)

// Paths
const (
	// Default endpoint to handle HTTP health
	healthPath = "/health"
	// Default endpoint to handle HTTP root
	rootPath = "/"
	// Default endpoint to handle webhooks
	webhookPath = "/webhook_receiver"
)

// Files and configurations
const (
	// Default service configuration file
	configurationFile = "config/service.json"
	// Default slack configuration file
	slackConfigurationFile = "config/slack.json"
	// Default threathunter configuration file
	threathunterConfigurationFile = "config/threathunter.json"
)

// Global general variables
var (
	err            error
	_threathunter        *ThreatHunterAPIs
	handlersHTTP   *HTTPHandlers
	serviceConfig  ConfigurationJSON
	slackConfig    SlackJSON
	threathunterConfig   ThreatHunterJSON
	serviceHostEnv string
	debugService   bool
)

func loadConfigs() (err error) {
	// Logging format flags
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
	// Load service configuration
	log.Printf("Loading configuration from %s", configurationFile)
	serviceConfig, err = loadServiceConfig(configurationFile)
	if err != nil {
		return
	}
	// Load slack configuration
	log.Printf("Loading configuration from %s", slackConfigurationFile)
	slackConfig, err = loadSlackConfig(slackConfigurationFile)
	if err != nil {
		return
	}
	// Load threathunter configuration
	log.Printf("Loading configuration from %s", threathunterConfigurationFile)
	threathunterConfig, err = loadThreatHunterConfig(threathunterConfigurationFile)
	if err != nil {
		return
	}
	// Save environment HOSTNAME to global variable
	serviceHostEnv = os.Getenv("HOSTNAME")
	// If we are in dev, turn debug on
	debugService = (serviceConfig.Instance == serviceDev)

	return
}

// Main code
func main() {
	err := loadConfigs()
	if err != nil {
		log.Fatal("Error loading configs. ", err.Error())
	}

	// Initialize ThreatHunter
	_threathunter, err = CreateThreatHunterAPIs(threathunterConfig, debugService)
	if err != nil {
		log.Fatalf("Error creating threathunter API - %v", err)
	}

	// Initialize HTTP Handlers
	log.Println("Initializing HTTP handlers")
	handlersHTTP = CreateHTTPHandlers(
		WithThreatHunter(_threathunter),
	)

	// Create router for service
	log.Println("Initializing router")
	routerService := mux.NewRouter()

	// Service: Health of service
	routerService.HandleFunc(healthPath, handlersHTTP.healthHandler).Methods("GET", "POST")

	// Service: Webhook for ThreatHunter
	log.Printf("Catching POST webhook calls in /%s%s\n", serviceConfig.WebhookPrefix, webhookPath)
	routerService.Handle("/"+serviceConfig.WebhookPrefix+webhookPath, handlerAuthCheck(http.HandlerFunc(handlersHTTP.webhookHandler))).Methods("POST")

	// Launch HTTP server for service
	serviceString := serviceConfig.Listener + ":" + serviceConfig.Port
	log.Printf("%s - %s - v%s - HTTP listening %s", serviceName, serviceDescription, serviceVersion, serviceString)
	log.Printf("%s running in %s", serviceName, serviceHostEnv)
	log.Fatal(http.ListenAndServe(serviceString, routerService))
}
