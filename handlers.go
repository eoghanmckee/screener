package main

import (
	"compress/gzip"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
)

const (
	// Default response
	defaultResponse = `(⌐▀ ʖ▀)`
	// Health response
	healthResponse = "✅"
)

// WebhookRequest to be sent from webhooks
type WebhookRequest struct {
	Payload WebhookPayload `json:"payload,omitempty"`
	Event   string         `json:"event,omitempty"`
	Meta    WebhookMeta    `json:"meta,omitempty"`
}

type WebhookPayload struct {
	ID         string            `json:"id,omitempty"`
	Event      string            `json:"event,omitempty"`
	Attributes WebhookAttributes `json:"attributes,omitempty"`
}

type WebhookMeta struct {
	Location WebhookLocationAttributes `json:"location,omitempty"`
}

type WebhookLocationAttributes struct {
	LocationAttributes LocationAttributes `json:"attributes,omitempty"`
}

type LocationAttributes struct {
	LocationName string `json:"name,omitempty"`
}

type WebhookAttributes struct {
	Email    string `json:"email,omitempty"`
	FullName string `json:"full-name,omitempty"`
	Host     string `json:"host,omitempty"`
	Location string `json:"name,omitempty"`
}

// HTTPHandlers to keep all handlers
type HTTPHandlers struct {
	ThreatHunter *ThreatHunterAPIs
}

// HandlersOption for interface options
type HandlersOption func(*HTTPHandlers)

func WithThreatHunter(threathunter *ThreatHunterAPIs) HandlersOption {
	return func(h *HTTPHandlers) {
		h.ThreatHunter = threathunter
	}
}

// CreateHTTPHandlers to initialize the handlers struct
func CreateHTTPHandlers(opts ...HandlersOption) *HTTPHandlers {
	h := &HTTPHandlers{}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// Handle health requests
func (h *HTTPHandlers) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(contentType, JSONApplicationUTF8)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(healthResponse))
}

// Handle webhooks
func (h *HTTPHandlers) webhookHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received webhook:\n%s", debugHTTP(r, debugService, false))
	if r.Header.Get(contentEncoding) == "gzip" {
		r.Body, err = gzip.NewReader(r.Body)
		if err != nil {
			log.Printf("error decoding gzip body - %v", err)
			return
		}
	}
	defer func() {
		if err := r.Body.Close(); err != nil {
			log.Printf("error closing body - %v", err)
			return
		}
	}()
	bodyRaw, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("error extracting body - %v", err)
		return
	}

	log.Printf("webhook signature - %s", healthResponse)
	var wr WebhookRequest
	if err := json.Unmarshal(bodyRaw, &wr); err != nil {
		log.Printf("error parsing POST body - %v", err)
		return
	}
	defer func() {
		if err := r.Body.Close(); err != nil {
			log.Printf("failed to close body - %v", err)
		}
	}()
	log.Printf("Visitor ID: %s\n", wr.Payload.ID)
	go h.ThreatHunter.ThreatHunter(
		wr.Payload.ID,
		wr.Payload.Attributes.Email,
		wr.Payload.Attributes.FullName,
		wr.Payload.Attributes.Host,
		wr.Meta.Location.LocationAttributes.LocationName,
		wr.Event,
	)

	w.Header().Set(contentType, JSONApplicationUTF8)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(defaultResponse))
}
