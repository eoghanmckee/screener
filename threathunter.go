package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

const (
	FPURL    = "https://fp.tools/api/v4/indicators/simple?limit=10&query="
	fpHeader = "\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n" +
		"~~~~~~ FLASHPOINT THREAT REPORT ~~~~~~\n" +
		"~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
)

type ThreatHunterAPIs struct {
	Configuration ThreatHunterJSON
	FPHeaders     map[string]string
	Debug         bool
	Slack         *SlackAlerter
}

// HandlersOption for interface options
type HandlersOptions func(*ThreatHunterAPIs)

type FPReport struct {
	Attribute struct {
		Event struct {
			Tags []string `json:"Tags"`
			Info string   `json:"info"`
		} `json:"Event"`
		Category string `json:"category"`
		Href     string `json:"href"`
		Type     string `json:"type"`
		Value    struct {
			Comment string `json:"comment"`
			URL     string `json:"url"`
		} `json:"value"`
	} `json:"Attribute"`
}

func CreateThreatHunterAPIs(config ThreatHunterJSON, debug bool) (*ThreatHunterAPIs, error) {
	o := &ThreatHunterAPIs{
		Configuration: config,
		FPHeaders: map[string]string{
			"Authorization": "Bearer " + config.FPAPIToken,
			contentType:     JSONApplication,
		},
		Debug: debug,
	}
	return o,
		nil
}

func (o *ThreatHunterAPIs) FlashpointChecker(email string) (string, error) {
	var fpreport []FPReport
	var flashpointMessage bytes.Buffer
	flashpointURL := FPURL + "\"" + email + "\""
	httpCode, response, err := parsedRequest("GET", flashpointURL, nil, o.FPHeaders)
	if err != nil {
		return "", err
	}
	if httpCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d - could not retrieve check", httpCode)
	}

	fpJSON, err := json.Marshal(response)
	if err != nil {
		return "", err
	}

	err2 := json.Unmarshal(fpJSON, &fpreport)
	if err != nil {
		return "", err2
	}
	if len(fpreport) > 0 {
		flashpointMessage.WriteString(fpHeader)
	}

	for k := range fpreport {
		flashpointMessage.WriteString("Info: " + fpreport[k].Attribute.Event.Info + "\n")
		flashpointMessage.WriteString("Type: " + fpreport[k].Attribute.Type + "\n")
		flashpointMessage.WriteString("Category: " + fpreport[k].Attribute.Category + "\n")
		flashpointMessage.WriteString("Link: " + fpreport[k].Attribute.Href + "\n\n")
	}

	return flashpointMessage.String(), nil
}

func (o *ThreatHunterAPIs) ThreatHunter(visitorID, email, fullname, host, location, event string) {
	fpMessage, err := o.FlashpointChecker(email)
	if err != nil {
		fmt.Printf("error retrieving Flashpoint data - %s", err)
	}
	finalThreatReport := fpMessage

	if len(finalThreatReport) > 0 {
		fmt.Printf("Threat data found for Visitor ID - %s. Alerting Slack.\n", visitorID)
		o.Slack.Alert(finalThreatReport, fullname, host, location, event)
	} else {
		fmt.Printf("No threat data for Visitor ID - %s\n", visitorID)
	}
}
