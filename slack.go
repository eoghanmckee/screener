package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
)

const (
	colorDangerousAlert string = "#ff0000"
)

// SlackAlerter will be used to send alerts via Slack
type SlackAlerter struct {
	Configuration SlackJSON
	Headers       map[string]string
	Debug         bool
}

type slackMessageData struct {
	Attachments []slackMessageAttachment `json:"attachments"`
}

type slackMessageField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

type slackMessageAttachment struct {
	Fallback   string              `json:"fallback"`
	Color      string              `json:"color"`
	Pretext    string              `json:"pretext"`
	AuthorName string              `json:"author_name"`
	AuthorLink string              `json:"author_link"`
	Title      string              `json:"title"`
	TitleLink  string              `json:"title_link"`
	Text       string              `json:"text"`
	Fields     []slackMessageField `json:"fields"`
}

// Send - Function that sends an alert to Slack based on a positive match
func (slackAL *SlackAlerter) Send(message slackMessageData) {
	// Prepare headers
	headers := map[string]string{
		"Content-Type": "application/json",
	}
	// Serialize data
	jsonMessage, err := json.Marshal(message)
	if err != nil {
		log.Printf("error marshaling data %s", err)
	}
	// Prepare data
	jsonParam := strings.NewReader(string(jsonMessage))
	resp, body, err := rawRequest("POST", slackConfig.SlackWebhook, jsonParam, headers)
	if err != nil {
		log.Printf("error sending messsage to slack: %v", err)
	}
	if resp != http.StatusOK {
		log.Printf("HTTP %d: %s", resp, string(body))
	}
}

// Alert - Function to alert in Slack for a dangerous file
func (slackAL *SlackAlerter) Alert(threatreport, fullname, host, location, event string) {
	pretext := fmt.Sprintf("*Envoy Visitor Alert - Threat Report for visitor: \"%s\"*", fullname)
	attachment := slackMessageAttachment{
		Fallback: pretext,
		Color:    colorDangerousAlert,
		Pretext:  pretext,
		Fields: []slackMessageField{
			{
				Title: "Fullname",
				Value: fullname,
			},
			{
				Title: "Host",
				Value: host,
			},
			{
				Title: "Location",
				Value: location,
			},
			{
				Title: "Event Type",
				Value: event,
			},
			{
				Title: "Threat Report",
				Value: "```" + threatreport + "```",
			},
		},
	}
	data := slackMessageData{
		Attachments: []slackMessageAttachment{attachment},
	}
	slackAL.Send(data)
}
