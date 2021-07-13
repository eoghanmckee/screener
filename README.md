<div align="center"><img src="screener.gif" /></div>

# Screener - Visitor Threat Analysis

This service checks office visitors against our threat intelligence vendors using data sent from an Envoy Webhook. 
If intelligence is found on the visitor, a slack channel will be notified. 

## Running

1. Set up your config; `config/service.json`, `config/slack.json`, `config/threathunter.json`
2. Build the docker container with `docker build -t screener:latest .`
3. Run the container with `$ docker run -p 8080:8080 screener`