# Screener Makefile

export GO111MODULE=on

SHELL := /bin/bash

OUTPUT = bin
SERVICE_NAME = screener

STATIC_ARGS = -ldflags "-linkmode external -extldflags -static"

.PHONY: build clean screener screener-static

build:
	make screener
	#make screener-static

screener:
	go build -o $(OUTPUT)/$(SERVICE_NAME) -a *.go

screener-static:
	go build $(STATIC_ARGS) -o $(OUTPUT)/$(SERVICE_NAME) -a *.go

format:
	gofmt -w ./

clean:
	rm -rf $(OUTPUT)/$(SERVICE_NAME)

tidy:
	make clean
	go mod tidy

test:
	go clean -testcache .
	go test . -v

test_cover:
	go test -cover .
