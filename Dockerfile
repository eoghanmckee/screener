FROM alpine:latest as certs
RUN apk --update add ca-certificates

FROM golang:latest AS builder
WORKDIR /screener

COPY . .

# Copy certificates

WORKDIR /screener
RUN make test
RUN make screener

ENTRYPOINT ["./bin/screener"]
