.PHONY: all test build clean check

all: clean check test build

.EXPORT_ALL_VARIABLES:
LOG_LEVEL=trace
NAME=iotpaas-auth-service
SERVER_PORT=9003
ENV=DEV
VERSION=1.0.5

# change these variables as needed
CONTAINER_ENGINE ?= podman
AUTH ?= --authfile=~/.docker/config
REGISTRY ?= quay.io/luigizuccarelli/iotpaas-auth-interface
IMAGE_VERSION ?= 1.16.6

build: 
	mkdir -p build
	go build -o build ./...

check:
	go fmt ./...
	go vet ./...

test:
	go test -v -coverprofile=tests/results/cover.out ./...

cover:
	go tool cover -html=tests/results/cover.out -o tests/results/cover.html

clean:
	rm -rf build/*
	go clean ./...

container:
	$(CONTAINER_ENGINE) build -t  $(REGISTRY):$(IMAGE_VERSION) .

push:
	$(CONATINER_ENGINE) push "$(AUTH)" $(REGISTRY):$(IMAGE_VERSION) 
