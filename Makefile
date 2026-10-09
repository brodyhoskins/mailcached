.PHONY: build test docker

VERSION ?= $(shell cat VERSION)
LDFLAGS := $(if $(VERSION),-X github.com/brodyhoskins/mailcached/internal/version.Version=$(VERSION))

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o . ./cmd/...

test:
	go test ./...

docker:
	docker build --build-arg VERSION=$(VERSION) -t mailcached:$(VERSION) .
