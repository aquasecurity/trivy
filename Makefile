VERSION := $(shell git describe --tags)
LDFLAGS=-ldflags "-s -w -X=main.version=$(VERSION)"

GOPATH=$(shell go env GOPATH)
GOBIN=$(GOPATH)/bin

u := $(if $(update),-u)

.PHONY: deps
deps:
	go get ${u} -d
	go mod tidy

$(GOBIN)/golangci-lint:
	curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh| sh -s -- -b $(GOBIN) v1.21.0

.PHONY: test
test:
	go test ./...

integration/testdata/fixtures/*.tar.gz:
	git clone https://github.com/aquasecurity/trivy-test-images.git integration/testdata/fixtures

.PHONY: test-integration
test-integration: integration/testdata/fixtures/*.tar.gz
	go test ./... -tags=integration

.PHONY: lint
lint: $(GOBIN)/golangci-lint
	golangci-lint run

.PHONY: build
build:
	go build $(LDFLAGS) ./cmd/trivy

.PHONY: install
install:
	go install $(LDFLAGS) ./cmd/trivy

