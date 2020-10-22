VERSION := $(shell git describe --tags)
LDFLAGS=-ldflags "-s -w -X=main.version=$(VERSION)"

GOPATH=$(shell go env GOPATH)
GOBIN=$(GOPATH)/bin
GOSRC=$(GOPATH)/src

u := $(if $(update),-u)

$(GOBIN)/wire:
	GO111MODULE=off go get github.com/google/wire/cmd/wire

.PHONY: wire
wire: $(GOBIN)/wire
	wire gen ./pkg/... ./internal/...

.PHONY: mock
mock: $(GOBIN)/mockery
	mockery -all -inpkg -case=snake -dir $(DIR)

.PHONY: deps
deps:
	go get ${u} -d
	go mod tidy

$(GOBIN)/golangci-lint:
	curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh| sh -s -- -b $(GOBIN) v1.21.0

.PHONY: test
test:
	go test -v -short -coverprofile=coverage.txt -covermode=atomic ./...

integration/testdata/fixtures/*.tar.gz:
	git clone https://github.com/aquasecurity/trivy-test-images.git integration/testdata/fixtures

.PHONY: test-integration
test-integration: integration/testdata/fixtures/*.tar.gz
	go test -v -tags=integration ./integration/...

.PHONY: lint
lint: $(GOBIN)/golangci-lint
	$(GOBIN)/golangci-lint run

.PHONY: fmt
fmt:
	find ./ -name "*.proto" | xargs clang-format -i

.PHONY: build
build:
	go build $(LDFLAGS) ./cmd/trivy

.PHONY: protoc
protoc:
	find ./rpc/ -name "*.proto" -type f -exec protoc --proto_path=$(GOSRC):. --twirp_out=. --go_out=. {} \;

.PHONY: install
install:
	go install $(LDFLAGS) ./cmd/trivy

.PHONY: clean
clean:
	rm -rf integration/testdata/fixtures/

$(GOBIN)/labeler:
	GO111MODULE=off go get github.com/knqyf263/labeler

.PHONY: label
label: $(GOBIN)/labeler
	labeler apply misc/triage/labels.yaml -r aquasecurity/trivy -l 5
