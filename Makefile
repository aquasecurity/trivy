VERSION := $(shell git describe --tags)
LDFLAGS=-ldflags "-s -w -X=main.version=$(VERSION)"

GOPATH=$(shell go env GOPATH)
GOBIN=$(GOPATH)/bin
GOSRC=$(GOPATH)/src

MKDOCS_IMAGE := aquasec/mkdocs-material:dev
MKDOCS_PORT := 8000

u := $(if $(update),-u)

$(GOBIN)/wire:
	go install github.com/google/wire/cmd/wire@v0.5.0

$(GOBIN)/crane:
	go install github.com/google/go-containerregistry/cmd/crane@v0.9.0

$(GOBIN)/golangci-lint:
	curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh| sh -s -- -b $(GOBIN) v1.45.2

$(GOBIN)/labeler:
	go install github.com/knqyf263/labeler@latest

.PHONY: wire
wire: $(GOBIN)/wire
	wire gen ./pkg/...

.PHONY: mock
mock: $(GOBIN)/mockery
	mockery -all -inpkg -case=snake -dir $(DIR)

.PHONY: deps
deps:
	go get ${u} -d
	go mod tidy


.PHONY: test
test:
	go test -v -short -coverprofile=coverage.txt -covermode=atomic ./...

integration/testdata/fixtures/images/*.tar.gz: $(GOBIN)/crane
	mkdir -p integration/testdata/fixtures/images/
	integration/scripts/download-images.sh

.PHONY: test-integration
test-integration: integration/testdata/fixtures/images/*.tar.gz
	go test -v -tags=integration ./integration/...

.PHONY: lint
lint: $(GOBIN)/golangci-lint
	$(GOBIN)/golangci-lint run --timeout 5m

.PHONY: fmt
fmt:
	find ./ -name "*.proto" | xargs clang-format -i

.PHONY: build
build:
	go build $(LDFLAGS) ./cmd/trivy

.PHONY: protoc
protoc:
	docker build -t trivy-protoc - < Dockerfile.protoc
	docker run --rm -it -v ${PWD}:/app -w /app trivy-protoc make _$@

_protoc:
	for path in `find ./rpc/ -name "*.proto" -type f`; do \
		protoc --twirp_out=. --twirp_opt=paths=source_relative --go_out=. --go_opt=paths=source_relative $${path} || exit; \
	done

.PHONY: install
install:
	go install $(LDFLAGS) ./cmd/trivy

.PHONY: clean
clean:
	rm -rf integration/testdata/fixtures/images

.PHONY: label
label: $(GOBIN)/labeler
	labeler apply misc/triage/labels.yaml -r aquasecurity/trivy -l 5

.PHONY: mkdocs-serve
## Runs MkDocs development server to preview the documentation page
mkdocs-serve:
	docker build -t $(MKDOCS_IMAGE) -f docs/build/Dockerfile docs/build
	docker run --name mkdocs-serve --rm -v $(PWD):/docs -p $(MKDOCS_PORT):8000 $(MKDOCS_IMAGE)
