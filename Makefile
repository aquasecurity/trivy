VERSION := $(patsubst v%,%,$(shell git describe --tags --always)) #Strips the v prefix from the tag
LDFLAGS := -ldflags "-s -w -X=main.version=$(VERSION)"

GOPATH := $(firstword $(subst :, ,$(shell go env GOPATH)))
GOBIN := $(GOPATH)/bin
GOSRC := $(GOPATH)/src

TEST_MODULE_DIR := pkg/module/testdata
TEST_MODULE_SRCS := $(wildcard $(TEST_MODULE_DIR)/*/*.go)
TEST_MODULES := $(patsubst %.go,%.wasm,$(TEST_MODULE_SRCS))

EXAMPLE_MODULE_DIR := examples/module
EXAMPLE_MODULE_SRCS := $(wildcard $(EXAMPLE_MODULE_DIR)/*/*.go)
EXAMPLE_MODULES := $(patsubst %.go,%.wasm,$(EXAMPLE_MODULE_SRCS))

MKDOCS_IMAGE := aquasec/mkdocs-material:dev
MKDOCS_PORT := 8000

u := $(if $(update),-u)

# Tools
$(GOBIN)/wire:
	go install github.com/google/wire/cmd/wire@v0.5.0

$(GOBIN)/crane:
	go install github.com/google/go-containerregistry/cmd/crane@v0.9.0

$(GOBIN)/golangci-lint:
	curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh| sh -s -- -b $(GOBIN) v1.49.0

$(GOBIN)/labeler:
	go install github.com/knqyf263/labeler@latest

$(GOBIN)/easyjson:
	go install github.com/mailru/easyjson/...@v0.7.7

.PHONY: wire
wire: $(GOBIN)/wire
	wire gen ./pkg/commands/... ./pkg/rpc/...

.PHONY: mock
mock: $(GOBIN)/mockery
	mockery -all -inpkg -case=snake -dir $(DIR)

.PHONY: deps
deps:
	go get ${u} -d
	go mod tidy

.PHONY: generate-test-modules
generate-test-modules: $(TEST_MODULES)

# Compile WASM modules for unit and integration tests
%.wasm:%.go
	@if !(type "tinygo" > /dev/null 2>&1); then \
		echo "Need to install TinyGo. Follow https://tinygo.org/getting-started/install/"; \
		exit 1; \
	fi
	go generate $<

# Run unit tests
.PHONY: test
test: $(TEST_MODULES)
	go test -v -short -coverprofile=coverage.txt -covermode=atomic ./...

integration/testdata/fixtures/images/*.tar.gz: $(GOBIN)/crane
	mkdir -p integration/testdata/fixtures/images/
	integration/scripts/download-images.sh

# Run integration tests
.PHONY: test-integration
test-integration: integration/testdata/fixtures/images/*.tar.gz
	go test -v -tags=integration ./integration/... ./pkg/fanal/test/integration/...

# Run WASM integration tests
.PHONY: test-module-integration
test-module-integration: integration/testdata/fixtures/images/*.tar.gz $(EXAMPLE_MODULES)
	go test -v -tags=module_integration ./integration/...

# Run VM integration tests
.PHONY: test-vm-integration
test-vm-integration: integration/testdata/fixtures/vm-images/*.img.gz
	go test -v -tags=vm_integration ./integration/...

integration/testdata/fixtures/vm-images/*.img.gz:
	integration/scripts/download-vm-images.sh


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

# Create labels on GitHub
.PHONY: label
label: $(GOBIN)/labeler
	labeler apply misc/triage/labels.yaml -r aquasecurity/trivy -l 5

# Run MkDocs development server to preview the documentation page
.PHONY: mkdocs-serve
mkdocs-serve:
	docker build -t $(MKDOCS_IMAGE) -f docs/build/Dockerfile docs/build
	docker run --name mkdocs-serve --rm -v $(PWD):/docs -p $(MKDOCS_PORT):8000 $(MKDOCS_IMAGE)

# Generate JSON marshaler/unmarshaler for TinyGo/WebAssembly as TinyGo doesn't support encoding/json.
.PHONY: easyjson
easyjson: $(GOBIN)/easyjson
	easyjson pkg/module/serialize/types.go