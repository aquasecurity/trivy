GOPATH=$(shell go env GOPATH)
GOBIN=$(GOPATH)/bin

.PHONY: deps
deps:
	go get -d

.PHONY: test
test:
	go test ./...

.PHONY: lint
lint: devel-deps
	go vet ./...
	golint -set_exit_status

.PHONY: cover
cover: devel-deps
	goveralls

$(GOBIN)/crane:
	go install github.com/google/go-containerregistry/cmd/crane@v0.9.0

test/integration/testdata/fixtures/*.tar.gz: $(GOBIN)/crane
	mkdir -p test/integration/testdata/fixtures/
	test/integration/scripts/download-images.sh

.PHONY: test-integration
test-integration: test/integration/testdata/fixtures/*.tar.gz
	go test -v -tags="integration" ./test/integration/...

.PHONY: test-performance
test-performance: test/integration/testdata/fixtures/*.tar.gz
	go test -v -benchtime=10x -run=^$$ -tags="performance" -bench=. ./test/integration/...
