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

test/integration/testdata/fixtures/*.tar.gz:
	git clone https://github.com/aquasecurity/trivy-test-images.git test/integration/testdata/fixtures

.PHONY: test-integration
test-integration: test/integration/testdata/fixtures/*.tar.gz
	go test -v -tags="integration" ./test/integration/...

.PHONY: test-performance
test-performance: test/integration/testdata/fixtures/*.tar.gz
	go test -v -benchtime=10x -run=^$$ -tags="performance" -bench=. ./test/integration/...
