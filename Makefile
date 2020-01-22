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

integration/testdata/fixtures/*.tar.gz:
	git clone https://github.com/aquasecurity/trivy-test-images.git integration/testdata/fixtures

.PHONY: test-integration
test-integration: integration/testdata/fixtures/*.tar.gz
	go test -v -tags=integration ./integration/...

.PHONY: test-performance
test-performance: integration/testdata/fixtures/*.tar.gz
	go test -v -tags=performance -bench=. ./integration/...
