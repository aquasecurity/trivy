.PHONY: deps
deps:
	go get -d

.PHONY: test
test:
	go test -tags="containers_image_storage_stub" ./...

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
	go test -v -tags="integration containers_image_storage_stub" ./integration/...

.PHONY: test-performance
test-performance: integration/testdata/fixtures/*.tar.gz
	go test -v -benchtime=10x -tags="performance containers_image_storage_stub" -bench=. ./integration/...
