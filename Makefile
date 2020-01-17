export GO111MODULE=on

.PHONY: deps
deps:
	go get -d

.PHONY: devel-deps
devel-deps: deps
	GO111MODULE=off go get \
	  golang.org/x/lint/golint \
	  github.com/mattn/goveralls

.PHONY: test
test: deps
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