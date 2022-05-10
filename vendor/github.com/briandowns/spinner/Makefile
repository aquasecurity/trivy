GO = GO111MODULE=on GOFLAGS=-mod=vendor go

.PHONY: deps
deps:
	$(GO) mod download
	$(GO) mod vendor

.PHONY: test
test:
	$(GO) test -v -cover ./...

.PHONY: check
check:
	if [ -d vendor ]; then cp -r vendor/* ${GOPATH}/src/; fi

.PHONY: clean
clean:
	$(GO) clean
