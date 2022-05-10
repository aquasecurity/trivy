PATH := ${PWD}/_tools/bin:${PWD}/bin:${PATH}
export GO111MODULE=off

all: setup test_all

.PHONY: setup generate test_all test test_clientcompat

setup:
	./check_protoc_version.sh
	GOPATH="$$PWD/_tools" GOBIN="$$PWD/_tools/bin" go get github.com/twitchtv/retool
	./_tools/bin/retool build

generate:
	# Recompile and install generator
	GOBIN="$$PWD/bin" go install -v ./protoc-gen-twirp
	# Generate code from go:generate comments
	go generate ./...

test_all: setup test test_clientcompat

test: generate
	./_tools/bin/errcheck ./internal/twirptest
	go test -race ./...

test_clientcompat: generate
	GOBIN="$$PWD/bin" go install ./clientcompat
	GOBIN="$$PWD/bin" go install ./clientcompat/gocompat
	./bin/clientcompat -client ./bin/gocompat
