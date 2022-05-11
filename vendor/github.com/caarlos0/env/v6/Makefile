SOURCE_FILES?=./...
TEST_PATTERN?=.

export GO111MODULE := on

setup:
	go mod tidy
.PHONY: setup

build:
	go build
.PHONY: build

test:
	go test -v -failfast -race -coverpkg=./... -covermode=atomic -coverprofile=coverage.txt $(SOURCE_FILES) -run $(TEST_PATTERN) -timeout=2m
.PHONY: test

cover: test
	go tool cover -html=coverage.txt
.PHONY: cover

fmt:
	find . -name '*.go' -not -wholename './vendor/*' | while read -r file; do gofmt -w -s "$$file"; goimports -w "$$file"; done
.PHONY: fmt

lint:
	./bin/golangci-lint run ./...
.PHONY: lint

ci: build test
.PHONY: ci

card:
	wget -O card.png -c "https://og.caarlos0.dev/**env**: parse envs to structs.png?theme=light&md=1&fontSize=100px&images=https://github.com/caarlos0.png"
.PHONY: card

.DEFAULT_GOAL := ci
