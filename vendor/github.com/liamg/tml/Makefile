
default: build

build: test
	mkdir -p bin
	go build ./tml/ -o bin/tml 

build-travis: test
	mkdir -p bin/linux-amd64/tml
	mkdir -p bin/darwin-amd64/tml
	GOOS=linux  GOARCH=amd64 go build -o bin/linux-amd64/tml  -ldflags "-X github.com/liamg/tml/version.Version=${TRAVIS_TAG}" ./tml
	GOOS=darwin GOARCH=amd64 go build -o bin/darwin-amd64/tml -ldflags "-X github.com/liamg/tml/version.Version=${TRAVIS_TAG}" ./tml

test:
	go vet ./...
	go test -v ./...

.PHONY: build test 
 