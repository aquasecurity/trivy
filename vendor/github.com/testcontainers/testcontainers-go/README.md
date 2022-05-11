[![Main pipeline](https://github.com/testcontainers/testcontainers-go/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/testcontainers/testcontainers-go/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/testcontainers/testcontainers-go)](https://goreportcard.com/report/github.com/testcontainers/testcontainers-go)
[![GoDoc Reference](https://camo.githubusercontent.com/8609cfcb531fa0f5598a3d4353596fae9336cce3/68747470733a2f2f676f646f632e6f72672f6769746875622e636f6d2f79616e6777656e6d61692f686f772d746f2d6164642d62616467652d696e2d6769746875622d726561646d653f7374617475732e737667)](https://pkg.go.dev/github.com/testcontainers/testcontainers-go)

Testcontainers-Go is a Go package that makes it simple to create and clean up container-based dependencies for
automated integration/smoke tests. The clean, easy-to-use API enables developers to programmatically define containers
that should be run as part of a test and clean up those resources when the test is done.

Here's an example of a test that spins up an NGINX container validates that it returns 200 for the status code:

```go
package main

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

type nginxContainer struct {
	testcontainers.Container
	URI string
}

func setupNginx(ctx context.Context) (*nginxContainer, error) {
	req := testcontainers.ContainerRequest{
		Image:        "nginx",
		ExposedPorts: []string{"80/tcp"},
		WaitingFor:   wait.ForHTTP("/"),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, err
	}

	ip, err := container.Host(ctx)
	if err != nil {
		return nil, err
	}

	mappedPort, err := container.MappedPort(ctx, "80")
	if err != nil {
		return nil, err
	}

	uri := fmt.Sprintf("http://%s:%s", ip, mappedPort.Port())

	return &nginxContainer{Container: container, URI: uri}, nil
}

func TestIntegrationNginxLatestReturn(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx := context.Background()

	nginxC, err := setupNginx(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Clean up the container after the test is complete
	defer nginxC.Terminate(ctx)

	resp, err := http.Get(nginxC.URI)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status code %d. Got %d.", http.StatusOK, resp.StatusCode)
	}
}
```

Cleaning up your environment after test completion should be accomplished by deferring the container termination, e.g
`defer nginxC.Terminate(ctx)`. Reaper (Ryuk) is also enabled by default to help clean up.

## Documentation

More information about TestContainers-Go can be found in [./docs](./docs), which is rendered at
[golang.testcontainers.org](https://golang.testcontainers.org).
