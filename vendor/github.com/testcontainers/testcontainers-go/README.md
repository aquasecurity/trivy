![Main pipeline](https://github.com/testcontainers/testcontainers-go/workflows/Main%20pipeline/badge.svg?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/testcontainers/testcontainers-go)](https://goreportcard.com/report/github.com/testcontainers/testcontainers-go)
[![GoDoc Reference](https://camo.githubusercontent.com/8609cfcb531fa0f5598a3d4353596fae9336cce3/68747470733a2f2f676f646f632e6f72672f6769746875622e636f6d2f79616e6777656e6d61692f686f772d746f2d6164642d62616467652d696e2d6769746875622d726561646d653f7374617475732e737667)](https://godoc.org/github.com/testcontainers/testcontainers-go)


When I was working on a Zipkin PR I discovered a nice Java library called
[Testcontainers](https://www.testcontainers.org/).

It provides an easy and clean API over the go docker sdk to run, terminate and
connect to containers in your tests.

I found myself comfortable programmatically writing the containers I need to run
an integration/smoke tests. So I started porting this library in Go.

This is an example:

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

func TestNginxLatestReturn(t *testing.T) {
	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        "nginx",
		ExposedPorts: []string{"80/tcp"},
		WaitingFor:   wait.ForHTTP("/"),
	}
	nginxC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Error(err)
	}
	defer nginxC.Terminate(ctx)
	ip, err := nginxC.Host(ctx)
	if err != nil {
		t.Error(err)
	}
	port, err := nginxC.MappedPort(ctx, "80")
	if err != nil {
		t.Error(err)
	}
	resp, err := http.Get(fmt.Sprintf("http://%s:%s", ip, port.Port()))
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d. Got %d.", http.StatusOK, resp.StatusCode)
	}
}
```
This is a simple example, you can create one container in my case using the
`nginx` image. You can get its IP `ip, err := nginxC.GetContainerIpAddress(ctx)` and you
can use it to make a GET: `resp, err := http.Get(fmt.Sprintf("http://%s", ip))`

To clean your environment you can defer the container termination `defer
nginxC.Terminate(ctx, t)`. `t` is `*testing.T` and it is used to notify is the
`defer` failed marking the test as failed.

## Documentation

The documentation lives in [./docs](./docs) and it is rendered at
[golang.testcontainers.org](https://golang.testcontainers.org).
