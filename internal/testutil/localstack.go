package testutil

import (
	"context"
	"fmt"
	"os"

	"github.com/moby/moby/api/types/container"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/localstack"
)

func SetupLocalStack(ctx context.Context, version string) (*localstack.LocalStackContainer, string, error) {
	if err := os.Setenv("TESTCONTAINERS_RYUK_DISABLED", "true"); err != nil {
		return nil, "", err
	}

	c, err := localstack.Run(ctx, "localstack/localstack:"+version, testcontainers.CustomizeRequest(
		testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				HostConfigModifier: func(hostConfig *container.HostConfig) {
					hostConfig.AutoRemove = true
				},
			},
		},
	))
	if err != nil {
		return nil, "", err
	}

	p, err := c.MappedPort(ctx, "4566/tcp")
	if err != nil {
		return nil, "", err
	}

	provider, err := testcontainers.NewDockerProvider()
	if err != nil {
		return nil, "", err
	}
	defer provider.Close()

	host, err := provider.DaemonHost(ctx)
	if err != nil {
		return nil, "", err
	}

	return c, fmt.Sprintf("http://%s:%d", host, p.Num()), nil

}
