package testutil

import (
	"context"
	"fmt"
	"os"

	dockercontainer "github.com/docker/docker/api/types/container"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/localstack"
)

func SetupLocalStack(ctx context.Context, version string) (*localstack.LocalStackContainer, string, error) {

	if err := os.Setenv("TESTCONTAINERS_RYUK_DISABLED", "true"); err != nil {
		return nil, "", err
	}

	container, err := localstack.RunContainer(ctx, testcontainers.CustomizeRequest(
		testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image: "localstack/localstack:" + version,
				HostConfigModifier: func(hostConfig *dockercontainer.HostConfig) {
					hostConfig.AutoRemove = true
				},
			},
		},
	))
	if err != nil {
		return nil, "", err
	}

	p, err := container.MappedPort(ctx, "4566/tcp")
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

	return container, fmt.Sprintf("http://%s:%d", host, p.Int()), nil

}
