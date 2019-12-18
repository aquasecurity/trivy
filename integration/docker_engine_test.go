// +build integration

package integration

import (
	"context"
	"io/ioutil"
	"os"
	"testing"

	"github.com/aquasecurity/trivy/internal"

	"github.com/docker/docker/client"

	"github.com/stretchr/testify/assert"
)

func TestRun_WithDockerEngine(t *testing.T) {
	f, err := os.Open("testdata/alpine-310.tar.gz")
	defer f.Close()
	assert.NoError(t, err)

	cli, err := client.NewClientWithOpts(client.FromEnv)
	assert.NoError(t, err)

	// load image into docker engine
	_, err = cli.ImageLoad(context.Background(), f, true)
	assert.NoError(t, err)

	// run trivy
	of, _ := ioutil.TempFile("", "integration-docker-engine-*")
	defer func() {
		os.Remove(of.Name())
	}()
	app := internal.NewApp("dev")
	assert.NoError(t, app.Run([]string{"--skip-update", "alpine:3.10", "--output", of.Name()}))

}
