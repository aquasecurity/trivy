package integration

import (
	"context"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/stretchr/testify/assert"
)

func TestRun_WithDockerEngine(t *testing.T) {
	testCases := []struct {
		name               string
		testfile           string
		expectedOutputFile string
		expectedError      error
	}{
		{
			name:               "happy path, alpine:3.10",
			expectedOutputFile: "testdata/alpine-310.json.golden",
			testfile:           "testdata/fixtures/alpine-310.tar.gz",
		},
	}

	for _, tc := range testCases {
		ctx := context.Background()
		testfile, _ := os.Open(tc.testfile)
		cli, err := client.NewClientWithOpts(client.FromEnv)
		require.NoError(t, err, tc.name)

		// ensure image doesnt already exists
		_, _ = cli.ImageRemove(ctx, tc.testfile, types.ImageRemoveOptions{
			Force:         true,
			PruneChildren: true,
		})

		// load image into docker engine
		_, err = cli.ImageLoad(ctx, testfile, true)
		require.NoError(t, err, tc.name)

		// tag our image to something unique
		err = cli.ImageTag(ctx, "alpine:3.10", tc.testfile)
		require.NoError(t, err, tc.name)

		// run trivy
		of, err := ioutil.TempFile("", "integration-docker-engine-*")
		defer func() {
			os.Remove(of.Name())
		}()
		require.NoError(t, err, tc.name)
		app := internal.NewApp("dev")
		assert.NoError(t, app.Run([]string{"--skip-update", "--quiet", "--format=json", "--output", of.Name(), tc.testfile}), tc.name)

		// check for vulnerability output info
		got, err := ioutil.ReadAll(of)
		assert.NoError(t, err, tc.name)
		want, err := ioutil.ReadFile(tc.expectedOutputFile)
		assert.NoError(t, err, tc.name)
		assert.JSONEq(t, string(want), string(got))

		// cleanup
		_, err = cli.ImageRemove(ctx, tc.testfile, types.ImageRemoveOptions{
			Force:         true,
			PruneChildren: true,
		})
		assert.NoError(t, err, tc.name)
	}

}
