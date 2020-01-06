// +build integration

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
		imageTag           string
		invalidImage       bool
		testfile           string
		expectedOutputFile string
		expectedError      string
	}{
		{
			name:               "happy path, valid image path, alpine:3.10",
			imageTag:           "alpine:3.10",
			expectedOutputFile: "testdata/alpine-310.json.golden",
			testfile:           "testdata/fixtures/alpine-310.tar.gz",
		},
		{
			name:               "happy path, valid image path, amazonlinux:1",
			imageTag:           "amazonlinux:1",
			expectedOutputFile: "testdata/amazon-1.json.golden",
			testfile:           "testdata/fixtures/amazon-1.tar.gz",
		},
		{
			name:               "happy path, valid image path, centos:6",
			imageTag:           "centos:6",
			expectedOutputFile: "testdata/centos-6.json.golden",
			testfile:           "testdata/fixtures/centos-6.tar.gz",
		},
		{
			name:               "happy path, valid image path, debian:buster",
			imageTag:           "debian:buster",
			expectedOutputFile: "testdata/debian-buster.json.golden",
			testfile:           "testdata/fixtures/debian-buster.tar.gz",
		},
		{
			name:               "happy path, valid image path, distroless:base",
			imageTag:           "gcr.io/distroless/base:latest",
			expectedOutputFile: "testdata/distroless-base.json.golden",
			testfile:           "testdata/fixtures/distroless-base.tar.gz",
		},
		{
			name:               "happy path, valid image path, oraclelinux:6-slim",
			imageTag:           "oraclelinux:6-slim",
			expectedOutputFile: "testdata/oraclelinux-6-slim.json.golden",
			testfile:           "testdata/fixtures/oraclelinux-6-slim.tar.gz",
		},
		{
			name:               "happy path, valid image path, ubuntu:16.04",
			imageTag:           "ubuntu:16.04",
			expectedOutputFile: "testdata/ubuntu-1604.json.golden",
			testfile:           "testdata/fixtures/ubuntu-1604.tar.gz",
		},
		{
			name:          "sad path, invalid image",
			invalidImage:  true,
			testfile:      "badimage:latest",
			expectedError: "error in image scan: failed to analyze image: failed to extract files: failed to get the v2 manifest: Get https://registry-1.docker.io/v2/library/badimage/manifests/latest: http: non-successful response (status=401 body=\"{\\\"errors\\\":[{\\\"code\\\":\\\"UNAUTHORIZED\\\",\\\"message\\\":\\\"authentication required\\\",\\\"detail\\\":[{\\\"Type\\\":\\\"repository\\\",\\\"Class\\\":\\\"\\\",\\\"Name\\\":\\\"library/badimage\\\",\\\"Action\\\":\\\"pull\\\"}]}]}\\n\")",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Copy DB file
			cacheDir := gunzipDB()
			defer os.RemoveAll(cacheDir)

			ctx := context.Background()
			defer ctx.Done()

			cli, err := client.NewClientWithOpts(client.FromEnv)
			require.NoError(t, err, tc.name)

			if !tc.invalidImage {
				testfile, err := os.Open(tc.testfile)
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
				err = cli.ImageTag(ctx, tc.imageTag, tc.testfile)
				require.NoError(t, err, tc.name)
			}

			of, err := ioutil.TempFile("", "integration-docker-engine-output-file-*")
			require.NoError(t, err, tc.name)
			defer os.Remove(of.Name())

			// run trivy
			app := internal.NewApp("dev")
			trivyArgs := []string{"trivy", "--skip-update", "--cache-dir", cacheDir, "--format=json"}
			if !tc.invalidImage {
				trivyArgs = append(trivyArgs, "--output", of.Name())
			}
			trivyArgs = append(trivyArgs, tc.testfile)

			err = app.Run(trivyArgs)
			switch {
			case tc.expectedError != "":
				assert.Equal(t, tc.expectedError, err.Error(), tc.name)
			default:
				assert.NoError(t, err, tc.name)
			}

			if !tc.invalidImage {
				// check for vulnerability output info
				got, err := ioutil.ReadAll(of)
				assert.NoError(t, err, tc.name)
				want, err := ioutil.ReadFile(tc.expectedOutputFile)
				assert.NoError(t, err, tc.name)
				assert.JSONEq(t, string(want), string(got), tc.name)

				// cleanup
				_, err = cli.ImageRemove(ctx, tc.testfile, types.ImageRemoveOptions{
					Force:         true,
					PruneChildren: true,
				})
				assert.NoError(t, err, tc.name)
			}
		})
	}
}
