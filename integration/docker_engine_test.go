//go:build integration
// +build integration

package integration

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/commands"
)

func TestDockerEngine(t *testing.T) {
	tests := []struct {
		name           string
		imageTag       string
		invalidImage   bool
		ignoreUnfixed  bool
		severity       []string
		ignoreIDs      []string
		testfile       string
		wantOutputFile string
		wantError      string
	}{
		{
			name:           "alpine:3.9",
			imageTag:       "alpine:3.9",
			wantOutputFile: "testdata/alpine-39.json.golden",
			testfile:       "testdata/fixtures/images/alpine-39.tar.gz",
		},
		{
			name:           "alpine:3.9, with high and critical severity",
			severity:       []string{"HIGH", "CRITICAL"},
			imageTag:       "alpine:3.9",
			wantOutputFile: "testdata/alpine-39-high-critical.json.golden",
			testfile:       "testdata/fixtures/images/alpine-39.tar.gz",
		},
		{
			name:           "alpine:3.9, with .trivyignore",
			imageTag:       "alpine:3.9",
			ignoreIDs:      []string{"CVE-2019-1549", "CVE-2019-14697"},
			wantOutputFile: "testdata/alpine-39-ignore-cveids.json.golden",
			testfile:       "testdata/fixtures/images/alpine-39.tar.gz",
		},
		{
			name:           "alpine:3.10",
			imageTag:       "alpine:3.10",
			wantOutputFile: "testdata/alpine-310.json.golden",
			testfile:       "testdata/fixtures/images/alpine-310.tar.gz",
		},
		{
			name:           "amazonlinux:1",
			imageTag:       "amazonlinux:1",
			wantOutputFile: "testdata/amazon-1.json.golden",
			testfile:       "testdata/fixtures/images/amazon-1.tar.gz",
		},
		{
			name:           "amazonlinux:2",
			imageTag:       "amazonlinux:2",
			wantOutputFile: "testdata/amazon-2.json.golden",
			testfile:       "testdata/fixtures/images/amazon-2.tar.gz",
		},
		// TODO: fix them
		//{
		//	name:           "happy path, valid image path, centos:6",
		//	imageTag:       "centos:6",
		//	wantOutputFile: "testdata/centos-6.json.golden",
		//	testfile:       "testdata/fixtures/images/centos-6.tar.gz",
		//},
		//{
		//	name:           "happy path, valid image path, centos:7",
		//	imageTag:       "centos:7",
		//	wantOutputFile: "testdata/centos-7.json.golden",
		//	testfile:       "testdata/fixtures/images/centos-7.tar.gz",
		//},
		//{
		//	name:           "happy path, valid image path, centos:7, with --ignore-unfixed option",
		//	imageTag:       "centos:7",
		//	ignoreUnfixed:  true,
		//	wantOutputFile: "testdata/centos-7-ignore-unfixed.json.golden",
		//	testfile:       "testdata/fixtures/images/centos-7.tar.gz",
		//},
		//{
		//	name:           "happy path, valid image path, centos:7, with --ignore-unfixed option, with low and high severity",
		//	imageTag:       "centos:7",
		//	ignoreUnfixed:  true,
		//	severity:       []string{"LOW", "HIGH"},
		//	wantOutputFile: "testdata/centos-7-low-high.json.golden",
		//	testfile:       "testdata/fixtures/images/centos-7.tar.gz",
		//},
		//{
		//	name:           "happy path, valid image path, registry.redhat.io/ubi7",
		//	imageTag:       "registry.redhat.io/ubi7",
		//	wantOutputFile: "testdata/ubi-7.json.golden",
		//	testfile:       "testdata/fixtures/images/ubi-7.tar.gz",
		//},
		{
			name:           "almalinux 8",
			imageTag:       "almalinux:8",
			wantOutputFile: "testdata/almalinux-8.json.golden",
			testfile:       "testdata/fixtures/images/almalinux-8.tar.gz",
		},
		{
			name:           "debian buster/10",
			imageTag:       "debian:buster",
			wantOutputFile: "testdata/debian-buster.json.golden",
			testfile:       "testdata/fixtures/images/debian-buster.tar.gz",
		},
		{
			name:           "debian buster/10, with --ignore-unfixed option",
			ignoreUnfixed:  true,
			imageTag:       "debian:buster",
			wantOutputFile: "testdata/debian-buster-ignore-unfixed.json.golden",
			testfile:       "testdata/fixtures/images/debian-buster.tar.gz",
		},
		{
			name:           "debian stretch/9",
			imageTag:       "debian:stretch",
			wantOutputFile: "testdata/debian-stretch.json.golden",
			testfile:       "testdata/fixtures/images/debian-stretch.tar.gz",
		},
		{
			name:           "distroless base",
			imageTag:       "gcr.io/distroless/base:latest",
			wantOutputFile: "testdata/distroless-base.json.golden",
			testfile:       "testdata/fixtures/images/distroless-base.tar.gz",
		},
		{
			name:           "distroless python2.7",
			imageTag:       "gcr.io/distroless/python2.7:latest",
			wantOutputFile: "testdata/distroless-python27.json.golden",
			testfile:       "testdata/fixtures/images/distroless-python27.tar.gz",
		},
		{
			name:           "oracle linux 8",
			imageTag:       "oraclelinux:8-slim",
			wantOutputFile: "testdata/oraclelinux-8-slim.json.golden",
			testfile:       "testdata/fixtures/images/oraclelinux-8-slim.tar.gz",
		},
		{
			name:           "ubuntu 18.04",
			imageTag:       "ubuntu:18.04",
			wantOutputFile: "testdata/ubuntu-1804.json.golden",
			testfile:       "testdata/fixtures/images/ubuntu-1804.tar.gz",
		},
		{
			name:           "ubuntu 18.04, with --ignore-unfixed option",
			imageTag:       "ubuntu:18.04",
			ignoreUnfixed:  true,
			wantOutputFile: "testdata/ubuntu-1804-ignore-unfixed.json.golden",
			testfile:       "testdata/fixtures/images/ubuntu-1804.tar.gz",
		},
		{
			name:           "happy path, valid image path, opensuse leap 15.1",
			imageTag:       "opensuse/leap:latest",
			wantOutputFile: "testdata/opensuse-leap-151.json.golden",
			testfile:       "testdata/fixtures/images/opensuse-leap-151.tar.gz",
		},
		{
			name:           "happy path, valid image path, photon 3.0",
			imageTag:       "photon:3.0-20190823",
			wantOutputFile: "testdata/photon-30.json.golden",
			testfile:       "testdata/fixtures/images/photon-30.tar.gz",
		},
		{
			name:           "buxybox with Cargo.lock",
			imageTag:       "busy-cargo:latest",
			wantOutputFile: "testdata/busybox-with-lockfile.json.golden",
			testfile:       "testdata/fixtures/images/busybox-with-lockfile.tar.gz",
		},
		{
			name:         "sad path, invalid image",
			invalidImage: true,
			testfile:     "badimage:latest",
			wantError:    "unable to inspect the image (index.docker.io/library/badimage:latest)",
		},
	}

	// Set up testing DB
	cacheDir := initDB(t)

	ctx := context.Background()
	defer ctx.Done()

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.invalidImage {
				testfile, err := os.Open(tt.testfile)
				require.NoError(t, err, tt.name)

				// ensure image doesnt already exists
				_, _ = cli.ImageRemove(ctx, tt.testfile, types.ImageRemoveOptions{
					Force:         true,
					PruneChildren: true,
				})

				// load image into docker engine
				res, err := cli.ImageLoad(ctx, testfile, true)
				require.NoError(t, err, tt.name)
				io.Copy(io.Discard, res.Body)

				// tag our image to something unique
				err = cli.ImageTag(ctx, tt.imageTag, tt.testfile)
				require.NoError(t, err, tt.name)
			}

			tmpDir := t.TempDir()
			output := filepath.Join(tmpDir, "result.json")

			// run trivy
			app := commands.NewApp("dev")
			trivyArgs := []string{"trivy", "--cache-dir", cacheDir, "image",
				"--skip-update", "--format=json", "--output", output}

			if tt.ignoreUnfixed {
				trivyArgs = append(trivyArgs, "--ignore-unfixed")
			}
			if len(tt.severity) != 0 {
				trivyArgs = append(trivyArgs,
					[]string{"--severity", strings.Join(tt.severity, ",")}...,
				)
			}
			if len(tt.ignoreIDs) != 0 {
				trivyIgnore := ".trivyignore"
				err = os.WriteFile(trivyIgnore, []byte(strings.Join(tt.ignoreIDs, "\n")), 0444)
				assert.NoError(t, err, "failed to write .trivyignore")
				defer os.Remove(trivyIgnore)
			}
			trivyArgs = append(trivyArgs, tt.testfile)

			err = app.Run(trivyArgs)
			if tt.wantError != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantError, tt.name)
				return
			}

			assert.NoError(t, err, tt.name)

			// check for vulnerability output info
			compareReports(t, tt.wantOutputFile, output)

			// cleanup
			_, err = cli.ImageRemove(ctx, tt.testfile, types.ImageRemoveOptions{
				Force:         true,
				PruneChildren: true,
			})
			_, err = cli.ImageRemove(ctx, tt.imageTag, types.ImageRemoveOptions{
				Force:         true,
				PruneChildren: true,
			})
			assert.NoError(t, err, tt.name)
		})
	}
}
