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
		name          string
		imageTag      string
		invalidImage  bool
		ignoreUnfixed bool
		severity      []string
		ignoreIDs     []string
		input         string
		golden        string
		wantErr       string
	}{
		{
			name:     "alpine:3.9",
			imageTag: "alpine:3.9",
			input:    "testdata/fixtures/images/alpine-39.tar.gz",
			golden:   "testdata/alpine-39.json.golden",
		},
		{
			name:     "alpine:3.9, with high and critical severity",
			severity: []string{"HIGH", "CRITICAL"},
			imageTag: "alpine:3.9",
			input:    "testdata/fixtures/images/alpine-39.tar.gz",
			golden:   "testdata/alpine-39-high-critical.json.golden",
		},
		{
			name:      "alpine:3.9, with .trivyignore",
			imageTag:  "alpine:3.9",
			ignoreIDs: []string{"CVE-2019-1549", "CVE-2019-14697"},
			input:     "testdata/fixtures/images/alpine-39.tar.gz",
			golden:    "testdata/alpine-39-ignore-cveids.json.golden",
		},
		{
			name:     "alpine:3.10",
			imageTag: "alpine:3.10",
			input:    "testdata/fixtures/images/alpine-310.tar.gz",
			golden:   "testdata/alpine-310.json.golden",
		},
		{
			name:     "amazonlinux:1",
			imageTag: "amazonlinux:1",
			input:    "testdata/fixtures/images/amazon-1.tar.gz",
			golden:   "testdata/amazon-1.json.golden",
		},
		{
			name:     "amazonlinux:2",
			imageTag: "amazonlinux:2",
			input:    "testdata/fixtures/images/amazon-2.tar.gz",
			golden:   "testdata/amazon-2.json.golden",
		},
		{
			name:     "almalinux 8",
			imageTag: "almalinux:8",
			input:    "testdata/fixtures/images/almalinux-8.tar.gz",
			golden:   "testdata/almalinux-8.json.golden",
		},
		{
			name:     "rocky linux 8",
			imageTag: "rockylinux:8",
			input:    "testdata/fixtures/images/rockylinux-8.tar.gz",
			golden:   "testdata/rockylinux-8.json.golden",
		},
		{
			name:     "centos 6",
			imageTag: "centos:6",
			input:    "testdata/fixtures/images/centos-6.tar.gz",
			golden:   "testdata/centos-6.json.golden",
		},
		{
			name:     "centos 7",
			imageTag: "centos:7",
			input:    "testdata/fixtures/images/centos-7.tar.gz",
			golden:   "testdata/centos-7.json.golden",
		},
		{
			name:          "centos 7, with --ignore-unfixed option",
			imageTag:      "centos:7",
			ignoreUnfixed: true,
			input:         "testdata/fixtures/images/centos-7.tar.gz",
			golden:        "testdata/centos-7-ignore-unfixed.json.golden",
		},
		{
			name:          "centos 7, with --ignore-unfixed option, with medium severity",
			imageTag:      "centos:7",
			ignoreUnfixed: true,
			severity:      []string{"MEDIUM"},
			input:         "testdata/fixtures/images/centos-7.tar.gz",
			golden:        "testdata/centos-7-medium.json.golden",
		},
		{
			name:     "registry.redhat.io/ubi7",
			imageTag: "registry.redhat.io/ubi7",
			input:    "testdata/fixtures/images/ubi-7.tar.gz",
			golden:   "testdata/ubi-7.json.golden",
		},
		{
			name:     "debian buster/10",
			imageTag: "debian:buster",
			input:    "testdata/fixtures/images/debian-buster.tar.gz",
			golden:   "testdata/debian-buster.json.golden",
		},
		{
			name:          "debian buster/10, with --ignore-unfixed option",
			ignoreUnfixed: true,
			imageTag:      "debian:buster",
			input:         "testdata/fixtures/images/debian-buster.tar.gz",
			golden:        "testdata/debian-buster-ignore-unfixed.json.golden",
		},
		{
			name:     "debian stretch/9",
			imageTag: "debian:stretch",
			input:    "testdata/fixtures/images/debian-stretch.tar.gz",
			golden:   "testdata/debian-stretch.json.golden",
		},
		{
			name:     "distroless base",
			imageTag: "gcr.io/distroless/base:latest",
			input:    "testdata/fixtures/images/distroless-base.tar.gz",
			golden:   "testdata/distroless-base.json.golden",
		},
		{
			name:     "distroless python2.7",
			imageTag: "gcr.io/distroless/python2.7:latest",
			input:    "testdata/fixtures/images/distroless-python27.tar.gz",
			golden:   "testdata/distroless-python27.json.golden",
		},
		{
			name:     "oracle linux 8",
			imageTag: "oraclelinux:8-slim",
			input:    "testdata/fixtures/images/oraclelinux-8-slim.tar.gz",
			golden:   "testdata/oraclelinux-8-slim.json.golden",
		},
		{
			name:     "ubuntu 18.04",
			imageTag: "ubuntu:18.04",
			input:    "testdata/fixtures/images/ubuntu-1804.tar.gz",
			golden:   "testdata/ubuntu-1804.json.golden",
		},
		{
			name:          "ubuntu 18.04, with --ignore-unfixed option",
			imageTag:      "ubuntu:18.04",
			ignoreUnfixed: true,
			input:         "testdata/fixtures/images/ubuntu-1804.tar.gz",
			golden:        "testdata/ubuntu-1804-ignore-unfixed.json.golden",
		},
		{
			name:     "opensuse leap 15.1",
			imageTag: "opensuse/leap:latest",
			input:    "testdata/fixtures/images/opensuse-leap-151.tar.gz",
			golden:   "testdata/opensuse-leap-151.json.golden",
		},
		{
			name:     "photon 3.0",
			imageTag: "photon:3.0-20190823",
			input:    "testdata/fixtures/images/photon-30.tar.gz",
			golden:   "testdata/photon-30.json.golden",
		},
		{
			name:     "busybox with Cargo.lock",
			imageTag: "busy-cargo:latest",
			input:    "testdata/fixtures/images/busybox-with-lockfile.tar.gz",
			golden:   "testdata/busybox-with-lockfile.json.golden",
		},
		{
			name:         "sad path, invalid image",
			invalidImage: true,
			input:        "badimage:latest",
			wantErr:      "unable to inspect the image (index.docker.io/library/badimage:latest)",
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
				testfile, err := os.Open(tt.input)
				require.NoError(t, err, tt.name)

				// ensure image doesnt already exists
				_, _ = cli.ImageRemove(ctx, tt.input, types.ImageRemoveOptions{
					Force:         true,
					PruneChildren: true,
				})

				// load image into docker engine
				res, err := cli.ImageLoad(ctx, testfile, true)
				require.NoError(t, err, tt.name)
				io.Copy(io.Discard, res.Body)

				// tag our image to something unique
				err = cli.ImageTag(ctx, tt.imageTag, tt.input)
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
			trivyArgs = append(trivyArgs, tt.input)

			err = app.Run(trivyArgs)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			}

			assert.NoError(t, err, tt.name)

			// check for vulnerability output info
			compareReports(t, tt.golden, output)

			// cleanup
			_, err = cli.ImageRemove(ctx, tt.input, types.ImageRemoveOptions{
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
