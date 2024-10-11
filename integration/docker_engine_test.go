//go:build integration

package integration

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/types"

	"github.com/stretchr/testify/require"
)

func TestDockerEngine(t *testing.T) {
	if *update {
		t.Skipf("This test doesn't update golden files")
	}
	tests := []struct {
		name          string
		invalidImage  bool
		ignoreUnfixed bool
		ignoreStatus  []string
		severity      []string
		ignoreIDs     []string
		input         string
		golden        string
		wantErr       string
	}{
		{
			name:   "alpine:3.9",
			input:  "testdata/fixtures/images/alpine-39.tar.gz",
			golden: "testdata/alpine-39.json.golden",
		},
		{
			name: "alpine:3.9, with high and critical severity",
			severity: []string{
				"HIGH",
				"CRITICAL",
			},
			input:  "testdata/fixtures/images/alpine-39.tar.gz",
			golden: "testdata/alpine-39-high-critical.json.golden",
		},
		{
			name: "alpine:3.9, with .trivyignore",
			ignoreIDs: []string{
				"CVE-2019-1549",
				"CVE-2019-14697",
			},
			input:  "testdata/fixtures/images/alpine-39.tar.gz",
			golden: "testdata/alpine-39-ignore-cveids.json.golden",
		},
		{
			name:   "alpine:3.10",
			input:  "testdata/fixtures/images/alpine-310.tar.gz",
			golden: "testdata/alpine-310.json.golden",
		},
		{
			name:   "amazonlinux:1",
			input:  "testdata/fixtures/images/amazon-1.tar.gz",
			golden: "testdata/amazon-1.json.golden",
		},
		{
			name:   "amazonlinux:2",
			input:  "testdata/fixtures/images/amazon-2.tar.gz",
			golden: "testdata/amazon-2.json.golden",
		},
		{
			name:   "almalinux 8",
			input:  "testdata/fixtures/images/almalinux-8.tar.gz",
			golden: "testdata/almalinux-8.json.golden",
		},
		{
			name:   "rocky linux 8",
			input:  "testdata/fixtures/images/rockylinux-8.tar.gz",
			golden: "testdata/rockylinux-8.json.golden",
		},
		{
			name:   "centos 6",
			input:  "testdata/fixtures/images/centos-6.tar.gz",
			golden: "testdata/centos-6.json.golden",
		},
		{
			name:   "centos 7",
			input:  "testdata/fixtures/images/centos-7.tar.gz",
			golden: "testdata/centos-7.json.golden",
		},
		{
			name:          "centos 7, with --ignore-unfixed option",
			ignoreUnfixed: true,
			input:         "testdata/fixtures/images/centos-7.tar.gz",
			golden:        "testdata/centos-7-ignore-unfixed.json.golden",
		},
		{
			name:         "centos 7, with --ignore-status option",
			ignoreStatus: []string{"will_not_fix"},
			input:        "testdata/fixtures/images/centos-7.tar.gz",
			golden:       "testdata/centos-7-ignore-unfixed.json.golden",
		},
		{
			name:          "centos 7, with --ignore-unfixed option, with medium severity",
			ignoreUnfixed: true,
			severity:      []string{"MEDIUM"},
			input:         "testdata/fixtures/images/centos-7.tar.gz",
			golden:        "testdata/centos-7-medium.json.golden",
		},
		{
			name:   "registry.redhat.io/ubi7",
			input:  "testdata/fixtures/images/ubi-7.tar.gz",
			golden: "testdata/ubi-7.json.golden",
		},
		{
			name:   "debian buster/10",
			input:  "testdata/fixtures/images/debian-buster.tar.gz",
			golden: "testdata/debian-buster.json.golden",
		},
		{
			name:          "debian buster/10, with --ignore-unfixed option",
			ignoreUnfixed: true,
			input:         "testdata/fixtures/images/debian-buster.tar.gz",
			golden:        "testdata/debian-buster-ignore-unfixed.json.golden",
		},
		{
			name:         "debian buster/10, with --ignore-status option",
			ignoreStatus: []string{"affected"},
			input:        "testdata/fixtures/images/debian-buster.tar.gz",
			golden:       "testdata/debian-buster-ignore-unfixed.json.golden",
		},
		{
			name:   "debian stretch/9",
			input:  "testdata/fixtures/images/debian-stretch.tar.gz",
			golden: "testdata/debian-stretch.json.golden",
		},
		{
			name:   "distroless base",
			input:  "testdata/fixtures/images/distroless-base.tar.gz",
			golden: "testdata/distroless-base.json.golden",
		},
		{
			name:   "distroless python2.7",
			input:  "testdata/fixtures/images/distroless-python27.tar.gz",
			golden: "testdata/distroless-python27.json.golden",
		},
		{
			name:   "oracle linux 8",
			input:  "testdata/fixtures/images/oraclelinux-8.tar.gz",
			golden: "testdata/oraclelinux-8.json.golden",
		},
		{
			name:   "ubuntu 18.04",
			input:  "testdata/fixtures/images/ubuntu-1804.tar.gz",
			golden: "testdata/ubuntu-1804.json.golden",
		},
		{
			name:          "ubuntu 18.04, with --ignore-unfixed option",
			ignoreUnfixed: true,
			input:         "testdata/fixtures/images/ubuntu-1804.tar.gz",
			golden:        "testdata/ubuntu-1804-ignore-unfixed.json.golden",
		},
		{
			name:   "opensuse leap 15.1",
			input:  "testdata/fixtures/images/opensuse-leap-151.tar.gz",
			golden: "testdata/opensuse-leap-151.json.golden",
		},
		{
			name:   "opensuse tumbleweed",
			input:  "testdata/fixtures/images/opensuse-tumbleweed.tar.gz",
			golden: "testdata/opensuse-tumbleweed.json.golden",
		},
		{
			name:   "sle micro rancher 5.4",
			input:  "testdata/fixtures/images/sle-micro-rancher-5.4_ndb.tar.gz",
			golden: "testdata/sl-micro-rancher5.4.json.golden",
		},
		{
			name:   "photon 3.0",
			input:  "testdata/fixtures/images/photon-30.tar.gz",
			golden: "testdata/photon-30.json.golden",
		},
		{
			name:   "CBL-Mariner 1.0",
			input:  "testdata/fixtures/images/mariner-1.0.tar.gz",
			golden: "testdata/mariner-1.0.json.golden",
		},
		{
			name:   "busybox with Cargo.lock",
			input:  "testdata/fixtures/images/busybox-with-lockfile.tar.gz",
			golden: "testdata/busybox-with-lockfile.json.golden",
		},
		{
			name:         "sad path, invalid image",
			invalidImage: true,
			input:        "badimage:latest",
			wantErr:      "unable to inspect the image (badimage:latest)",
		},
	}

	// Set up testing DB
	cacheDir := initDB(t)

	// Set a temp dir so that modules will not be loaded
	t.Setenv("XDG_DATA_HOME", cacheDir)

	ctx := context.Background()
	defer ctx.Done()

	cli := testutil.NewDockerClient(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.invalidImage {
				testfile, err := os.Open(tt.input)
				require.NoError(t, err, tt.name)
				defer testfile.Close()

				// Ensure image doesn't already exist
				cli.ImageRemove(t, ctx, tt.input)

				// Load image into docker engine
				loadedImage := cli.ImageLoad(t, ctx, tt.input)

				// Tag our image to something unique
				err = cli.ImageTag(ctx, loadedImage, tt.input)
				require.NoError(t, err, tt.name)

				// Cleanup
				t.Cleanup(func() { cli.ImageRemove(t, ctx, tt.input) })
			}

			osArgs := []string{
				"--cache-dir",
				cacheDir,
				"image",
				"--skip-update",
				"--format=json",
			}

			if tt.ignoreUnfixed {
				osArgs = append(osArgs, "--ignore-unfixed")
			}

			if len(tt.ignoreStatus) != 0 {
				osArgs = append(osArgs,
					[]string{
						"--ignore-status",
						strings.Join(tt.ignoreStatus, ","),
					}...,
				)
			}
			if len(tt.severity) != 0 {
				osArgs = append(osArgs,
					[]string{
						"--severity",
						strings.Join(tt.severity, ","),
					}...,
				)
			}
			if len(tt.ignoreIDs) != 0 {
				trivyIgnore := ".trivyignore"
				err := os.WriteFile(trivyIgnore, []byte(strings.Join(tt.ignoreIDs, "\n")), 0444)
				require.NoError(t, err, "failed to write .trivyignore")
				defer os.Remove(trivyIgnore)
			}
			osArgs = append(osArgs, tt.input)

			// Run Trivy
			runTest(t, osArgs, tt.golden, "", types.FormatJSON, runOptions{
				wantErr: tt.wantErr,
				// Container field was removed in Docker Engine v26.0
				// cf. https://github.com/docker/cli/blob/v26.1.3/docs/deprecated.md#container-and-containerconfig-fields-in-image-inspect
				override: overrideFuncs(overrideUID, func(t *testing.T, want, got *types.Report) {
					got.Metadata.ImageConfig.Container = ""
					want.Metadata.ImageConfig.Container = ""
				}),
			})
		})
	}
}
