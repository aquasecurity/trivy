//go:build integration

package integration

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/types"
)

// TestDockerEngine tests scanning images via Docker Engine API.
//
// Golden files are shared with TestTar.
func TestDockerEngine(t *testing.T) {
	if *update {
		t.Skipf("Skipping TestDockerEngine when -update flag is set. Golden files should be updated via TestTar.")
	}

	tests := []struct {
		name          string
		invalidImage  bool
		ignoreUnfixed bool
		ignoreStatus  []string
		severity      []string
		ignoreIDs     []string
		maxImageSize  string
		input         string
		golden        string
		wantErr       string
	}{
		{
			name:   "alpine:3.9",
			input:  "testdata/fixtures/images/alpine-39.tar.gz",
			golden: goldenAlpine39,
		},
		{
			name:         "alpine:3.9, with max image size",
			maxImageSize: "100mb",
			input:        "testdata/fixtures/images/alpine-39.tar.gz",
			golden:       goldenAlpine39,
		},
		{
			name: "alpine:3.9, with high and critical severity",
			severity: []string{
				"HIGH",
				"CRITICAL",
			},
			input:  "testdata/fixtures/images/alpine-39.tar.gz",
			golden: goldenAlpine39HighCritical,
		},
		{
			name: "alpine:3.9, with .trivyignore",
			ignoreIDs: []string{
				"CVE-2019-1549",
				"CVE-2019-14697",
			},
			input:  "testdata/fixtures/images/alpine-39.tar.gz",
			golden: goldenAlpine39IgnoreCVEIDs,
		},
		{
			name:   "alpine:3.10",
			input:  "testdata/fixtures/images/alpine-310.tar.gz",
			golden: goldenAlpine310JSON,
		},
		{
			name:   "amazonlinux:1",
			input:  "testdata/fixtures/images/amazon-1.tar.gz",
			golden: goldenAmazon1,
		},
		{
			name:   "amazonlinux:2",
			input:  "testdata/fixtures/images/amazon-2.tar.gz",
			golden: goldenAmazon2,
		},
		{
			name:   "almalinux 8",
			input:  "testdata/fixtures/images/almalinux-8.tar.gz",
			golden: goldenAlmaLinux8,
		},
		{
			name:   "rocky linux 8",
			input:  "testdata/fixtures/images/rockylinux-8.tar.gz",
			golden: goldenRockyLinux8,
		},
		{
			name:   "centos 6",
			input:  "testdata/fixtures/images/centos-6.tar.gz",
			golden: goldenCentOS6,
		},
		{
			name:   "centos 7",
			input:  "testdata/fixtures/images/centos-7.tar.gz",
			golden: goldenCentOS7,
		},
		{
			name:          "centos 7, with --ignore-unfixed option",
			ignoreUnfixed: true,
			input:         "testdata/fixtures/images/centos-7.tar.gz",
			golden:        goldenCentOS7IgnoreUnfixed,
		},
		{
			name:         "centos 7, with --ignore-status option",
			ignoreStatus: []string{"will_not_fix"},
			input:        "testdata/fixtures/images/centos-7.tar.gz",
			golden:       goldenCentOS7IgnoreUnfixed,
		},
		{
			name:          "centos 7, with --ignore-unfixed option, with medium severity",
			ignoreUnfixed: true,
			severity:      []string{"MEDIUM"},
			input:         "testdata/fixtures/images/centos-7.tar.gz",
			golden:        goldenCentOS7Medium,
		},
		{
			name:   "registry.redhat.io/ubi7",
			input:  "testdata/fixtures/images/ubi-7.tar.gz",
			golden: goldenUBI7,
		},
		{
			name:   "debian buster/10",
			input:  "testdata/fixtures/images/debian-buster.tar.gz",
			golden: goldenDebianBuster,
		},
		{
			name:          "debian buster/10, with --ignore-unfixed option",
			ignoreUnfixed: true,
			input:         "testdata/fixtures/images/debian-buster.tar.gz",
			golden:        goldenDebianBusterIgnoreUnfixed,
		},
		{
			name:         "debian buster/10, with --ignore-status option",
			ignoreStatus: []string{"affected"},
			input:        "testdata/fixtures/images/debian-buster.tar.gz",
			golden:       goldenDebianBusterIgnoreUnfixed,
		},
		{
			name:   "debian stretch/9",
			input:  "testdata/fixtures/images/debian-stretch.tar.gz",
			golden: goldenDebianStretch,
		},
		{
			name:   "distroless base",
			input:  "testdata/fixtures/images/distroless-base.tar.gz",
			golden: goldenDistrolessBase,
		},
		{
			name:   "distroless python2.7",
			input:  "testdata/fixtures/images/distroless-python27.tar.gz",
			golden: goldenDistrolessPython27,
		},
		{
			name:   "oracle linux 8",
			input:  "testdata/fixtures/images/oraclelinux-8.tar.gz",
			golden: goldenOracleLinux8,
		},
		{
			name:   "ubuntu 18.04",
			input:  "testdata/fixtures/images/ubuntu-1804.tar.gz",
			golden: goldenUbuntu1804,
		},
		{
			name:          "ubuntu 18.04, with --ignore-unfixed option",
			ignoreUnfixed: true,
			input:         "testdata/fixtures/images/ubuntu-1804.tar.gz",
			golden:        goldenUbuntu1804IgnoreUnfixed,
		},
		{
			name:   "opensuse leap 15.1",
			input:  "testdata/fixtures/images/opensuse-leap-151.tar.gz",
			golden: goldenOpenSUSELeap151,
		},
		{
			name:   "opensuse tumbleweed",
			input:  "testdata/fixtures/images/opensuse-tumbleweed.tar.gz",
			golden: goldenOpenSUSETumbleweed,
		},
		{
			name:   "sle micro rancher 5.4",
			input:  "testdata/fixtures/images/sle-micro-rancher-5.4_ndb.tar.gz",
			golden: goldenSLMicroRancher54,
		},
		{
			name:   "photon 3.0",
			input:  "testdata/fixtures/images/photon-30.tar.gz",
			golden: goldenPhoton30,
		},
		{
			name:   "CBL-Mariner 1.0",
			input:  "testdata/fixtures/images/mariner-1.0.tar.gz",
			golden: goldenMariner10,
		},
		{
			name:   "busybox with Cargo.lock",
			input:  "testdata/fixtures/images/busybox-with-lockfile.tar.gz",
			golden: goldenBusyboxWithLockfile,
		},
		{
			name:         "sad path, invalid image",
			invalidImage: true,
			input:        "badimage:latest",
			wantErr:      "unable to inspect the image (badimage:latest)",
		},
		{
			name:         "sad path, image size is larger than the maximum",
			input:        "testdata/fixtures/images/alpine-39.tar.gz",
			maxImageSize: "3mb",
			wantErr:      "uncompressed layers size 5.8MB exceeds maximum allowed size 3MB",
		},
	}

	// Set up testing DB
	cacheDir := initDB(t)

	// Set a temp dir so that modules will not be loaded
	t.Setenv("XDG_DATA_HOME", cacheDir)

	ctx := t.Context()
	defer ctx.Done()

	cli := testutil.NewDockerClient(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			imageName := tt.input
			if !tt.invalidImage {
				// Removes any existing images with conflicting RepoTags and loading images
				imageName = cli.ImageCleanLoad(t, ctx, tt.input)
			}

			osArgs := []string{
				"image",
				imageName,
				"--cache-dir",
				cacheDir,
				"--quiet",
				"--skip-db-update",
				"--format=json",
				"--list-all-pkgs=false",
				"--image-src=docker",
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
				err := os.WriteFile(trivyIgnore, []byte(strings.Join(tt.ignoreIDs, "\n")), 0o444)
				require.NoError(t, err, "failed to write .trivyignore")
				defer os.Remove(trivyIgnore)
			}

			if tt.maxImageSize != "" {
				osArgs = append(osArgs, []string{
					"--max-image-size",
					tt.maxImageSize,
				}...)
			}

			// Run Trivy
			runTest(t, osArgs, tt.golden, types.FormatJSON, runOptions{
				wantErr:  tt.wantErr,
				fakeUUID: "3ff14136-e09f-4df9-80ea-%012d",
				// Image config fields were removed
				override: overrideFuncs(overrideUID, overrideDockerRemovedFields, func(t *testing.T, want, got *types.Report) {
					// Override ArtifactName to match the archive file path
					got.ArtifactName = tt.input

					// Override Result.Target for each result to match golden file expectations
					require.Len(t, got.Results, len(want.Results))
					for i := range got.Results {
						got.Results[i].Target = want.Results[i].Target
					}
				}),
			})
		})
	}
}
