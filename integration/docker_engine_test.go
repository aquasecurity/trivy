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

type overrideValues struct {
	artifactID string
	imageID    string
}

var (
	alpineIDs = overrideValues{
		artifactID: "sha256:243ee36277d8f2a79a980373843fe7834a484a024cd7e647d6db3d0434335e6b",
		imageID:    "sha256:e1b6a1e6b446c39fa12f218e3050e59b47a870de1b1afca840dce65e913b196f",
	}

	centOS7IDs = overrideValues{
		artifactID: "sha256:14bd400fe6aba45977110fadb29ab402fed2356ae68d071ed8e6ffe95ec4e387",
		imageID:    "sha256:c51c4bac51fc7a3d6b6035336eb6a3cc9d57113dd1c10b2109e14dfc3a509740",
	}

	debianBusterIDs = overrideValues{
		artifactID: "sha256:542c2a0b2641139673b479e67ae5bd3e6c62559e3fc882dcf2679b6b0ffb9837",
		imageID:    "sha256:c46a5c17bdd6698cc02e4dd15d033898840e1e0f8016dcc86bb1f5d3239a9cb6",
	}

	ubuntu1804IDs = overrideValues{
		artifactID: "sha256:133f1c0f30523d26ea2686df45a950b80fb957f8da83c10c01b95df3acfeedc6",
		imageID:    "sha256:50c3ea3e170e9e02f880dd630d46f6bafd0966066b7d5ff1424e4268412c5344",
	}
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
		override      overrideValues
		golden        string
		wantErr       string
	}{
		{
			name:     "alpine:3.9",
			input:    "testdata/fixtures/images/alpine-39.tar.gz",
			golden:   goldenAlpine39,
			override: alpineIDs,
		},
		{
			name:         "alpine:3.9, with max image size",
			maxImageSize: "100mb",
			input:        "testdata/fixtures/images/alpine-39.tar.gz",
			golden:       goldenAlpine39,
			override:     alpineIDs,
		},
		{
			name: "alpine:3.9, with high and critical severity",
			severity: []string{
				"HIGH",
				"CRITICAL",
			},
			input:    "testdata/fixtures/images/alpine-39.tar.gz",
			golden:   goldenAlpine39HighCritical,
			override: alpineIDs,
		},
		{
			name: "alpine:3.9, with .trivyignore",
			ignoreIDs: []string{
				"CVE-2019-1549",
				"CVE-2019-14697",
			},
			input:    "testdata/fixtures/images/alpine-39.tar.gz",
			golden:   goldenAlpine39IgnoreCVEIDs,
			override: alpineIDs,
		},
		{
			name:   "alpine:3.10",
			input:  "testdata/fixtures/images/alpine-310.tar.gz",
			golden: goldenAlpine310JSON,
			override: overrideValues{
				artifactID: "sha256:61bd381a03b7e96b5950ac465077b9b104cd7ac5a38aa57b64ae0c99bb2470d0",
				imageID:    "sha256:f12582b2f2190f350e3904462c1c23aaf366b4f76705e97b199f9bbded1d816a",
			},
		},
		{
			name:   "amazonlinux:1",
			input:  "testdata/fixtures/images/amazon-1.tar.gz",
			golden: goldenAmazon1,
			override: overrideValues{
				artifactID: "sha256:372784e31f6a7c4efc3d433e193d668ac61d4e1533e308267cdf1bffb7d0dafb",
				imageID:    "sha256:83b15d0365d6ff7b7c45595bf29a999cdcc03d8d7899fcb74639319ad3f9f18a",
			},
		},
		{
			name:   "amazonlinux:2",
			input:  "testdata/fixtures/images/amazon-2.tar.gz",
			golden: goldenAmazon2,
			override: overrideValues{
				artifactID: "sha256:9ed60ac6eedb461967fd109f8721d8761379d6f38a6ea770d10fbc9a280dd1a6",
				imageID:    "sha256:b553b1064cde62ceee90a8575f4954ef9adda2e45a9e712fbcc67b63114cd940",
			},
		},
		{
			name:   "almalinux 8",
			input:  "testdata/fixtures/images/almalinux-8.tar.gz",
			golden: goldenAlmaLinux8,
			override: overrideValues{
				artifactID: "sha256:2ef11ad6245281caff084e034208cd2a71e195405cb15396feb6d4e7cf83a587",
				imageID:    "sha256:52318004f70433054028789494879e77893a956437fb3a4842b69a1a762e83f4",
			},
		},
		{
			name:   "rocky linux 8",
			input:  "testdata/fixtures/images/rockylinux-8.tar.gz",
			golden: goldenRockyLinux8,
			override: overrideValues{
				artifactID: "sha256:280a62f2a00f406b1e74187ea60f0fe95de83b9a5a5dfaef382b7c58ce6fd196",
				imageID:    "sha256:566c2bd67e04ad98ca170128846ed3ab326ff90caad4a1715ed4f47939cc3f69",
			},
		},
		{
			name:   "centos 6",
			input:  "testdata/fixtures/images/centos-6.tar.gz",
			golden: goldenCentOS6,
			override: overrideValues{
				artifactID: "sha256:e910d8a213217aefe45b1cc7923bda2a60398f6d3e0d958926892abff9c10da4",
				imageID:    "sha256:8b35caa27ab5e27bdf5aef411cd6ee0b6c7ad7777cb9cfcc37f2949ca273cdb5",
			},
		},
		{
			name:     "centos 7",
			input:    "testdata/fixtures/images/centos-7.tar.gz",
			golden:   goldenCentOS7,
			override: centOS7IDs,
		},
		{
			name:          "centos 7, with --ignore-unfixed option",
			ignoreUnfixed: true,
			input:         "testdata/fixtures/images/centos-7.tar.gz",
			golden:        goldenCentOS7IgnoreUnfixed,
			override:      centOS7IDs,
		},
		{
			name:         "centos 7, with --ignore-status option",
			ignoreStatus: []string{"will_not_fix"},
			input:        "testdata/fixtures/images/centos-7.tar.gz",
			golden:       goldenCentOS7IgnoreUnfixed,
			override:     centOS7IDs,
		},
		{
			name:          "centos 7, with --ignore-unfixed option, with medium severity",
			ignoreUnfixed: true,
			severity:      []string{"MEDIUM"},
			input:         "testdata/fixtures/images/centos-7.tar.gz",
			golden:        goldenCentOS7Medium,
			override:      centOS7IDs,
		},
		{
			name:   "registry.redhat.io/ubi7",
			input:  "testdata/fixtures/images/ubi-7.tar.gz",
			golden: goldenUBI7,
			override: overrideValues{
				artifactID: "sha256:af6cb66f90c404bc6c3d69c3d9f16c10c272af173a236a17fd4b9fa7f791a4eb",
				imageID:    "sha256:a80dd41cbeea43204ae0f77c7e18a39512563803f85425fc6cdab45f52158e73",
			},
		},
		{
			name:     "debian buster/10",
			input:    "testdata/fixtures/images/debian-buster.tar.gz",
			golden:   goldenDebianBuster,
			override: debianBusterIDs,
		},
		{
			name:          "debian buster/10, with --ignore-unfixed option",
			ignoreUnfixed: true,
			input:         "testdata/fixtures/images/debian-buster.tar.gz",
			golden:        goldenDebianBusterIgnoreUnfixed,
			override:      debianBusterIDs,
		},
		{
			name:         "debian buster/10, with --ignore-status option",
			ignoreStatus: []string{"affected"},
			input:        "testdata/fixtures/images/debian-buster.tar.gz",
			golden:       goldenDebianBusterIgnoreUnfixed,
			override:     debianBusterIDs,
		},
		{
			name:   "debian stretch/9",
			input:  "testdata/fixtures/images/debian-stretch.tar.gz",
			golden: goldenDebianStretch,
			override: overrideValues{
				artifactID: "sha256:ae095a2b1168c65ba0300011f1eda9a792f3f6a2ee0b50c899be29c652fb0439",
				imageID:    "sha256:fc77e6160638c0695323710349cb88597e451f9e4ff265e7f1fea888aead83fb",
			},
		},
		{
			name:   "distroless base",
			input:  "testdata/fixtures/images/distroless-base.tar.gz",
			golden: goldenDistrolessBase,
			override: overrideValues{
				artifactID: "sha256:50b91b7954a592a5582854a23f16ca5d8d206a70ce68eb2c84f81721546050fa",
				imageID:    "sha256:2257d71271eb9b723b25d7dc17998ca0cf3dd3ffb145c68addebabb6956633d8",
			},
		},
		{
			name:   "distroless python2.7",
			input:  "testdata/fixtures/images/distroless-python27.tar.gz",
			golden: goldenDistrolessPython27,
			override: overrideValues{
				artifactID: "sha256:e13c0afa7d2811598be25b369cd3dc78c455fd0a5f8415993dd2f46d360ccd51",
				imageID:    "sha256:eb04cafc9222da50d0647e515e9409712cf8c9ce0e6ea149e24cf01525dfd613",
			},
		},
		{
			name:   "oracle linux 8",
			input:  "testdata/fixtures/images/oraclelinux-8.tar.gz",
			golden: goldenOracleLinux8,
			override: overrideValues{
				artifactID: "sha256:a818222f173267637277bd66d4a3dddcd7a271ea5686d72848b2006ab4f2b999",
				imageID:    "sha256:5bad2539f9e86fe1c81636eed263ab8166b7a6508ebaa1084ec5695fd4855fe1",
			},
		},
		{
			name:     "ubuntu 18.04",
			input:    "testdata/fixtures/images/ubuntu-1804.tar.gz",
			golden:   goldenUbuntu1804,
			override: ubuntu1804IDs,
		},
		{
			name:          "ubuntu 18.04, with --ignore-unfixed option",
			ignoreUnfixed: true,
			input:         "testdata/fixtures/images/ubuntu-1804.tar.gz",
			golden:        goldenUbuntu1804IgnoreUnfixed,
			override:      ubuntu1804IDs,
		},
		{
			name:   "opensuse leap 15.1",
			input:  "testdata/fixtures/images/opensuse-leap-151.tar.gz",
			golden: goldenOpenSUSELeap151,
			override: overrideValues{
				artifactID: "sha256:b48df6bf517580ff3b846112870f09d1a42399af52a740ce69233ba16d5228f0",
				imageID:    "sha256:38d0b4bb21b5e2095d0ce40c69c4d24e4ae0e76bbe4a45db53afe87d2e1ba228",
			},
		},
		{
			name:   "opensuse tumbleweed",
			input:  "testdata/fixtures/images/opensuse-tumbleweed.tar.gz",
			golden: goldenOpenSUSETumbleweed,
			override: overrideValues{
				artifactID: "sha256:28c7ebf409a2ca8a1d33d5479a19a543f228baec9b22f41df7dfacd95ca6ed0e",
				imageID:    "sha256:b59aaf21088bbdd92253b5a3d415a4f48a2103007935840a651ac691284a051e",
			},
		},
		{
			name:   "sle micro rancher 5.4",
			input:  "testdata/fixtures/images/sle-micro-rancher-5.4_ndb.tar.gz",
			golden: goldenSLMicroRancher54,
			override: overrideValues{
				artifactID: "sha256:6c1e0eadb53697c85176149ead4287154dfbc1dd91ef439d199a84fd7c60dc59",
				imageID:    "sha256:6e58434b86592f28909d8fafc030694d8c6b630eeb94ad4208431b207a6acd1a",
			},
		},
		{
			name:   "photon 3.0",
			input:  "testdata/fixtures/images/photon-30.tar.gz",
			golden: goldenPhoton30,
			override: overrideValues{
				artifactID: "sha256:2b7cef41f06fa33e05c64f408fcda876d57d87141aa4ee1fb8a50fb56b875b84",
				imageID:    "sha256:0041aaabd5852bf345e8f6d70f8596c0a0ab9c15695193977bfa3abc58d3a41d",
			},
		},
		{
			name:   "CBL-Mariner 1.0",
			input:  "testdata/fixtures/images/mariner-1.0.tar.gz",
			golden: goldenMariner10,
			override: overrideValues{
				artifactID: "sha256:e85742037b190a22f7ff747e466bd66c302bbc7266f04c7518ba9ab146ca7f43",
				imageID:    "sha256:330dd5ae6d537d2dc18e89a56409a2dab6d3afff8c6cd6e16943c1b340a828a9",
			},
		},
		{
			name:   "busybox with Cargo.lock",
			input:  "testdata/fixtures/images/busybox-with-lockfile.tar.gz",
			golden: goldenBusyboxWithLockfile,
			override: overrideValues{
				artifactID: "sha256:e0edf846fd89372b0869a4826791a1c22dd620e75e32b586bc7e7bba245793a4",
				imageID:    "sha256:51dccb50b93f4f7d860045f19b34fd9eeca83fec890bdba10e0b706d6289a8bf",
			},
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
				override: overrideFuncs(overrideUID, overrideFingerprint, overrideDockerRemovedFields, func(t *testing.T, want, got *types.Report) {
					// Override ArtifactName to match the archive file path
					got.ArtifactName = tt.input

					// Override Result.Target for each result to match golden file expectations
					require.Len(t, got.Results, len(want.Results))
					for i := range got.Results {
						got.Results[i].Target = want.Results[i].Target
					}

					// Docker API v0.29.0+ calculates the imageID digest based on the manifest, rather than the config file.
					want.ArtifactID = tt.override.artifactID
					want.Metadata.ImageID = tt.override.imageID
				}),
			})
		})
	}
}
