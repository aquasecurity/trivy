//go:build integration && linux

package integration

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	testcontainers "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/aquasecurity/fanal/applier"
	"github.com/aquasecurity/fanal/artifact"
	aimage "github.com/aquasecurity/fanal/artifact/image"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/image"
	"github.com/aquasecurity/fanal/types"
)

func configureTestDataPaths(t *testing.T) (string, string) {
	t.Helper()
	tmpDir, err := os.MkdirTemp("/tmp", "fanal")
	require.NoError(t, err)

	containerdDir := filepath.Join(tmpDir, "containerd")
	err = os.MkdirAll(containerdDir, os.ModePerm)
	require.NoError(t, err)

	socketPath := filepath.Join(containerdDir, "containerd.sock")

	return tmpDir, socketPath
}

func startContainerd(t *testing.T, ctx context.Context, hostPath string) testcontainers.Container {
	t.Helper()
	req := testcontainers.ContainerRequest{
		Name:       "containerd",
		Image:      "ghcr.io/aquasecurity/trivy-test-images/containerd:latest",
		Entrypoint: []string{"/bin/sh", "-c", "/usr/local/bin/containerd"},
		Mounts: testcontainers.Mounts(
			testcontainers.BindMount(hostPath, "/run"),
		),
		SkipReaper: true,
		AutoRemove: false,
		WaitingFor: wait.ForLog("containerd successfully booted"),
	}
	containerdC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)

	_, err = containerdC.Exec(ctx, []string{"chmod", "666", "/run/containerd/containerd.sock"})
	require.NoError(t, err)

	return containerdC
}

func TestContainerd_LocalImage(t *testing.T) {
	tests := []struct {
		name         string
		imageName    string
		tarArchive   string
		wantMetadata types.ImageMetadata
	}{
		{
			name:       "alpine 3.10",
			imageName:  "ghcr.io/aquasecurity/trivy-test-images:alpine-310",
			tarArchive: "alpine-310.tar.gz",
			wantMetadata: types.ImageMetadata{
				ID: "sha256:961769676411f082461f9ef46626dd7a2d1e2b2a38e6a44364bcbecf51e66dd4",
				DiffIDs: []string{
					"sha256:03901b4a2ea88eeaad62dbe59b072b28b6efa00491962b8741081c5df50c65e0",
				},
				RepoTags:    []string{"ghcr.io/aquasecurity/trivy-test-images:alpine-310"},
				RepoDigests: []string{"ghcr.io/aquasecurity/trivy-test-images@sha256:f12582b2f2190f350e3904462c1c23aaf366b4f76705e97b199f9bbded1d816a"},
				ConfigFile: v1.ConfigFile{
					Architecture: "amd64",
					Created: v1.Time{
						Time: time.Date(2019, 8, 20, 20, 19, 55, 211423266, time.UTC),
					},
					OS: "linux",
					RootFS: v1.RootFS{
						Type: "layers",
						DiffIDs: []v1.Hash{
							{
								Algorithm: "sha256",
								Hex:       "03901b4a2ea88eeaad62dbe59b072b28b6efa00491962b8741081c5df50c65e0",
							},
						},
					},
					Config: v1.Config{
						Cmd: []string{
							"/bin/sh",
						},
						Env: []string{
							"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
						},
					},
				},
			},
		},
		{
			name:       "vulnimage",
			imageName:  "ghcr.io/aquasecurity/trivy-test-images:vulnimage",
			tarArchive: "vulnimage.tar.gz",
			wantMetadata: types.ImageMetadata{
				ID: "sha256:c17083664da903e13e9092fa3a3a1aeee2431aa2728298e3dbcec72f26369c41",
				DiffIDs: []string{
					"sha256:ebf12965380b39889c99a9c02e82ba465f887b45975b6e389d42e9e6a3857888",
					"sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33",
					"sha256:9922bc15eeefe1637b803ef2106f178152ce19a391f24aec838cbe2e48e73303",
					"sha256:dc00fbef458ad3204bbb548e2d766813f593d857b845a940a0de76aed94c94d1",
					"sha256:5cb2a5009179b1e78ecfef81a19756328bb266456cf9a9dbbcf9af8b83b735f0",
					"sha256:9bdb2c849099a99c8ab35f6fd7469c623635e8f4479a0a5a3df61e22bae509f6",
					"sha256:6408527580eade39c2692dbb6b0f6a9321448d06ea1c2eef06bb7f37da9c5013",
					"sha256:83abef706f5ae199af65d1c13d737d0eb36219f0d18e36c6d8ff06159df39a63",
					"sha256:c03283c257abd289a30b4f5e9e1345da0e9bfdc6ca398ee7e8fac6d2c1456227",
					"sha256:2da3602d664dd3f71fae83cbc566d4e80b432c6ee8bb4efd94c8e85122f503d4",
					"sha256:82c59ac8ee582542648e634ca5aff9a464c68ff8a054f105a58689fb52209e34",
					"sha256:2f4a5c9187c249834ebc28783bd3c65bdcbacaa8baa6620ddaa27846dd3ef708",
					"sha256:6ca56f561e677ae06c3bc87a70792642d671a4416becb9a101577c1a6e090e36",
					"sha256:154ad0735c360b212b167f424d33a62305770a1fcfb6363882f5c436cfbd9812",
					"sha256:b2a1a2d80bf0c747a4f6b0ca6af5eef23f043fcdb1ed4f3a3e750aef2dc68079",
					"sha256:4d116f47cb2cc77a88d609b9805f2b011a5d42339b67300166654b3922685ac9",
					"sha256:9b1326af1cf81505fd8e596b7f622b679ae5d290e46b25214ba26e4f7c661d60",
					"sha256:a66245f885f2a210071e415f0f8ac4f21f5e4eab6c0435b4082e5c3637c411cb",
					"sha256:ba17950e91742d6ac7055ea3a053fe764486658ca1ce8188f1e427b1fe2bc4da",
					"sha256:6ef42db7800507577383edf1937cb203b9b85f619feed6046594208748ceb52c",
				},
				RepoTags:    []string{"ghcr.io/aquasecurity/trivy-test-images:vulnimage"},
				RepoDigests: []string{"ghcr.io/aquasecurity/trivy-test-images@sha256:e74abbfd81e00baaf464cf9e09f8b24926e5255171e3150a60aa341ce064688f"},
				ConfigFile: v1.ConfigFile{
					Architecture: "amd64",
					Created: v1.Time{
						Time: time.Date(2019, 8, 7, 7, 25, 58, 651649800, time.UTC),
					},
					OS: "linux",
					RootFS: v1.RootFS{
						Type: "layers",
						DiffIDs: []v1.Hash{
							{Algorithm: "sha256", Hex: "ebf12965380b39889c99a9c02e82ba465f887b45975b6e389d42e9e6a3857888"},
							{Algorithm: "sha256", Hex: "0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33"},
							{Algorithm: "sha256", Hex: "9922bc15eeefe1637b803ef2106f178152ce19a391f24aec838cbe2e48e73303"},
							{Algorithm: "sha256", Hex: "dc00fbef458ad3204bbb548e2d766813f593d857b845a940a0de76aed94c94d1"},
							{Algorithm: "sha256", Hex: "5cb2a5009179b1e78ecfef81a19756328bb266456cf9a9dbbcf9af8b83b735f0"},
							{Algorithm: "sha256", Hex: "9bdb2c849099a99c8ab35f6fd7469c623635e8f4479a0a5a3df61e22bae509f6"},
							{Algorithm: "sha256", Hex: "6408527580eade39c2692dbb6b0f6a9321448d06ea1c2eef06bb7f37da9c5013"},
							{Algorithm: "sha256", Hex: "83abef706f5ae199af65d1c13d737d0eb36219f0d18e36c6d8ff06159df39a63"},
							{Algorithm: "sha256", Hex: "c03283c257abd289a30b4f5e9e1345da0e9bfdc6ca398ee7e8fac6d2c1456227"},
							{Algorithm: "sha256", Hex: "2da3602d664dd3f71fae83cbc566d4e80b432c6ee8bb4efd94c8e85122f503d4"},
							{Algorithm: "sha256", Hex: "82c59ac8ee582542648e634ca5aff9a464c68ff8a054f105a58689fb52209e34"},
							{Algorithm: "sha256", Hex: "2f4a5c9187c249834ebc28783bd3c65bdcbacaa8baa6620ddaa27846dd3ef708"},
							{Algorithm: "sha256", Hex: "6ca56f561e677ae06c3bc87a70792642d671a4416becb9a101577c1a6e090e36"},
							{Algorithm: "sha256", Hex: "154ad0735c360b212b167f424d33a62305770a1fcfb6363882f5c436cfbd9812"},
							{Algorithm: "sha256", Hex: "b2a1a2d80bf0c747a4f6b0ca6af5eef23f043fcdb1ed4f3a3e750aef2dc68079"},
							{Algorithm: "sha256", Hex: "4d116f47cb2cc77a88d609b9805f2b011a5d42339b67300166654b3922685ac9"},
							{Algorithm: "sha256", Hex: "9b1326af1cf81505fd8e596b7f622b679ae5d290e46b25214ba26e4f7c661d60"},
							{Algorithm: "sha256", Hex: "a66245f885f2a210071e415f0f8ac4f21f5e4eab6c0435b4082e5c3637c411cb"},
							{Algorithm: "sha256", Hex: "ba17950e91742d6ac7055ea3a053fe764486658ca1ce8188f1e427b1fe2bc4da"},
							{Algorithm: "sha256", Hex: "6ef42db7800507577383edf1937cb203b9b85f619feed6046594208748ceb52c"},
						},
					},
					Config: v1.Config{
						Cmd: []string{"composer"},
						Env: []string{
							"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
							"PHPIZE_DEPS=autoconf \t\tdpkg-dev dpkg \t\tfile \t\tg++ \t\tgcc \t\tlibc-dev \t\tmake \t\tpkgconf \t\tre2c",
							"PHP_INI_DIR=/usr/local/etc/php",
							"PHP_CFLAGS=-fstack-protector-strong -fpic -fpie -O2",
							"PHP_CPPFLAGS=-fstack-protector-strong -fpic -fpie -O2",
							"PHP_LDFLAGS=-Wl,-O1 -Wl,--hash-style=both -pie",
							"GPG_KEYS=1729F83938DA44E27BA0F4D3DBDB397470D12172 B1B44D8F021E4E2D6021E995DC9FF8D3EE5AF27F",
							"PHP_VERSION=7.2.11",
							"PHP_URL=https://secure.php.net/get/php-7.2.11.tar.xz/from/this/mirror",
							"PHP_ASC_URL=https://secure.php.net/get/php-7.2.11.tar.xz.asc/from/this/mirror",
							"PHP_SHA256=da1a705c0bc46410e330fc6baa967666c8cd2985378fb9707c01a8e33b01d985",
							"PHP_MD5=",
							"COMPOSER_ALLOW_SUPERUSER=1",
							"COMPOSER_HOME=/tmp",
							"COMPOSER_VERSION=1.7.2",
						},
						WorkingDir: "/app",
						Entrypoint: []string{
							"/bin/sh",
							"/docker-entrypoint.sh",
						},
					},
				},
			},
		},
	}
	ctx := namespaces.WithNamespace(context.Background(), "default")

	tmpDir, socketPath := configureTestDataPaths(t)
	defer os.RemoveAll(tmpDir)

	// Set a containerd socket
	t.Setenv("CONTAINERD_ADDRESS", socketPath)

	containerdC := startContainerd(t, ctx, tmpDir)
	defer containerdC.Terminate(ctx)

	client, err := containerd.New(socketPath)
	require.NoError(t, err)
	defer client.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cacheDir := t.TempDir()
			c, err := cache.NewFSCache(cacheDir)
			require.NoError(t, err)

			defer func() {
				c.Clear()
				c.Close()
			}()

			archive, err := os.Open(path.Join("testdata", "fixtures", tt.tarArchive))
			require.NoError(t, err)

			uncompressedArchive, err := gzip.NewReader(archive)
			require.NoError(t, err)
			defer archive.Close()

			_, err = client.Import(ctx, uncompressedArchive)
			require.NoError(t, err)

			img, cleanup, err := image.NewContainerImage(ctx, tt.imageName, types.DockerOption{})
			require.NoError(t, err)
			defer cleanup()

			ar, err := aimage.NewArtifact(img, c, artifact.Option{})
			require.NoError(t, err)

			ref, err := ar.Inspect(ctx)
			require.NoError(t, err)
			require.Equal(t, tt.wantMetadata, ref.ImageMetadata)

			a := applier.NewApplier(c)
			got, err := a.ApplyLayers(ref.ID, ref.BlobIDs)
			require.NoError(t, err)

			// Parse a golden file
			tag := strings.Split(tt.imageName, ":")[1]
			golden, err := os.Open(fmt.Sprintf("testdata/goldens/packages/%s.json.golden", tag))
			require.NoError(t, err)

			var wantPkgs []types.Package
			err = json.NewDecoder(golden).Decode(&wantPkgs)
			require.NoError(t, err)

			// Assert
			assert.Equal(t, wantPkgs, got.Packages)
		})
	}
}

func TestContainerd_PullImage(t *testing.T) {
	tests := []struct {
		name         string
		imageName    string
		wantMetadata types.ImageMetadata
	}{
		{
			name:      "remote alpine 3.10",
			imageName: "ghcr.io/aquasecurity/trivy-test-images:alpine-310",
			wantMetadata: types.ImageMetadata{
				ID: "sha256:961769676411f082461f9ef46626dd7a2d1e2b2a38e6a44364bcbecf51e66dd4",
				DiffIDs: []string{
					"sha256:03901b4a2ea88eeaad62dbe59b072b28b6efa00491962b8741081c5df50c65e0",
				},
				RepoTags:    []string{"ghcr.io/aquasecurity/trivy-test-images:alpine-310"},
				RepoDigests: []string{"ghcr.io/aquasecurity/trivy-test-images@sha256:72c42ed48c3a2db31b7dafe17d275b634664a708d901ec9fd57b1529280f01fb"},
				ConfigFile: v1.ConfigFile{
					Architecture: "amd64",
					Container:    "0a80155a31551fcc1a36fccbbda79fcd3f0b1c7d270653d00310e6e2217c57e6",
					Created: v1.Time{
						Time: time.Date(2019, 8, 20, 20, 19, 55, 211423266, time.UTC),
					},
					OS: "linux",
					RootFS: v1.RootFS{
						Type: "layers",
						DiffIDs: []v1.Hash{
							{
								Algorithm: "sha256",
								Hex:       "03901b4a2ea88eeaad62dbe59b072b28b6efa00491962b8741081c5df50c65e0",
							},
						},
					},
					DockerVersion: "18.06.1-ce",
					History: []v1.History{
						{
							Created: v1.Time{
								Time: time.Date(2019, 8, 20, 20, 19, 55, 62606894, time.UTC),
							},
							CreatedBy: "/bin/sh -c #(nop) ADD file:fe64057fbb83dccb960efabbf1cd8777920ef279a7fa8dbca0a8801c651bdf7c in / ",
						},
						{
							Created: v1.Time{
								Time: time.Date(2019, 8, 20, 20, 19, 55, 211423266, time.UTC),
							},
							CreatedBy:  "/bin/sh -c #(nop)  CMD [\"/bin/sh\"]",
							EmptyLayer: true,
						},
					},
					Config: v1.Config{
						Cmd: []string{
							"/bin/sh",
						},
						Env: []string{
							"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
						},
						Image:       "sha256:06f4121dff4d0123ce11bd2e44f48da9ba9ddcd23ae376ea1f363f63ea0849b5",
						ArgsEscaped: true,
					},
				},
			},
		},
	}

	ctx := namespaces.WithNamespace(context.Background(), "default")

	tmpDir, socketPath := configureTestDataPaths(t)

	containerdC := startContainerd(t, ctx, tmpDir)
	defer containerdC.Terminate(ctx)

	cli, err := containerd.New(socketPath)
	require.NoError(t, err)
	defer cli.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cacheDir := t.TempDir()
			c, err := cache.NewFSCache(cacheDir)
			require.NoError(t, err)

			defer func() {
				c.Clear()
				c.Close()
			}()

			_, err = cli.Pull(ctx, tt.imageName)
			require.NoError(t, err)

			img, cleanup, err := image.NewContainerImage(ctx, tt.imageName, types.DockerOption{})
			require.NoError(t, err)
			defer cleanup()

			art, err := aimage.NewArtifact(img, c, artifact.Option{})
			require.NoError(t, err)
			require.NotNil(t, art)

			ref, err := art.Inspect(context.Background())
			require.NoError(t, err)
			require.Equal(t, tt.wantMetadata, ref.ImageMetadata)

			a := applier.NewApplier(c)
			got, err := a.ApplyLayers(ref.ID, ref.BlobIDs)
			require.NoError(t, err)

			// Parse a golden file
			tag := strings.Split(tt.imageName, ":")[1]
			golden, err := os.Open(fmt.Sprintf("testdata/goldens/packages/%s.json.golden", tag))
			require.NoError(t, err)

			var wantPkgs []types.Package
			err = json.NewDecoder(golden).Decode(&wantPkgs)
			require.NoError(t, err)

			// Assert
			assert.Equal(t, wantPkgs, got.Packages)
		})
	}
}
