//go:build integration && linux

package integration

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/namespaces"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	testcontainers "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/aquasecurity/trivy/pkg/fanal/applier"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	aimage "github.com/aquasecurity/trivy/pkg/fanal/artifact/image"
	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/image"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func configureTestDataPaths(t *testing.T, namespace string) (string, string) {
	t.Helper()
	tmpDir, err := os.MkdirTemp("/tmp", "fanal")
	require.NoError(t, err)

	containerdDir := filepath.Join(tmpDir, "containerd")
	err = os.MkdirAll(containerdDir, os.ModePerm)
	require.NoError(t, err)

	socketPath := filepath.Join(containerdDir, "containerd.sock")

	// Set a containerd socket
	t.Setenv("CONTAINERD_ADDRESS", socketPath)
	t.Setenv("CONTAINERD_NAMESPACE", namespace)

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

	_, _, err = containerdC.Exec(ctx, []string{"chmod", "666", "/run/containerd/containerd.sock"})
	require.NoError(t, err)

	return containerdC
}

// Each of these tests imports an image and tags it with the name found in the
// `imageName` field. Then, the containerd store is searched by the reference
// provided in the `searchName` field.
func TestContainerd_SearchLocalStoreByNameOrDigest(t *testing.T) {
	type testInstance struct {
		name       string
		imageName  string
		searchName string
		expectErr  bool
	}

	digest := "sha256:f12582b2f2190f350e3904462c1c23aaf366b4f76705e97b199f9bbded1d816a"
	basename := "hello"
	tag := "world"
	importedImageOriginalName := "ghcr.io/aquasecurity/trivy-test-images:alpine-310"

	tests := []testInstance{
		{
			name:       "familiarName:tag",
			imageName:  fmt.Sprintf("%s:%s", basename, tag),
			searchName: fmt.Sprintf("%s:%s", basename, tag),
		},
		{
			name:       "compound/name:tag",
			imageName:  fmt.Sprintf("say/%s:%s", basename, tag),
			searchName: fmt.Sprintf("say/%s:%s", basename, tag),
		},
		{
			name:       "docker.io/library/name:tag",
			imageName:  fmt.Sprintf("docker.io/library/%s:%s", basename, tag),
			searchName: fmt.Sprintf("docker.io/library/%s:%s", basename, tag),
		},
		{
			name:       "other-registry.io/library/name:tag",
			imageName:  fmt.Sprintf("other-registry.io/library/%s:%s", basename, tag),
			searchName: fmt.Sprintf("other-registry.io/library/%s:%s", basename, tag),
		},
		{
			name:       "other-registry.io/library/name:wrongTag should fail",
			imageName:  fmt.Sprintf("other-registry.io/library/%s:%s", basename, tag),
			searchName: fmt.Sprintf("other-registry.io/library/%s:badtag", basename),
			expectErr:  true,
		},
		{
			name:       "other-registry.io/library/wrongName:tag should fail",
			imageName:  fmt.Sprintf("other-registry.io/library/%s:%s", basename, tag),
			searchName: fmt.Sprintf("other-registry.io/library/badname:%s", tag),
			expectErr:  true,
		},
		{
			name:       "digest should succeed",
			imageName:  "",
			searchName: digest,
		},
		{
			name:       "wrong digest should fail",
			imageName:  "",
			searchName: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			expectErr:  true,
		},
		{
			name:       "name@digest",
			imageName:  fmt.Sprintf("%s:%s", basename, tag),
			searchName: fmt.Sprintf("hello@%s", digest),
		},
		{
			name:       "compound/name@digest",
			imageName:  fmt.Sprintf("compound/%s:%s", basename, tag),
			searchName: fmt.Sprintf("compound/%s@%s", basename, digest),
		},
		{
			name:       "docker.io/library/name@digest",
			imageName:  fmt.Sprintf("docker.io/library/%s:%s", basename, tag),
			searchName: fmt.Sprintf("docker.io/library/%s@%s", basename, digest),
		},
		{
			name:       "otherdomain.io/name@digest",
			imageName:  fmt.Sprintf("otherdomain.io/%s:%s", basename, tag),
			searchName: fmt.Sprintf("otherdomain.io/%s@%s", basename, digest),
		},
		{
			name:       "wrongName@digest should fail",
			imageName:  fmt.Sprintf("%s:%s", basename, tag),
			searchName: fmt.Sprintf("badname@%s", digest),
			expectErr:  true,
		},
		{
			name:       "compound/wrongName@digest should fail",
			imageName:  fmt.Sprintf("compound/%s:%s", basename, tag),
			searchName: fmt.Sprintf("compound/badname@%s", digest),
			expectErr:  true,
		},
	}
	// Each architecture needs different images and test cases.
	// Currently only amd64 architecture is supported
	if runtime.GOARCH != "amd64" {
		t.Skip("'Containerd' test only supports amd64 architecture")
	}

	namespace := "default"
	ctx := namespaces.WithNamespace(context.Background(), namespace)
	tmpDir, socketPath := configureTestDataPaths(t, namespace)
	defer os.RemoveAll(tmpDir)

	containerdC := startContainerd(t, ctx, tmpDir)
	defer containerdC.Terminate(ctx)

	client, err := containerd.New(socketPath)
	require.NoError(t, err)
	defer client.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			archive, err := os.Open("../../../../integration/testdata/fixtures/images/alpine-310.tar.gz")
			require.NoError(t, err)

			uncompressedArchive, err := gzip.NewReader(archive)
			require.NoError(t, err)
			defer archive.Close()

			cacheDir := t.TempDir()
			c, err := cache.NewFSCache(cacheDir)
			require.NoError(t, err)

			imgs, err := client.Import(ctx, uncompressedArchive)
			require.NoError(t, err)
			_ = imgs

			digestTest := tt.imageName == ""

			if !digestTest {
				// Tag the image, taken from the code in `ctr image tag...`
				imgs[0].Name = tt.imageName
				_, err = client.ImageService().Create(ctx, imgs[0])
				require.NoError(t, err)

				// Remove the image by its original name, to ensure the image
				// is known only by the tag we have given it.
				err = client.ImageService().Delete(ctx, importedImageOriginalName, images.SynchronousDelete())
				require.NoError(t, err)
			}

			t.Cleanup(func() {
				for _, img := range imgs {
					err = client.ImageService().Delete(ctx, img.Name, images.SynchronousDelete())
					require.NoError(t, err)
				}
			})

			img, cleanup, err := image.NewContainerImage(ctx, tt.searchName, types.DockerOption{},
				image.DisableDockerd(), image.DisablePodman(), image.DisableRemote())
			defer cleanup()
			if tt.expectErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			ar, err := aimage.NewArtifact(img, c, artifact.Option{})
			require.NoError(t, err)

			ref, err := ar.Inspect(ctx)
			require.NoError(t, err)

			if digestTest {
				actualDigest := strings.Split(ref.ImageMetadata.RepoDigests[0], "@")[1]
				require.Equal(t, tt.searchName, actualDigest)
				return
			}

			require.Equal(t, tt.searchName, ref.Name)
		})
	}
}

func TestContainerd_LocalImage(t *testing.T) {
	localImageTestWithNamespace(t, "default")
}

func TestContainerd_LocalImage_Alternative_Namespace(t *testing.T) {
	localImageTestWithNamespace(t, "test")
}

func localImageTestWithNamespace(t *testing.T, namespace string) {
	t.Helper()
	tests := []struct {
		name         string
		imageName    string
		tarArchive   string
		wantMetadata types.ImageMetadata
	}{
		{
			name:       "alpine 3.10",
			imageName:  "ghcr.io/aquasecurity/trivy-test-images:alpine-310",
			tarArchive: "../../../../integration/testdata/fixtures/images/alpine-310.tar.gz",
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
					History: []v1.History{
						{
							Created:   v1.Time{Time: time.Date(2019, 8, 20, 20, 19, 55, 62606894, time.UTC)},
							CreatedBy: "/bin/sh -c #(nop) ADD file:fe64057fbb83dccb960efabbf1cd8777920ef279a7fa8dbca0a8801c651bdf7c in / ",
						},
						{
							Created:    v1.Time{Time: time.Date(2019, 8, 20, 20, 19, 55, 211423266, time.UTC)},
							CreatedBy:  "/bin/sh -c #(nop)  CMD [\"/bin/sh\"]",
							EmptyLayer: true,
						},
					},
				},
			},
		},
		{
			name:       "vulnimage",
			imageName:  "ghcr.io/aquasecurity/trivy-test-images:vulnimage",
			tarArchive: "../../../../integration/testdata/fixtures/images/vulnimage.tar.gz",
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
					History: []v1.History{
						{
							Created:   v1.Time{Time: time.Date(2018, 9, 11, 22, 19, 38, 885299940, time.UTC)},
							CreatedBy: "/bin/sh -c #(nop) ADD file:49f9e47e678d868d5b023482aa8dded71276a241a665c4f8b55ca77269321b34 in / ",
						},
						{
							Created:    v1.Time{Time: time.Date(2018, 9, 11, 22, 19, 39, 58628442, time.UTC)},
							CreatedBy:  "/bin/sh -c #(nop)  CMD [\"/bin/sh\"]",
							EmptyLayer: true,
						},
						{
							Created:    v1.Time{Time: time.Date(2018, 9, 12, 1, 26, 59, 951316015, time.UTC)},
							CreatedBy:  "/bin/sh -c #(nop)  ENV PHPIZE_DEPS=autoconf \t\tdpkg-dev dpkg \t\tfile \t\tg++ \t\tgcc \t\tlibc-dev \t\tmake \t\tpkgconf \t\tre2c",
							EmptyLayer: true,
						},
						{
							Created:   v1.Time{Time: time.Date(2018, 9, 12, 1, 27, 1, 470388635, time.UTC)},
							CreatedBy: "/bin/sh -c apk add --no-cache --virtual .persistent-deps \t\tca-certificates \t\tcurl \t\ttar \t\txz \t\tlibressl",
						},
						{
							Created:   v1.Time{Time: time.Date(2018, 9, 12, 1, 27, 2, 432381785, time.UTC)},
							CreatedBy: "/bin/sh -c set -x \t&& addgroup -g 82 -S www-data \t&& adduser -u 82 -D -S -G www-data www-data",
						},
						{
							Created:    v1.Time{Time: time.Date(2018, 9, 12, 1, 27, 2, 715120309, time.UTC)},
							CreatedBy:  "/bin/sh -c #(nop)  ENV PHP_INI_DIR=/usr/local/etc/php",
							EmptyLayer: true,
						},
						{
							Created:   v1.Time{Time: time.Date(2018, 9, 12, 1, 27, 3, 655421341, time.UTC)},
							CreatedBy: "/bin/sh -c mkdir -p $PHP_INI_DIR/conf.d",
						},
						{
							Created:    v1.Time{Time: time.Date(2018, 9, 12, 1, 27, 3, 931799562, time.UTC)},
							CreatedBy:  "/bin/sh -c #(nop)  ENV PHP_CFLAGS=-fstack-protector-strong -fpic -fpie -O2",
							EmptyLayer: true,
						},
						{
							Created:    v1.Time{Time: time.Date(2018, 9, 12, 1, 27, 4, 210945499, time.UTC)},
							CreatedBy:  "/bin/sh -c #(nop)  ENV PHP_CPPFLAGS=-fstack-protector-strong -fpic -fpie -O2",
							EmptyLayer: true,
						},
						{
							Created:    v1.Time{Time: time.Date(2018, 9, 12, 1, 27, 4, 523116501, time.UTC)},
							CreatedBy:  "/bin/sh -c #(nop)  ENV PHP_LDFLAGS=-Wl,-O1 -Wl,--hash-style=both -pie",
							EmptyLayer: true,
						},
						{
							Created:    v1.Time{Time: time.Date(2018, 9, 12, 1, 27, 4, 795176159, time.UTC)},
							CreatedBy:  "/bin/sh -c #(nop)  ENV GPG_KEYS=1729F83938DA44E27BA0F4D3DBDB397470D12172 B1B44D8F021E4E2D6021E995DC9FF8D3EE5AF27F",
							EmptyLayer: true,
						},
						{
							Created:    v1.Time{Time: time.Date(2018, 10, 15, 19, 2, 18, 415761689, time.UTC)},
							CreatedBy:  "/bin/sh -c #(nop)  ENV PHP_VERSION=7.2.11",
							EmptyLayer: true,
						},
						{
							Created:    v1.Time{Time: time.Date(2018, 10, 15, 19, 2, 18, 599097853, time.UTC)},
							CreatedBy:  "/bin/sh -c #(nop)  ENV PHP_URL=https://secure.php.net/get/php-7.2.11.tar.xz/from/this/mirror PHP_ASC_URL=https://secure.php.net/get/php-7.2.11.tar.xz.asc/from/this/mirror",
							EmptyLayer: true,
						},
						{
							Created:    v1.Time{Time: time.Date(2018, 10, 15, 19, 2, 18, 782890412, time.UTC)},
							CreatedBy:  "/bin/sh -c #(nop)  ENV PHP_SHA256=da1a705c0bc46410e330fc6baa967666c8cd2985378fb9707c01a8e33b01d985 PHP_MD5=",
							EmptyLayer: true,
						},
						{
							Created:   v1.Time{Time: time.Date(2018, 10, 15, 19, 2, 22, 795846753, time.UTC)},
							CreatedBy: "/bin/sh -c set -xe; \t\tapk add --no-cache --virtual .fetch-deps \t\tgnupg \t\twget \t; \t\tmkdir -p /usr/src; \tcd /usr/src; \t\twget -O php.tar.xz \"$PHP_URL\"; \t\tif [ -n \"$PHP_SHA256\" ]; then \t\techo \"$PHP_SHA256 *php.tar.xz\" | sha256sum -c -; \tfi; \tif [ -n \"$PHP_MD5\" ]; then \t\techo \"$PHP_MD5 *php.tar.xz\" | md5sum -c -; \tfi; \t\tif [ -n \"$PHP_ASC_URL\" ]; then \t\twget -O php.tar.xz.asc \"$PHP_ASC_URL\"; \t\texport GNUPGHOME=\"$(mktemp -d)\"; \t\tfor key in $GPG_KEYS; do \t\t\tgpg --keyserver ha.pool.sks-keyservers.net --recv-keys \"$key\"; \t\tdone; \t\tgpg --batch --verify php.tar.xz.asc php.tar.xz; \t\tcommand -v gpgconf > /dev/null && gpgconf --kill all; \t\trm -rf \"$GNUPGHOME\"; \tfi; \t\tapk del .fetch-deps",
						},
						{
							Created:   v1.Time{Time: time.Date(2018, 10, 15, 19, 2, 23, 71406376, time.UTC)},
							CreatedBy: "/bin/sh -c #(nop) COPY file:207c686e3fed4f71f8a7b245d8dcae9c9048d276a326d82b553c12a90af0c0ca in /usr/local/bin/ ",
						},
						{
							Created:   v1.Time{Time: time.Date(2018, 10, 15, 19, 7, 13, 93396680, time.UTC)},
							CreatedBy: "/bin/sh -c set -xe \t&& apk add --no-cache --virtual .build-deps \t\t$PHPIZE_DEPS \t\tcoreutils \t\tcurl-dev \t\tlibedit-dev \t\tlibressl-dev \t\tlibsodium-dev \t\tlibxml2-dev \t\tsqlite-dev \t\t&& export CFLAGS=\"$PHP_CFLAGS\" \t\tCPPFLAGS=\"$PHP_CPPFLAGS\" \t\tLDFLAGS=\"$PHP_LDFLAGS\" \t&& docker-php-source extract \t&& cd /usr/src/php \t&& gnuArch=\"$(dpkg-architecture --query DEB_BUILD_GNU_TYPE)\" \t&& ./configure \t\t--build=\"$gnuArch\" \t\t--with-config-file-path=\"$PHP_INI_DIR\" \t\t--with-config-file-scan-dir=\"$PHP_INI_DIR/conf.d\" \t\t\t\t--enable-option-checking=fatal \t\t\t\t--with-mhash \t\t\t\t--enable-ftp \t\t--enable-mbstring \t\t--enable-mysqlnd \t\t--with-sodium=shared \t\t\t\t--with-curl \t\t--with-libedit \t\t--with-openssl \t\t--with-zlib \t\t\t\t$(test \"$gnuArch\" = 's390x-linux-gnu' && echo '--without-pcre-jit') \t\t\t\t$PHP_EXTRA_CONFIGURE_ARGS \t&& make -j \"$(nproc)\" \t&& make install \t&& { find /usr/local/bin /usr/local/sbin -type f -perm +0111 -exec strip --strip-all '{}' + || true; } \t&& make clean \t\t&& cp -v php.ini-* \"$PHP_INI_DIR/\" \t\t&& cd / \t&& docker-php-source delete \t\t&& runDeps=\"$( \t\tscanelf --needed --nobanner --format '%n#p' --recursive /usr/local \t\t\t| tr ',' '\\n' \t\t\t| sort -u \t\t\t| awk 'system(\"[ -e /usr/local/lib/\" $1 \" ]\") == 0 { next } { print \"so:\" $1 }' \t)\" \t&& apk add --no-cache --virtual .php-rundeps $runDeps \t\t&& apk del .build-deps \t\t&& pecl update-channels \t&& rm -rf /tmp/pear ~/.pearrc",
						},
						{
							Created:   v1.Time{Time: time.Date(2018, 10, 15, 19, 7, 13, 722586262, time.UTC)},
							CreatedBy: "/bin/sh -c #(nop) COPY multi:2cdcedabcf5a3b9ae610fab7848e94bc2f64b4d85710d55fd6f79e44dacf73d8 in /usr/local/bin/ ",
						},
						{
							Created:   v1.Time{Time: time.Date(2018, 10, 15, 19, 7, 14, 618087104, time.UTC)},
							CreatedBy: "/bin/sh -c docker-php-ext-enable sodium",
						},
						{
							Created:    v1.Time{Time: time.Date(2018, 10, 15, 19, 7, 14, 826981756, time.UTC)},
							CreatedBy:  "/bin/sh -c #(nop)  ENTRYPOINT [\"docker-php-entrypoint\"]",
							EmptyLayer: true,
						},
						{
							Created:    v1.Time{Time: time.Date(2018, 10, 15, 19, 7, 15, 10831572, time.UTC)},
							CreatedBy:  "/bin/sh -c #(nop)  CMD [\"php\" \"-a\"]",
							EmptyLayer: true,
						},
						{
							Created:   v1.Time{Time: time.Date(2018, 10, 15, 21, 28, 21, 919735971, time.UTC)},
							CreatedBy: "/bin/sh -c apk --no-cache add git subversion openssh mercurial tini bash patch",
						},
						{
							Created:   v1.Time{Time: time.Date(2018, 10, 15, 21, 28, 22, 611763893, time.UTC)},
							CreatedBy: "/bin/sh -c echo \"memory_limit=-1\" > \"$PHP_INI_DIR/conf.d/memory-limit.ini\"  && echo \"date.timezone=${PHP_TIMEZONE:-UTC}\" > \"$PHP_INI_DIR/conf.d/date_timezone.ini\"",
						},
						{
							Created:   v1.Time{Time: time.Date(2018, 10, 15, 21, 28, 50, 224278478, time.UTC)},
							CreatedBy: "/bin/sh -c apk add --no-cache --virtual .build-deps zlib-dev  && docker-php-ext-install zip  && runDeps=\"$(     scanelf --needed --nobanner --format '%n#p' --recursive /usr/local/lib/php/extensions     | tr ',' '\\n'     | sort -u     | awk 'system(\"[ -e /usr/local/lib/\" $1 \" ]\") == 0 { next } { print \"so:\" $1 }'     )\"  && apk add --virtual .composer-phpext-rundeps $runDeps  && apk del .build-deps",
						},
						{
							Created:    v1.Time{Time: time.Date(2018, 10, 15, 21, 28, 50, 503010161, time.UTC)},
							CreatedBy:  "/bin/sh -c #(nop)  ENV COMPOSER_ALLOW_SUPERUSER=1",
							EmptyLayer: true,
						},
						{
							Created:    v1.Time{Time: time.Date(2018, 10, 15, 21, 28, 50, 775378559, time.UTC)},
							CreatedBy:  "/bin/sh -c #(nop)  ENV COMPOSER_HOME=/tmp",
							EmptyLayer: true,
						},
						{
							Created:    v1.Time{Time: time.Date(2018, 10, 15, 21, 28, 51, 35012363, time.UTC)},
							CreatedBy:  "/bin/sh -c #(nop)  ENV COMPOSER_VERSION=1.7.2",
							EmptyLayer: true,
						},
						{
							Created:   v1.Time{Time: time.Date(2018, 10, 15, 21, 28, 52, 491402624, time.UTC)},
							CreatedBy: "/bin/sh -c curl --silent --fail --location --retry 3 --output /tmp/installer.php --url https://raw.githubusercontent.com/composer/getcomposer.org/b107d959a5924af895807021fcef4ffec5a76aa9/web/installer  && php -r \"     \\$signature = '544e09ee996cdf60ece3804abc52599c22b1f40f4323403c44d44fdfdd586475ca9813a858088ffbc1f233e9b180f061';     \\$hash = hash('SHA384', file_get_contents('/tmp/installer.php'));     if (!hash_equals(\\$signature, \\$hash)) {         unlink('/tmp/installer.php');         echo 'Integrity check failed, installer is either corrupt or worse.' . PHP_EOL;         exit(1);     }\"  && php /tmp/installer.php --no-ansi --install-dir=/usr/bin --filename=composer --version=${COMPOSER_VERSION}  && composer --ansi --version --no-interaction  && rm -rf /tmp/* /tmp/.htaccess",
						},
						{
							Created:   v1.Time{Time: time.Date(2018, 10, 15, 21, 28, 52, 948859545, time.UTC)},
							CreatedBy: "/bin/sh -c #(nop) COPY file:295943a303e8f27de4302b6aa3687bce4b1d1392335efaaab9ecd37bec5ab4c5 in /docker-entrypoint.sh ",
						},
						{
							Created:   v1.Time{Time: time.Date(2018, 10, 15, 21, 28, 53, 295399872, time.UTC)},
							CreatedBy: "/bin/sh -c #(nop) WORKDIR /app",
						},
						{
							Created:    v1.Time{Time: time.Date(2018, 10, 15, 21, 28, 53, 582920705, time.UTC)},
							CreatedBy:  "/bin/sh -c #(nop)  ENTRYPOINT [\"/bin/sh\" \"/docker-entrypoint.sh\"]",
							EmptyLayer: true,
						},
						{
							Created:    v1.Time{Time: time.Date(2018, 10, 15, 21, 28, 53, 798628678, time.UTC)},
							CreatedBy:  "/bin/sh -c #(nop)  CMD [\"composer\"]",
							EmptyLayer: true,
						},
						{
							Created:   v1.Time{Time: time.Date(2019, 8, 7, 7, 25, 57, 211142800, time.UTC)},
							CreatedBy: "/bin/sh -c #(nop) ADD file:842584685f26edb24dc305d76894f51cfda2bad0c24a05e727f9d4905d184a70 in /php-app/composer.lock ",
						},
						{
							Created:   v1.Time{Time: time.Date(2019, 8, 7, 7, 25, 57, 583779000, time.UTC)},
							CreatedBy: "/bin/sh -c #(nop) ADD file:c6d0373d380252b91829a5bb3c81d5b1afa574c91cef7752d18170a231c31f6d in /ruby-app/Gemfile.lock ",
						},
						{
							Created:   v1.Time{Time: time.Date(2019, 8, 7, 7, 25, 57, 921730100, time.UTC)},
							CreatedBy: "/bin/sh -c #(nop) ADD file:54a1c52556a5ebe98fd124f51c25d071f9e29e2714c72c80d6d3d254b9e83386 in /node-app/package-lock.json ",
						},
						{
							Created:   v1.Time{Time: time.Date(2019, 8, 7, 7, 25, 58, 311593100, time.UTC)},
							CreatedBy: "/bin/sh -c #(nop) ADD file:097d32f46acde76c4da9e55f17110d69d02cc6d16c86da907980da335fc0fc5f in /python-app/Pipfile.lock ",
						},
						{
							Created:   v1.Time{Time: time.Date(2019, 8, 7, 7, 25, 58, 651649800, time.UTC)},
							CreatedBy: "/bin/sh -c #(nop) ADD file:7f147d85de19bfb905c260a0c175f227a433259022c163017b96d0efacdcd105 in /rust-app/Cargo.lock ",
						},
					},
				},
			},
		},
	}
	// Each architecture needs different images and test cases.
	// Currently only amd64 architecture is supported
	if runtime.GOARCH != "amd64" {
		t.Skip("'Containerd' test only supports amd64 architecture")
	}
	ctx := namespaces.WithNamespace(context.Background(), namespace)

	tmpDir, socketPath := configureTestDataPaths(t, namespace)
	defer os.RemoveAll(tmpDir)

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

			archive, err := os.Open(tt.tarArchive)
			require.NoError(t, err)

			uncompressedArchive, err := gzip.NewReader(archive)
			require.NoError(t, err)
			defer archive.Close()

			_, err = client.Import(ctx, uncompressedArchive)
			require.NoError(t, err)

			// Enable only containerd
			img, cleanup, err := image.NewContainerImage(ctx, tt.imageName, types.DockerOption{},
				image.DisableDockerd(), image.DisablePodman(), image.DisableRemote())
			require.NoError(t, err)
			defer cleanup()

			ar, err := aimage.NewArtifact(img, c, artifact.Option{
				DisabledAnalyzers: []analyzer.Type{
					analyzer.TypeExecutable,
					analyzer.TypeLicenseFile,
				},
			})
			require.NoError(t, err)

			ref, err := ar.Inspect(ctx)
			require.NoError(t, err)
			require.Equal(t, tt.wantMetadata, ref.ImageMetadata)

			a := applier.NewApplier(c)
			got, err := a.ApplyLayers(ref.ID, ref.BlobIDs)
			require.NoError(t, err)

			tag := strings.Split(tt.imageName, ":")[1]
			goldenFile := fmt.Sprintf("testdata/goldens/packages/%s.json.golden", tag)

			if *update {
				b, err := json.MarshalIndent(got.Packages, "", "  ")
				require.NoError(t, err)
				err = os.WriteFile(goldenFile, b, 0666)
				require.NoError(t, err)
			}

			// Parse a golden file
			golden, err := os.Open(goldenFile)
			require.NoError(t, err)
			defer golden.Close()

			var wantPkgs types.Packages
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
						ArgsEscaped: false,
					},
					History: []v1.History{
						{
							Created:   v1.Time{time.Date(2019, 8, 20, 20, 19, 55, 62606894, time.UTC)},
							CreatedBy: "/bin/sh -c #(nop) ADD file:fe64057fbb83dccb960efabbf1cd8777920ef279a7fa8dbca0a8801c651bdf7c in / ",
						},
						{
							Created:    v1.Time{time.Date(2019, 8, 20, 20, 19, 55, 211423266, time.UTC)},
							CreatedBy:  "/bin/sh -c #(nop)  CMD [\"/bin/sh\"]",
							EmptyLayer: true,
						},
					},
				},
			},
		},
	}

	// Each architecture needs different images and test cases.
	// Currently only amd64 architecture is supported
	if runtime.GOARCH != "amd64" {
		t.Skip("'Containerd' test only supports amd64 architecture")
	}

	namespace := "default"
	ctx := namespaces.WithNamespace(context.Background(), namespace)

	tmpDir, socketPath := configureTestDataPaths(t, namespace)

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

			// Enable only containerd
			img, cleanup, err := image.NewContainerImage(ctx, tt.imageName, types.DockerOption{},
				image.DisableDockerd(), image.DisablePodman(), image.DisableRemote())
			require.NoError(t, err)
			defer cleanup()

			art, err := aimage.NewArtifact(img, c, artifact.Option{
				DisabledAnalyzers: []analyzer.Type{
					analyzer.TypeExecutable,
					analyzer.TypeLicenseFile,
				},
			})
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

			var wantPkgs types.Packages
			err = json.NewDecoder(golden).Decode(&wantPkgs)
			require.NoError(t, err)

			// Assert
			assert.Equal(t, wantPkgs, got.Packages)
		})
	}
}
