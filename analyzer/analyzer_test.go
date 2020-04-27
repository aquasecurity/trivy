package analyzer_test

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"

	_ "github.com/aquasecurity/fanal/analyzer/command/apk"
	_ "github.com/aquasecurity/fanal/analyzer/library/composer"
	_ "github.com/aquasecurity/fanal/analyzer/os/alpine"
	_ "github.com/aquasecurity/fanal/analyzer/os/debianbase"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/apk"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/dpkg"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/extractor"
	"github.com/aquasecurity/fanal/extractor/docker"
	"github.com/aquasecurity/fanal/types"
	depTypes "github.com/aquasecurity/go-dep-parser/pkg/types"
)

func TestConfig_Analyze(t *testing.T) {
	type fields struct {
		Extractor extractor.Extractor
		Cache     cache.ImageCache
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name                    string
		imagePath               string
		fields                  fields
		args                    args
		missingLayerExpectation cache.ImageCacheMissingLayersExpectation
		putLayerExpectations    []cache.ImageCachePutLayerExpectation
		putImageExpectations    []cache.ImageCachePutImageExpectation
		want                    types.ImageReference
		wantErr                 string
	}{
		{
			name:      "happy path",
			imagePath: "testdata/alpine.tar.gz",
			missingLayerExpectation: cache.ImageCacheMissingLayersExpectation{
				Args: cache.ImageCacheMissingLayersArgs{
					ImageID:  "sha256:965ea09ff2ebd2b9eeec88cd822ce156f6674c7e99be082c7efac3c62f3ff652",
					LayerIDs: []string{"sha256:77cae8ab23bf486355d1b3191259705374f4a11d483b24964d2f729dd8c076a0"},
				},
				Returns: cache.ImageCacheMissingLayersReturns{
					MissingImage:    true,
					MissingLayerIDs: []string{"sha256:77cae8ab23bf486355d1b3191259705374f4a11d483b24964d2f729dd8c076a0"},
				},
			},
			putLayerExpectations: []cache.ImageCachePutLayerExpectation{
				{
					Args: cache.ImageCachePutLayerArgs{
						DiffID: "sha256:77cae8ab23bf486355d1b3191259705374f4a11d483b24964d2f729dd8c076a0",
						LayerInfo: types.LayerInfo{
							SchemaVersion: 1,
							Digest:        "",
							DiffID:        "sha256:77cae8ab23bf486355d1b3191259705374f4a11d483b24964d2f729dd8c076a0",
							OS: &types.OS{
								Family: "alpine",
								Name:   "3.10.3",
							},
							PackageInfos:  []types.PackageInfo{{FilePath: "lib/apk/db/installed", Packages: []types.Package{{Name: "musl", Version: "1.1.22-r3", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "busybox", Version: "1.30.1-r2", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "alpine-baselayout", Version: "3.1.2-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "alpine-keys", Version: "2.1-r2", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "openssl", Version: "1.1.1d-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "libcrypto1.1", Version: "1.1.1d-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "libssl1.1", Version: "1.1.1d-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "ca-certificates", Version: "20190108-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "ca-certificates-cacert", Version: "20190108-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "libtls-standalone", Version: "2.9.1-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "ssl_client", Version: "1.30.1-r2", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "zlib", Version: "1.2.11-r1", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "apk-tools", Version: "2.10.4-r2", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "pax-utils", Version: "1.2.3-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "scanelf", Version: "1.2.3-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "musl-utils", Version: "1.1.22-r3", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "libc-dev", Version: "0.7.1-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "libc-utils", Version: "0.7.1-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}}}},
							Applications:  []types.Application(nil),
							OpaqueDirs:    []string(nil),
							WhiteoutFiles: []string(nil),
						},
					},
					Returns: cache.ImageCachePutLayerReturns{},
				},
			},
			putImageExpectations: []cache.ImageCachePutImageExpectation{
				{
					Args: cache.ImageCachePutImageArgs{
						ImageID: "sha256:965ea09ff2ebd2b9eeec88cd822ce156f6674c7e99be082c7efac3c62f3ff652",
						ImageInfo: types.ImageInfo{
							SchemaVersion: 1,
							Architecture:  "amd64",
							Created:       time.Date(2019, 10, 21, 17, 21, 42, 387111039, time.UTC),
							DockerVersion: "18.06.1-ce",
							OS:            "linux",
						},
					},
				},
			},
			want: types.ImageReference{
				Name:     "testdata/alpine.tar.gz",
				ID:       "sha256:965ea09ff2ebd2b9eeec88cd822ce156f6674c7e99be082c7efac3c62f3ff652",
				LayerIDs: []string{"sha256:77cae8ab23bf486355d1b3191259705374f4a11d483b24964d2f729dd8c076a0"},
			},
		},
		{
			name:      "happy path: include lock files",
			imagePath: "testdata/vuln-image.tar.gz",
			missingLayerExpectation: cache.ImageCacheMissingLayersExpectation{
				Args: cache.ImageCacheMissingLayersArgs{
					ImageID: "sha256:58701fd185bda36cab0557bb6438661831267aa4a9e0b54211c4d5317a48aff4",
					LayerIDs: []string{
						"sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
						"sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
						"sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
						"sha256:a4595c43a874856bf95f3bfc4fbf78bbaa04c92c726276d4f64193a47ced0566",
					},
				},
				Returns: cache.ImageCacheMissingLayersReturns{
					MissingLayerIDs: []string{
						"sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
						"sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
						"sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
					},
				},
			},
			putLayerExpectations: []cache.ImageCachePutLayerExpectation{
				{
					Args: cache.ImageCachePutLayerArgs{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
						LayerInfo: types.LayerInfo{
							SchemaVersion: 1,
							Digest:        "",
							DiffID:        "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
							OS:            &types.OS{Family: "debian", Name: "9.9"},
							PackageInfos:  []types.PackageInfo{{FilePath: "var/lib/dpkg/status.d/base", Packages: []types.Package{{Name: "base-files", Version: "9.9+deb9u9", Release: "", Epoch: 0, Arch: "", SrcName: "base-files", SrcVersion: "9.9+deb9u9", SrcRelease: "", SrcEpoch: 0}}}, {FilePath: "var/lib/dpkg/status.d/netbase", Packages: []types.Package{{Name: "netbase", Version: "5.4", Release: "", Epoch: 0, Arch: "", SrcName: "netbase", SrcVersion: "5.4", SrcRelease: "", SrcEpoch: 0}}}, {FilePath: "var/lib/dpkg/status.d/tzdata", Packages: []types.Package{{Name: "tzdata", Version: "2019a-0+deb9u1", Release: "", Epoch: 0, Arch: "", SrcName: "tzdata", SrcVersion: "2019a-0+deb9u1", SrcRelease: "", SrcEpoch: 0}}}},
						},
					},
				},
				{
					Args: cache.ImageCachePutLayerArgs{
						DiffID: "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
						LayerInfo: types.LayerInfo{
							SchemaVersion: 1,
							Digest:        "",
							DiffID:        "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
							PackageInfos:  []types.PackageInfo{{FilePath: "var/lib/dpkg/status.d/libc6", Packages: []types.Package{{Name: "libc6", Version: "2.24-11+deb9u4", Release: "", Epoch: 0, Arch: "", SrcName: "glibc", SrcVersion: "2.24-11+deb9u4", SrcRelease: "", SrcEpoch: 0}}}, {FilePath: "var/lib/dpkg/status.d/libssl1", Packages: []types.Package{{Name: "libssl1.1", Version: "1.1.0k-1~deb9u1", Release: "", Epoch: 0, Arch: "", SrcName: "openssl", SrcVersion: "1.1.0k-1~deb9u1", SrcRelease: "", SrcEpoch: 0}}}, {FilePath: "var/lib/dpkg/status.d/openssl", Packages: []types.Package{{Name: "openssl", Version: "1.1.0k-1~deb9u1", Release: "", Epoch: 0, Arch: "", SrcName: "openssl", SrcVersion: "1.1.0k-1~deb9u1", SrcRelease: "", SrcEpoch: 0}}}},
						},
					},
				},
				{
					Args: cache.ImageCachePutLayerArgs{
						DiffID: "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
						LayerInfo: types.LayerInfo{
							SchemaVersion: 1,
							Digest:        "",
							DiffID:        "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
							Applications: []types.Application{{Type: "composer", FilePath: "php-app/composer.lock",
								Libraries: []types.LibraryInfo{
									{Library: depTypes.Library{Name: "guzzlehttp/guzzle", Version: "6.2.0"}},
									{Library: depTypes.Library{Name: "guzzlehttp/promises", Version: "v1.3.1"}},
									{Library: depTypes.Library{Name: "guzzlehttp/psr7", Version: "1.5.2"}},
									{Library: depTypes.Library{Name: "laravel/installer", Version: "v2.0.1"}},
									{Library: depTypes.Library{Name: "pear/log", Version: "1.13.1"}},
									{Library: depTypes.Library{Name: "pear/pear_exception", Version: "v1.0.0"}},
									{Library: depTypes.Library{Name: "psr/http-message", Version: "1.0.1"}},
									{Library: depTypes.Library{Name: "ralouphie/getallheaders", Version: "2.0.5"}},
									{Library: depTypes.Library{Name: "symfony/console", Version: "v4.2.7"}},
									{Library: depTypes.Library{Name: "symfony/contracts", Version: "v1.0.2"}},
									{Library: depTypes.Library{Name: "symfony/filesystem", Version: "v4.2.7"}},
									{Library: depTypes.Library{Name: "symfony/polyfill-ctype", Version: "v1.11.0"}},
									{Library: depTypes.Library{Name: "symfony/polyfill-mbstring", Version: "v1.11.0"}},
									{Library: depTypes.Library{Name: "symfony/process", Version: "v4.2.7"}},
								},
							}},
							OpaqueDirs: []string{"php-app/"},
						},
					},
				},
			},
			want: types.ImageReference{
				Name: "testdata/vuln-image.tar.gz",
				ID:   "sha256:58701fd185bda36cab0557bb6438661831267aa4a9e0b54211c4d5317a48aff4",
				LayerIDs: []string{
					"sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					"sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
					"sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
					"sha256:a4595c43a874856bf95f3bfc4fbf78bbaa04c92c726276d4f64193a47ced0566",
				},
			},
		},
		{
			name:      "sad path, MissingLayers returns an error",
			imagePath: "testdata/alpine.tar.gz",
			missingLayerExpectation: cache.ImageCacheMissingLayersExpectation{
				Args: cache.ImageCacheMissingLayersArgs{
					ImageID:  "sha256:965ea09ff2ebd2b9eeec88cd822ce156f6674c7e99be082c7efac3c62f3ff652",
					LayerIDs: []string{"sha256:77cae8ab23bf486355d1b3191259705374f4a11d483b24964d2f729dd8c076a0"},
				},
				Returns: cache.ImageCacheMissingLayersReturns{
					Err: xerrors.New("MissingLayers failed"),
				},
			},
			wantErr: "MissingLayers failed",
		},
		{
			name:      "sad path, PutLayer returns an error",
			imagePath: "testdata/alpine.tar.gz",
			missingLayerExpectation: cache.ImageCacheMissingLayersExpectation{
				Args: cache.ImageCacheMissingLayersArgs{
					ImageID:  "sha256:965ea09ff2ebd2b9eeec88cd822ce156f6674c7e99be082c7efac3c62f3ff652",
					LayerIDs: []string{"sha256:77cae8ab23bf486355d1b3191259705374f4a11d483b24964d2f729dd8c076a0"},
				},
				Returns: cache.ImageCacheMissingLayersReturns{
					MissingLayerIDs: []string{"sha256:77cae8ab23bf486355d1b3191259705374f4a11d483b24964d2f729dd8c076a0"},
				},
			},
			putLayerExpectations: []cache.ImageCachePutLayerExpectation{
				{
					Args: cache.ImageCachePutLayerArgs{
						DiffID: "sha256:77cae8ab23bf486355d1b3191259705374f4a11d483b24964d2f729dd8c076a0",
						LayerInfo: types.LayerInfo{
							SchemaVersion: 1,
							Digest:        "",
							DiffID:        "sha256:77cae8ab23bf486355d1b3191259705374f4a11d483b24964d2f729dd8c076a0",
							OS: &types.OS{
								Family: "alpine",
								Name:   "3.10.3",
							},
							PackageInfos:  []types.PackageInfo{{FilePath: "lib/apk/db/installed", Packages: []types.Package{{Name: "musl", Version: "1.1.22-r3", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "busybox", Version: "1.30.1-r2", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "alpine-baselayout", Version: "3.1.2-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "alpine-keys", Version: "2.1-r2", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "openssl", Version: "1.1.1d-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "libcrypto1.1", Version: "1.1.1d-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "libssl1.1", Version: "1.1.1d-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "ca-certificates", Version: "20190108-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "ca-certificates-cacert", Version: "20190108-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "libtls-standalone", Version: "2.9.1-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "ssl_client", Version: "1.30.1-r2", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "zlib", Version: "1.2.11-r1", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "apk-tools", Version: "2.10.4-r2", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "pax-utils", Version: "1.2.3-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "scanelf", Version: "1.2.3-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "musl-utils", Version: "1.1.22-r3", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "libc-dev", Version: "0.7.1-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}, {Name: "libc-utils", Version: "0.7.1-r0", Release: "", Epoch: 0, Arch: "", SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0}}}},
							Applications:  []types.Application(nil),
							OpaqueDirs:    []string(nil),
							WhiteoutFiles: []string(nil),
						},
					},
					Returns: cache.ImageCachePutLayerReturns{
						Err: errors.New("put layer failed"),
					},
				},
			},
			wantErr: "put layer failed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCache := new(cache.MockImageCache)
			mockCache.ApplyMissingLayersExpectation(tt.missingLayerExpectation)
			mockCache.ApplyPutLayerExpectations(tt.putLayerExpectations)
			mockCache.ApplyPutImageExpectations(tt.putImageExpectations)

			d, err := docker.NewArchiveImageExtractor(tt.imagePath)
			require.NoError(t, err, tt.name)

			ac := analyzer.New(d, mockCache)
			got, err := ac.Analyze(context.Background())
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
			} else {
				require.NoError(t, err, tt.name)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestApplier_ApplyLayers(t *testing.T) {
	type args struct {
		imageID  string
		layerIDs []string
	}
	tests := []struct {
		name                 string
		args                 args
		getLayerExpectations []cache.LocalImageCacheGetLayerExpectation
		getImageExpectations []cache.LocalImageCacheGetImageExpectation
		want                 types.ImageDetail
		wantErr              string
	}{
		{
			name: "happy path",
			args: args{
				imageID: "sha256:4791503518dff090d6a82f7a5c1fd71c41146920e2562fb64308e17ab6834b7e",
				layerIDs: []string{
					"sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					"sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
					"sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
				},
			},
			getLayerExpectations: []cache.LocalImageCacheGetLayerExpectation{
				{
					Args: cache.LocalImageCacheGetLayerArgs{
						LayerID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
					Returns: cache.LocalImageCacheGetLayerReturns{
						LayerInfo: types.LayerInfo{
							SchemaVersion: 1,
							Digest:        "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
							DiffID:        "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
							OS: &types.OS{
								Family: "debian",
								Name:   "9.9",
							},
							PackageInfos: []types.PackageInfo{
								{
									FilePath: "var/lib/dpkg/status.d/tzdata",
									Packages: []types.Package{
										{
											Name:       "tzdata",
											Version:    "2019a-0+deb9u1",
											SrcName:    "tzdata",
											SrcVersion: "2019a-0+deb9u1",
										},
									},
								},
							},
						},
					},
				},
				{
					Args: cache.LocalImageCacheGetLayerArgs{
						LayerID: "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
					},
					Returns: cache.LocalImageCacheGetLayerReturns{
						LayerInfo: types.LayerInfo{
							SchemaVersion: 1,
							Digest:        "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
							DiffID:        "sha256:aad63a9339440e7c3e1fff2b988991b9bfb81280042fa7f39a5e327023056819",
							PackageInfos: []types.PackageInfo{
								{
									FilePath: "var/lib/dpkg/status.d/libc6",
									Packages: []types.Package{
										{
											Name:       "libc6",
											Version:    "2.24-11+deb9u4",
											SrcName:    "glibc",
											SrcVersion: "2.24-11+deb9u4",
										},
									},
								},
							},
							Applications:  nil,
							OpaqueDirs:    nil,
							WhiteoutFiles: nil,
						},
					},
				},
				{
					Args: cache.LocalImageCacheGetLayerArgs{
						LayerID: "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
					},
					Returns: cache.LocalImageCacheGetLayerReturns{
						LayerInfo: types.LayerInfo{
							SchemaVersion: 1,
							Digest:        "sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203",
							DiffID:        "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
							Applications: []types.Application{
								{
									Type:     "composer",
									FilePath: "php-app/composer.lock",
									Libraries: []types.LibraryInfo{
										{
											Library: depTypes.Library{
												Name:    "guzzlehttp/guzzle",
												Version: "6.2.0",
											},
										},
										{
											Library: depTypes.Library{
												Name:    "symfony/process",
												Version: "v4.2.7",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			getImageExpectations: []cache.LocalImageCacheGetImageExpectation{
				{
					Args: cache.LocalImageCacheGetImageArgs{
						ImageID: "sha256:4791503518dff090d6a82f7a5c1fd71c41146920e2562fb64308e17ab6834b7e",
					},
					Returns: cache.LocalImageCacheGetImageReturns{
						ImageInfo: types.ImageInfo{
							SchemaVersion: 1,
						},
					},
				},
			},
			want: types.ImageDetail{
				OS: &types.OS{
					Family: "debian",
					Name:   "9.9",
				},
				Packages: []types.Package{
					{
						Name: "libc6", Version: "2.24-11+deb9u4", SrcName: "glibc", SrcVersion: "2.24-11+deb9u4",
						Layer: types.Layer{
							Digest: "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
							DiffID: "sha256:aad63a9339440e7c3e1fff2b988991b9bfb81280042fa7f39a5e327023056819",
						},
					},
					{
						Name: "tzdata", Version: "2019a-0+deb9u1", SrcName: "tzdata", SrcVersion: "2019a-0+deb9u1",
						Layer: types.Layer{
							Digest: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
							DiffID: "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
						},
					},
				},
				Applications: []types.Application{
					{
						Type: "composer", FilePath: "php-app/composer.lock",
						Libraries: []types.LibraryInfo{
							{
								Library: depTypes.Library{
									Name:    "guzzlehttp/guzzle",
									Version: "6.2.0",
								},
								Layer: types.Layer{
									Digest: "sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203",
									DiffID: "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
								},
							},
							{
								Library: depTypes.Library{
									Name:    "symfony/process",
									Version: "v4.2.7",
								},
								Layer: types.Layer{
									Digest: "sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203",
									DiffID: "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "happy path with history packages",
			args: args{
				imageID: "sha256:3bb70bd5fb37e05b8ecaaace5d6a6b5ec7834037c07ecb5907355c23ab70352d",
				layerIDs: []string{
					"sha256:531743b7098cb2aaf615641007a129173f63ed86ca32fe7b5a246a1c47286028",
				},
			},
			getLayerExpectations: []cache.LocalImageCacheGetLayerExpectation{
				{
					Args: cache.LocalImageCacheGetLayerArgs{
						LayerID: "sha256:531743b7098cb2aaf615641007a129173f63ed86ca32fe7b5a246a1c47286028",
					},
					Returns: cache.LocalImageCacheGetLayerReturns{
						LayerInfo: types.LayerInfo{
							SchemaVersion: 1,
							Digest:        "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
							DiffID:        "sha256:531743b7098cb2aaf615641007a129173f63ed86ca32fe7b5a246a1c47286028",
							OS: &types.OS{
								Family: "alpine",
								Name:   "3.10.4",
							},
							PackageInfos: []types.PackageInfo{
								{
									FilePath: "lib/apk/db/installed",
									Packages: []types.Package{
										{Name: "musl", Version: "1.1.22-r3"},
										{Name: "busybox", Version: "1.30.1-r3"},
										{Name: "openssl", Version: "1.1.1d-r2"},
										{Name: "libcrypto1.1", Version: "1.1.1d-r2"},
										{Name: "libssl1.1", Version: "1.1.1d-r2"},
									},
								},
							},
						},
					},
				},
			},
			getImageExpectations: []cache.LocalImageCacheGetImageExpectation{
				{
					Args: cache.LocalImageCacheGetImageArgs{
						ImageID: "sha256:3bb70bd5fb37e05b8ecaaace5d6a6b5ec7834037c07ecb5907355c23ab70352d",
					},
					Returns: cache.LocalImageCacheGetImageReturns{
						ImageInfo: types.ImageInfo{
							SchemaVersion: 1,
							HistoryPackages: []types.Package{
								{Name: "musl", Version: "1.1.23"},
								{Name: "busybox", Version: "1.31"},
								{Name: "ncurses-libs", Version: "6.1_p20190518-r0"},
								{Name: "ncurses-terminfo-base", Version: "6.1_p20190518-r0"},
								{Name: "ncurses", Version: "6.1_p20190518-r0"},
								{Name: "ncurses-terminfo", Version: "6.1_p20190518-r0"},
								{Name: "bash", Version: "5.0.0-r0"},
								{Name: "readline", Version: "8.0.0-r0"},
							},
						},
					},
				},
			},
			want: types.ImageDetail{
				OS: &types.OS{
					Family: "alpine",
					Name:   "3.10.4",
				},
				Packages: []types.Package{
					{
						Name:    "busybox",
						Version: "1.30.1-r3",
						Layer: types.Layer{
							Digest: "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
							DiffID: "sha256:531743b7098cb2aaf615641007a129173f63ed86ca32fe7b5a246a1c47286028",
						},
					},
					{
						Name:    "libcrypto1.1",
						Version: "1.1.1d-r2",
						Layer: types.Layer{
							Digest: "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
							DiffID: "sha256:531743b7098cb2aaf615641007a129173f63ed86ca32fe7b5a246a1c47286028",
						},
					},
					{
						Name:    "libssl1.1",
						Version: "1.1.1d-r2",
						Layer: types.Layer{
							Digest: "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
							DiffID: "sha256:531743b7098cb2aaf615641007a129173f63ed86ca32fe7b5a246a1c47286028",
						},
					},
					{
						Name:    "musl",
						Version: "1.1.22-r3",
						Layer: types.Layer{
							Digest: "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
							DiffID: "sha256:531743b7098cb2aaf615641007a129173f63ed86ca32fe7b5a246a1c47286028",
						},
					},
					{
						Name:    "openssl",
						Version: "1.1.1d-r2",
						Layer: types.Layer{
							Digest: "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
							DiffID: "sha256:531743b7098cb2aaf615641007a129173f63ed86ca32fe7b5a246a1c47286028",
						},
					},
				},
				HistoryPackages: []types.Package{
					{Name: "musl", Version: "1.1.23"},
					{Name: "busybox", Version: "1.31"},
					{Name: "ncurses-libs", Version: "6.1_p20190518-r0"},
					{Name: "ncurses-terminfo-base", Version: "6.1_p20190518-r0"},
					{Name: "ncurses", Version: "6.1_p20190518-r0"},
					{Name: "ncurses-terminfo", Version: "6.1_p20190518-r0"},
					{Name: "bash", Version: "5.0.0-r0"},
					{Name: "readline", Version: "8.0.0-r0"},
				},
			},
		},
		{
			name: "sad path GetLayer returns an error",
			args: args{
				layerIDs: []string{
					"sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
				},
			},
			getLayerExpectations: []cache.LocalImageCacheGetLayerExpectation{
				{
					Args: cache.LocalImageCacheGetLayerArgs{
						LayerID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
					Returns: cache.LocalImageCacheGetLayerReturns{LayerInfo: types.LayerInfo{}},
				},
			},
			wantErr: "layer cache missing",
		},
		{
			name: "sad path GetLayer returns empty layer info",
			args: args{
				layerIDs: []string{
					"sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
				},
			},
			getLayerExpectations: []cache.LocalImageCacheGetLayerExpectation{
				{
					Args: cache.LocalImageCacheGetLayerArgs{
						LayerID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
					Returns: cache.LocalImageCacheGetLayerReturns{LayerInfo: types.LayerInfo{}},
				},
			},
			wantErr: "layer cache missing",
		},
		{
			name: "happy path with some packages but unknown OS",
			args: args{
				imageID: "sha256:4791503518dff090d6a82f7a5c1fd71c41146920e2562fb64308e17ab6834b7e",
				layerIDs: []string{
					"sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					"sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
					"sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
				},
			},
			getLayerExpectations: []cache.LocalImageCacheGetLayerExpectation{
				{
					Args: cache.LocalImageCacheGetLayerArgs{
						LayerID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
					Returns: cache.LocalImageCacheGetLayerReturns{
						LayerInfo: types.LayerInfo{
							SchemaVersion: 1,
							Digest:        "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
							DiffID:        "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
							PackageInfos: []types.PackageInfo{
								{
									FilePath: "var/lib/dpkg/status.d/tzdata",
									Packages: []types.Package{
										{
											Name:       "tzdata",
											Version:    "2019a-0+deb9u1",
											SrcName:    "tzdata",
											SrcVersion: "2019a-0+deb9u1",
										},
									},
								},
							},
						},
					},
				},
				{
					Args: cache.LocalImageCacheGetLayerArgs{
						LayerID: "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
					},
					Returns: cache.LocalImageCacheGetLayerReturns{
						LayerInfo: types.LayerInfo{
							SchemaVersion: 1,
							Digest:        "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
							DiffID:        "sha256:aad63a9339440e7c3e1fff2b988991b9bfb81280042fa7f39a5e327023056819",
							PackageInfos: []types.PackageInfo{
								{
									FilePath: "var/lib/dpkg/status.d/libc6",
									Packages: []types.Package{
										{
											Name:       "libc6",
											Version:    "2.24-11+deb9u4",
											SrcName:    "glibc",
											SrcVersion: "2.24-11+deb9u4",
										},
									},
								},
							},
							Applications:  nil,
							OpaqueDirs:    nil,
							WhiteoutFiles: nil,
						},
					},
				},
				{
					Args: cache.LocalImageCacheGetLayerArgs{
						LayerID: "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
					},
					Returns: cache.LocalImageCacheGetLayerReturns{
						LayerInfo: types.LayerInfo{
							SchemaVersion: 1,
							Digest:        "sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203",
							DiffID:        "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
							Applications: []types.Application{
								{
									Type:     "composer",
									FilePath: "php-app/composer.lock",
									Libraries: []types.LibraryInfo{
										{
											Library: depTypes.Library{
												Name:    "guzzlehttp/guzzle",
												Version: "6.2.0",
											},
										},
										{
											Library: depTypes.Library{
												Name:    "symfony/process",
												Version: "v4.2.7",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: types.ImageDetail{
				Packages: []types.Package{
					{
						Name: "libc6", Version: "2.24-11+deb9u4", SrcName: "glibc", SrcVersion: "2.24-11+deb9u4",
						Layer: types.Layer{
							Digest: "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
							DiffID: "sha256:aad63a9339440e7c3e1fff2b988991b9bfb81280042fa7f39a5e327023056819",
						},
					},
					{
						Name: "tzdata", Version: "2019a-0+deb9u1", SrcName: "tzdata", SrcVersion: "2019a-0+deb9u1",
						Layer: types.Layer{
							Digest: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
							DiffID: "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
						},
					},
				},
				Applications: []types.Application{
					{
						Type: "composer", FilePath: "php-app/composer.lock",
						Libraries: []types.LibraryInfo{
							{
								Library: depTypes.Library{
									Name:    "guzzlehttp/guzzle",
									Version: "6.2.0",
								},
								Layer: types.Layer{
									Digest: "sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203",
									DiffID: "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
								},
							},
							{
								Library: depTypes.Library{
									Name:    "symfony/process",
									Version: "v4.2.7",
								},
								Layer: types.Layer{
									Digest: "sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203",
									DiffID: "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
								},
							},
						},
					},
				},
			},
			wantErr: "unknown OS",
		},
		{
			name: "sad path no package detected",
			args: args{
				layerIDs: []string{
					"sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
				},
			},
			getLayerExpectations: []cache.LocalImageCacheGetLayerExpectation{
				{
					Args: cache.LocalImageCacheGetLayerArgs{
						LayerID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
					Returns: cache.LocalImageCacheGetLayerReturns{
						LayerInfo: types.LayerInfo{
							SchemaVersion: 1,
							OS: &types.OS{
								Family: "debian",
								Name:   "9.9",
							},
						},
					},
				},
			},
			want: types.ImageDetail{
				OS: &types.OS{
					Family: "debian",
					Name:   "9.9",
				},
			},
			wantErr: "no packages detected",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := new(cache.MockLocalImageCache)
			c.ApplyGetLayerExpectations(tt.getLayerExpectations)
			c.ApplyGetImageExpectations(tt.getImageExpectations)

			a := analyzer.NewApplier(c)

			got, err := a.ApplyLayers(tt.args.imageID, tt.args.layerIDs)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
			} else {
				require.NoError(t, err, tt.name)
			}

			sort.Slice(got.Packages, func(i, j int) bool {
				return got.Packages[i].Name < got.Packages[j].Name
			})
			for _, app := range got.Applications {
				sort.Slice(app.Libraries, func(i, j int) bool {
					return app.Libraries[i].Library.Name < app.Libraries[j].Library.Name
				})
			}
			assert.Equal(t, tt.want, got)
			c.AssertExpectations(t)
		})
	}
}
