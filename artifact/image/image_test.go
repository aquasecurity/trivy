package image_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	_ "github.com/aquasecurity/fanal/analyzer/all"
	"github.com/aquasecurity/fanal/analyzer/config"
	image2 "github.com/aquasecurity/fanal/artifact/image"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/hook"
	_ "github.com/aquasecurity/fanal/hook/all"
	"github.com/aquasecurity/fanal/image"
	"github.com/aquasecurity/fanal/types"
	depTypes "github.com/aquasecurity/go-dep-parser/pkg/types"
)

func TestArtifact_Inspect(t *testing.T) {
	tests := []struct {
		name                    string
		imagePath               string
		disableAnalyzers        []analyzer.Type
		disableHooks            []hook.Type
		missingBlobsExpectation cache.ArtifactCacheMissingBlobsExpectation
		putBlobExpectations     []cache.ArtifactCachePutBlobExpectation
		putArtifactExpectations []cache.ArtifactCachePutArtifactExpectation
		want                    types.ArtifactReference
		wantErr                 string
	}{
		{
			name:      "happy path",
			imagePath: "../../test/testdata/alpine-311.tar.gz",
			missingBlobsExpectation: cache.ArtifactCacheMissingBlobsExpectation{
				Args: cache.ArtifactCacheMissingBlobsArgs{
					ArtifactID: "sha256:59c4082ceb491faefd44cf9a006dd24c8f57b44b438f081251c90ea1367ca043",
					BlobIDs:    []string{"sha256:868fafa15d51961bffd953db0369326b78b8fbff5c856283f642941645cfe630"},
				},
				Returns: cache.ArtifactCacheMissingBlobsReturns{
					MissingArtifact: true,
					MissingBlobIDs:  []string{"sha256:868fafa15d51961bffd953db0369326b78b8fbff5c856283f642941645cfe630"},
				},
			},
			putBlobExpectations: []cache.ArtifactCachePutBlobExpectation{
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:868fafa15d51961bffd953db0369326b78b8fbff5c856283f642941645cfe630",
						BlobInfo: types.BlobInfo{
							SchemaVersion: 1,
							Digest:        "",
							DiffID:        "sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203",
							OS: &types.OS{
								Family: "alpine",
								Name:   "3.11.5",
							},
							PackageInfos: []types.PackageInfo{{
								FilePath: "lib/apk/db/installed",
								Packages: []types.Package{
									{Name: "alpine-baselayout", Version: "3.2.0-r3", SrcName: "alpine-baselayout", SrcVersion: "3.2.0-r3", License: "GPL-2.0-only"},
									{Name: "alpine-keys", Version: "2.1-r2", SrcName: "alpine-keys", SrcVersion: "2.1-r2", License: "MIT"},
									{Name: "apk-tools", Version: "2.10.4-r3", SrcName: "apk-tools", SrcVersion: "2.10.4-r3", License: "GPL2"},
									{Name: "busybox", Version: "1.31.1-r9", SrcName: "busybox", SrcVersion: "1.31.1-r9", License: "GPL-2.0-only"},
									{Name: "ca-certificates-cacert", Version: "20191127-r1", SrcName: "ca-certificates", SrcVersion: "20191127-r1", License: "MPL-2.0 GPL-2.0-or-later"},
									{Name: "libc-utils", Version: "0.7.2-r0", SrcName: "libc-dev", SrcVersion: "0.7.2-r0", License: "BSD"},
									{Name: "libcrypto1.1", Version: "1.1.1d-r3", SrcName: "openssl", SrcVersion: "1.1.1d-r3", License: "OpenSSL"},
									{Name: "libssl1.1", Version: "1.1.1d-r3", SrcName: "openssl", SrcVersion: "1.1.1d-r3", License: "OpenSSL"},
									{Name: "libtls-standalone", Version: "2.9.1-r0", SrcName: "libtls-standalone", SrcVersion: "2.9.1-r0", License: "ISC"},
									{Name: "musl", Version: "1.1.24-r2", SrcName: "musl", SrcVersion: "1.1.24-r2", License: "MIT"},
									{Name: "musl-utils", Version: "1.1.24-r2", SrcName: "musl", SrcVersion: "1.1.24-r2", License: "MIT BSD GPL2+"},
									{Name: "scanelf", Version: "1.2.4-r0", SrcName: "pax-utils", SrcVersion: "1.2.4-r0", License: "GPL-2.0-only"},
									{Name: "ssl_client", Version: "1.31.1-r9", SrcName: "busybox", SrcVersion: "1.31.1-r9", License: "GPL-2.0-only"},
									{Name: "zlib", Version: "1.2.11-r3", SrcName: "zlib", SrcVersion: "1.2.11-r3", License: "Zlib"},
								},
							}},
							Applications:  []types.Application(nil),
							OpaqueDirs:    []string(nil),
							WhiteoutFiles: []string(nil),
						},
					},
					Returns: cache.ArtifactCachePutBlobReturns{},
				},
			},
			putArtifactExpectations: []cache.ArtifactCachePutArtifactExpectation{
				{
					Args: cache.ArtifactCachePutArtifactArgs{
						ArtifactID: "sha256:59c4082ceb491faefd44cf9a006dd24c8f57b44b438f081251c90ea1367ca043",
						ArtifactInfo: types.ArtifactInfo{
							SchemaVersion: 1,
							Architecture:  "amd64",
							Created:       time.Date(2020, 3, 23, 21, 19, 34, 196162891, time.UTC),
							DockerVersion: "18.09.7",
							OS:            "linux",
						},
					},
				},
			},
			want: types.ArtifactReference{
				Name:    "../../test/testdata/alpine-311.tar.gz",
				Type:    types.ArtifactContainerImage,
				ID:      "sha256:59c4082ceb491faefd44cf9a006dd24c8f57b44b438f081251c90ea1367ca043",
				BlobIDs: []string{"sha256:868fafa15d51961bffd953db0369326b78b8fbff5c856283f642941645cfe630"},
			},
		},
		{
			name:      "happy path: include lock files",
			imagePath: "../../test/testdata/vuln-image.tar.gz",
			missingBlobsExpectation: cache.ArtifactCacheMissingBlobsExpectation{
				Args: cache.ArtifactCacheMissingBlobsArgs{
					ArtifactID: "sha256:b79b48d9023d85be348e989163bb5f78bf9d0a9e6004a656dba50841ff212693",
					BlobIDs: []string{
						"sha256:b84728aa02ac822f6c83b6864a6a81be09f533a0ac4462ed3614daa7a9d9c72b",
						"sha256:aa3e1096dc950427d0f6a7bfdc519b39be4051459f7562d5f9693942b3ba3bf8",
						"sha256:bffb1ac0624bb6f64e4f3ebd160fd2fb183825e6dec009ffc365efba749432ef",
						"sha256:d9b84a3857355817fe46ebdde8e58009c37ea8965bd39bfe5a07e14875ca6080",
					},
				},
				Returns: cache.ArtifactCacheMissingBlobsReturns{
					MissingBlobIDs: []string{
						"sha256:b84728aa02ac822f6c83b6864a6a81be09f533a0ac4462ed3614daa7a9d9c72b",
						"sha256:aa3e1096dc950427d0f6a7bfdc519b39be4051459f7562d5f9693942b3ba3bf8",
						"sha256:bffb1ac0624bb6f64e4f3ebd160fd2fb183825e6dec009ffc365efba749432ef",
						"sha256:d9b84a3857355817fe46ebdde8e58009c37ea8965bd39bfe5a07e14875ca6080",
					},
				},
			},
			putBlobExpectations: []cache.ArtifactCachePutBlobExpectation{
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:b84728aa02ac822f6c83b6864a6a81be09f533a0ac4462ed3614daa7a9d9c72b",
						BlobInfo: types.BlobInfo{
							SchemaVersion: 1,
							Digest:        "",
							DiffID:        "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
							OS: &types.OS{
								Family: "debian",
								Name:   "9.9",
							},
							PackageInfos: []types.PackageInfo{
								{
									FilePath: "var/lib/dpkg/status.d/base",
									Packages: []types.Package{
										{Name: "base-files", Version: "9.9+deb9u9", SrcName: "base-files", SrcVersion: "9.9+deb9u9"},
									},
								},
								{
									FilePath: "var/lib/dpkg/status.d/netbase",
									Packages: []types.Package{
										{Name: "netbase", Version: "5.4", SrcName: "netbase", SrcVersion: "5.4"},
									},
								},
								{
									FilePath: "var/lib/dpkg/status.d/tzdata",
									Packages: []types.Package{
										{Name: "tzdata", Version: "2019a-0+deb9u1", SrcName: "tzdata", SrcVersion: "2019a-0+deb9u1"},
									},
								},
							},
						},
					},
				},
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:aa3e1096dc950427d0f6a7bfdc519b39be4051459f7562d5f9693942b3ba3bf8",
						BlobInfo: types.BlobInfo{
							SchemaVersion: 1,
							Digest:        "",
							DiffID:        "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
							PackageInfos: []types.PackageInfo{
								{
									FilePath: "var/lib/dpkg/status.d/libc6",
									Packages: []types.Package{
										{Name: "libc6", Version: "2.24-11+deb9u4", SrcName: "glibc", SrcVersion: "2.24-11+deb9u4"},
									},
								},
								{
									FilePath: "var/lib/dpkg/status.d/libssl1",
									Packages: []types.Package{
										{Name: "libssl1.1", Version: "1.1.0k-1~deb9u1", SrcName: "openssl", SrcVersion: "1.1.0k-1~deb9u1"},
									},
								},
								{
									FilePath: "var/lib/dpkg/status.d/openssl",
									Packages: []types.Package{
										{Name: "openssl", Version: "1.1.0k-1~deb9u1", SrcName: "openssl", SrcVersion: "1.1.0k-1~deb9u1"},
									},
								},
							},
						},
					},
				},
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:bffb1ac0624bb6f64e4f3ebd160fd2fb183825e6dec009ffc365efba749432ef",
						BlobInfo: types.BlobInfo{
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
				{
					// Gemfile.lock will not be scanned.
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:d9b84a3857355817fe46ebdde8e58009c37ea8965bd39bfe5a07e14875ca6080",
						BlobInfo: types.BlobInfo{
							SchemaVersion: 1,
							Digest:        "",
							DiffID:        "sha256:a4595c43a874856bf95f3bfc4fbf78bbaa04c92c726276d4f64193a47ced0566",
							OpaqueDirs:    []string{"ruby-app/"},
						},
					},
				},
			},
			want: types.ArtifactReference{
				Name: "../../test/testdata/vuln-image.tar.gz",
				Type: types.ArtifactContainerImage,
				ID:   "sha256:b79b48d9023d85be348e989163bb5f78bf9d0a9e6004a656dba50841ff212693",
				BlobIDs: []string{
					"sha256:b84728aa02ac822f6c83b6864a6a81be09f533a0ac4462ed3614daa7a9d9c72b",
					"sha256:aa3e1096dc950427d0f6a7bfdc519b39be4051459f7562d5f9693942b3ba3bf8",
					"sha256:bffb1ac0624bb6f64e4f3ebd160fd2fb183825e6dec009ffc365efba749432ef",
					"sha256:d9b84a3857355817fe46ebdde8e58009c37ea8965bd39bfe5a07e14875ca6080",
				},
			},
		},
		{
			name:             "happy path: disable analyzers",
			imagePath:        "../../test/testdata/vuln-image.tar.gz",
			disableAnalyzers: []analyzer.Type{analyzer.TypeDebian, analyzer.TypeDpkg, analyzer.TypeComposer, analyzer.TypeBundler},
			missingBlobsExpectation: cache.ArtifactCacheMissingBlobsExpectation{
				Args: cache.ArtifactCacheMissingBlobsArgs{
					ArtifactID: "sha256:b79b48d9023d85be348e989163bb5f78bf9d0a9e6004a656dba50841ff212693",
					BlobIDs: []string{
						"sha256:00080f51a7badb4ca442a2fabdf5033006899b8de6bea9b1530fd0942a952b6c",
						"sha256:902ce3b0e03137f311796a6df2a15dd0729b88857a3c0b48b2f7098de87f633b",
						"sha256:b2a31345f7afe47856b2d19c8490597cb2335d7e8a43134359684fb4df78ec19",
						"sha256:bef0956a7402c9cb87f4662486557517f00bc1049099e4dfef4b83be70dce242",
					},
				},
				Returns: cache.ArtifactCacheMissingBlobsReturns{
					MissingBlobIDs: []string{
						"sha256:00080f51a7badb4ca442a2fabdf5033006899b8de6bea9b1530fd0942a952b6c",
						"sha256:902ce3b0e03137f311796a6df2a15dd0729b88857a3c0b48b2f7098de87f633b",
						"sha256:b2a31345f7afe47856b2d19c8490597cb2335d7e8a43134359684fb4df78ec19",
						"sha256:bef0956a7402c9cb87f4662486557517f00bc1049099e4dfef4b83be70dce242",
					},
				},
			},
			putBlobExpectations: []cache.ArtifactCachePutBlobExpectation{
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:00080f51a7badb4ca442a2fabdf5033006899b8de6bea9b1530fd0942a952b6c",
						BlobInfo: types.BlobInfo{
							SchemaVersion: 1,
							Digest:        "",
							DiffID:        "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
						},
					},
				},
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:902ce3b0e03137f311796a6df2a15dd0729b88857a3c0b48b2f7098de87f633b",
						BlobInfo: types.BlobInfo{
							SchemaVersion: 1,
							Digest:        "",
							DiffID:        "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
						},
					},
				},
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:b2a31345f7afe47856b2d19c8490597cb2335d7e8a43134359684fb4df78ec19",
						BlobInfo: types.BlobInfo{
							SchemaVersion: 1,
							Digest:        "",
							DiffID:        "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
							OpaqueDirs:    []string{"php-app/"},
						},
					},
				},
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:bef0956a7402c9cb87f4662486557517f00bc1049099e4dfef4b83be70dce242",
						BlobInfo: types.BlobInfo{
							SchemaVersion: 1,
							Digest:        "",
							DiffID:        "sha256:a4595c43a874856bf95f3bfc4fbf78bbaa04c92c726276d4f64193a47ced0566",
							OpaqueDirs:    []string{"ruby-app/"},
						},
					},
				},
			},
			want: types.ArtifactReference{
				Name: "../../test/testdata/vuln-image.tar.gz",
				Type: types.ArtifactContainerImage,
				ID:   "sha256:b79b48d9023d85be348e989163bb5f78bf9d0a9e6004a656dba50841ff212693",
				BlobIDs: []string{
					"sha256:00080f51a7badb4ca442a2fabdf5033006899b8de6bea9b1530fd0942a952b6c",
					"sha256:902ce3b0e03137f311796a6df2a15dd0729b88857a3c0b48b2f7098de87f633b",
					"sha256:b2a31345f7afe47856b2d19c8490597cb2335d7e8a43134359684fb4df78ec19",
					"sha256:bef0956a7402c9cb87f4662486557517f00bc1049099e4dfef4b83be70dce242",
				},
			},
		},
		{
			name:      "sad path, MissingBlobs returns an error",
			imagePath: "../../test/testdata/alpine-311.tar.gz",
			missingBlobsExpectation: cache.ArtifactCacheMissingBlobsExpectation{
				Args: cache.ArtifactCacheMissingBlobsArgs{
					ArtifactID: "sha256:59c4082ceb491faefd44cf9a006dd24c8f57b44b438f081251c90ea1367ca043",
					BlobIDs:    []string{"sha256:868fafa15d51961bffd953db0369326b78b8fbff5c856283f642941645cfe630"},
				},
				Returns: cache.ArtifactCacheMissingBlobsReturns{
					Err: xerrors.New("MissingBlobs failed"),
				},
			},
			wantErr: "MissingBlobs failed",
		},
		{
			name:      "sad path, PutBlob returns an error",
			imagePath: "../../test/testdata/alpine-311.tar.gz",
			missingBlobsExpectation: cache.ArtifactCacheMissingBlobsExpectation{
				Args: cache.ArtifactCacheMissingBlobsArgs{
					ArtifactID: "sha256:59c4082ceb491faefd44cf9a006dd24c8f57b44b438f081251c90ea1367ca043",
					BlobIDs:    []string{"sha256:868fafa15d51961bffd953db0369326b78b8fbff5c856283f642941645cfe630"},
				},
				Returns: cache.ArtifactCacheMissingBlobsReturns{
					MissingBlobIDs: []string{"sha256:868fafa15d51961bffd953db0369326b78b8fbff5c856283f642941645cfe630"},
				},
			},
			putBlobExpectations: []cache.ArtifactCachePutBlobExpectation{
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:868fafa15d51961bffd953db0369326b78b8fbff5c856283f642941645cfe630",
						BlobInfo: types.BlobInfo{
							SchemaVersion: 1,
							Digest:        "",
							DiffID:        "sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203",
							OS: &types.OS{
								Family: "alpine",
								Name:   "3.11.5",
							},
							PackageInfos: []types.PackageInfo{{
								FilePath: "lib/apk/db/installed",
								Packages: []types.Package{
									{Name: "alpine-baselayout", Version: "3.2.0-r3", SrcName: "alpine-baselayout", SrcVersion: "3.2.0-r3", License: "GPL-2.0-only"},
									{Name: "alpine-keys", Version: "2.1-r2", SrcName: "alpine-keys", SrcVersion: "2.1-r2", License: "MIT"},
									{Name: "apk-tools", Version: "2.10.4-r3", SrcName: "apk-tools", SrcVersion: "2.10.4-r3", License: "GPL2"},
									{Name: "busybox", Version: "1.31.1-r9", SrcName: "busybox", SrcVersion: "1.31.1-r9", License: "GPL-2.0-only"},
									{Name: "ca-certificates-cacert", Version: "20191127-r1", SrcName: "ca-certificates", SrcVersion: "20191127-r1", License: "MPL-2.0 GPL-2.0-or-later"},
									{Name: "libc-utils", Version: "0.7.2-r0", SrcName: "libc-dev", SrcVersion: "0.7.2-r0", License: "BSD"},
									{Name: "libcrypto1.1", Version: "1.1.1d-r3", SrcName: "openssl", SrcVersion: "1.1.1d-r3", License: "OpenSSL"},
									{Name: "libssl1.1", Version: "1.1.1d-r3", SrcName: "openssl", SrcVersion: "1.1.1d-r3", License: "OpenSSL"},
									{Name: "libtls-standalone", Version: "2.9.1-r0", SrcName: "libtls-standalone", SrcVersion: "2.9.1-r0", License: "ISC"},
									{Name: "musl", Version: "1.1.24-r2", SrcName: "musl", SrcVersion: "1.1.24-r2", License: "MIT"},
									{Name: "musl-utils", Version: "1.1.24-r2", SrcName: "musl", SrcVersion: "1.1.24-r2", License: "MIT BSD GPL2+"},
									{Name: "scanelf", Version: "1.2.4-r0", SrcName: "pax-utils", SrcVersion: "1.2.4-r0", License: "GPL-2.0-only"},
									{Name: "ssl_client", Version: "1.31.1-r9", SrcName: "busybox", SrcVersion: "1.31.1-r9", License: "GPL-2.0-only"},
									{Name: "zlib", Version: "1.2.11-r3", SrcName: "zlib", SrcVersion: "1.2.11-r3", License: "Zlib"},
								},
							}},
							Applications:  []types.Application(nil),
							OpaqueDirs:    []string(nil),
							WhiteoutFiles: []string(nil),
						},
					},
					Returns: cache.ArtifactCachePutBlobReturns{
						Err: errors.New("put layer failed"),
					},
				},
			},
			wantErr: "put layer failed",
		},
		{
			name:      "sad path, PutArtifact returns an error",
			imagePath: "../../test/testdata/alpine-311.tar.gz",
			missingBlobsExpectation: cache.ArtifactCacheMissingBlobsExpectation{
				Args: cache.ArtifactCacheMissingBlobsArgs{
					ArtifactID: "sha256:59c4082ceb491faefd44cf9a006dd24c8f57b44b438f081251c90ea1367ca043",
					BlobIDs:    []string{"sha256:868fafa15d51961bffd953db0369326b78b8fbff5c856283f642941645cfe630"},
				},
				Returns: cache.ArtifactCacheMissingBlobsReturns{
					MissingArtifact: true,
					MissingBlobIDs:  []string{"sha256:868fafa15d51961bffd953db0369326b78b8fbff5c856283f642941645cfe630"},
				},
			},
			putBlobExpectations: []cache.ArtifactCachePutBlobExpectation{
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:868fafa15d51961bffd953db0369326b78b8fbff5c856283f642941645cfe630",
						BlobInfo: types.BlobInfo{
							SchemaVersion: 1,
							Digest:        "",
							DiffID:        "sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203",
							OS: &types.OS{
								Family: "alpine",
								Name:   "3.11.5",
							},
							PackageInfos: []types.PackageInfo{{
								FilePath: "lib/apk/db/installed",
								Packages: []types.Package{
									{Name: "alpine-baselayout", Version: "3.2.0-r3", SrcName: "alpine-baselayout", SrcVersion: "3.2.0-r3", License: "GPL-2.0-only"},
									{Name: "alpine-keys", Version: "2.1-r2", SrcName: "alpine-keys", SrcVersion: "2.1-r2", License: "MIT"},
									{Name: "apk-tools", Version: "2.10.4-r3", SrcName: "apk-tools", SrcVersion: "2.10.4-r3", License: "GPL2"},
									{Name: "busybox", Version: "1.31.1-r9", SrcName: "busybox", SrcVersion: "1.31.1-r9", License: "GPL-2.0-only"},
									{Name: "ca-certificates-cacert", Version: "20191127-r1", SrcName: "ca-certificates", SrcVersion: "20191127-r1", License: "MPL-2.0 GPL-2.0-or-later"},
									{Name: "libc-utils", Version: "0.7.2-r0", SrcName: "libc-dev", SrcVersion: "0.7.2-r0", License: "BSD"},
									{Name: "libcrypto1.1", Version: "1.1.1d-r3", SrcName: "openssl", SrcVersion: "1.1.1d-r3", License: "OpenSSL"},
									{Name: "libssl1.1", Version: "1.1.1d-r3", SrcName: "openssl", SrcVersion: "1.1.1d-r3", License: "OpenSSL"},
									{Name: "libtls-standalone", Version: "2.9.1-r0", SrcName: "libtls-standalone", SrcVersion: "2.9.1-r0", License: "ISC"},
									{Name: "musl", Version: "1.1.24-r2", SrcName: "musl", SrcVersion: "1.1.24-r2", License: "MIT"},
									{Name: "musl-utils", Version: "1.1.24-r2", SrcName: "musl", SrcVersion: "1.1.24-r2", License: "MIT BSD GPL2+"},
									{Name: "scanelf", Version: "1.2.4-r0", SrcName: "pax-utils", SrcVersion: "1.2.4-r0", License: "GPL-2.0-only"},
									{Name: "ssl_client", Version: "1.31.1-r9", SrcName: "busybox", SrcVersion: "1.31.1-r9", License: "GPL-2.0-only"},
									{Name: "zlib", Version: "1.2.11-r3", SrcName: "zlib", SrcVersion: "1.2.11-r3", License: "Zlib"},
								},
							}},
							Applications:  []types.Application(nil),
							OpaqueDirs:    []string(nil),
							WhiteoutFiles: []string(nil),
						},
					},
					Returns: cache.ArtifactCachePutBlobReturns{},
				},
			},
			putArtifactExpectations: []cache.ArtifactCachePutArtifactExpectation{
				{
					Args: cache.ArtifactCachePutArtifactArgs{
						ArtifactID: "sha256:59c4082ceb491faefd44cf9a006dd24c8f57b44b438f081251c90ea1367ca043",
						ArtifactInfo: types.ArtifactInfo{
							SchemaVersion: 1,
							Architecture:  "amd64",
							Created:       time.Date(2020, 3, 23, 21, 19, 34, 196162891, time.UTC),
							DockerVersion: "18.09.7",
							OS:            "linux",
						},
					},
					Returns: cache.ArtifactCachePutArtifactReturns{
						Err: errors.New("put artifact failed"),
					},
				},
			},
			wantErr: "put artifact failed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCache := new(cache.MockArtifactCache)
			mockCache.ApplyMissingBlobsExpectation(tt.missingBlobsExpectation)
			mockCache.ApplyPutBlobExpectations(tt.putBlobExpectations)
			mockCache.ApplyPutArtifactExpectations(tt.putArtifactExpectations)

			img, err := image.NewArchiveImage(tt.imagePath)
			require.NoError(t, err)

			a, err := image2.NewArtifact(img, mockCache, tt.disableAnalyzers, tt.disableHooks, config.ScannerOption{})
			require.NoError(t, err)

			got, err := a.Inspect(context.Background())
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
