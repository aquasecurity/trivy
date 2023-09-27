package image_test

import (
	"context"
	"errors"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	image2 "github.com/aquasecurity/trivy/pkg/fanal/artifact/image"
	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/image"
	"github.com/aquasecurity/trivy/pkg/fanal/types"

	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/config/all"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/imgconf/apk"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/php/composer"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/ruby/bundler"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/licensing"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/alpine"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/debian"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/pkg/apk"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/pkg/dpkg"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/repo/apk"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/secret"
	_ "github.com/aquasecurity/trivy/pkg/fanal/handler/sysfile"
)

func TestArtifact_Inspect(t *testing.T) {
	alpinePkgs := types.Packages{
		{
			ID:         "alpine-baselayout@3.2.0-r3",
			Name:       "alpine-baselayout",
			Version:    "3.2.0-r3",
			SrcName:    "alpine-baselayout",
			SrcVersion: "3.2.0-r3",
			Licenses:   []string{"GPL-2.0"},
			Digest:     "sha1:8f373f5b329c3aaf136eb30c63a387661ee0f3d0",
			DependsOn: []string{
				"busybox@1.31.1-r9",
				"musl@1.1.24-r2",
			},
			Arch: "x86_64",
		},
		{
			ID:         "alpine-keys@2.1-r2",
			Name:       "alpine-keys",
			Version:    "2.1-r2",
			SrcName:    "alpine-keys",
			SrcVersion: "2.1-r2",
			Licenses:   []string{"MIT"},
			Arch:       "x86_64",
			Digest:     "sha1:64929f85b7f8b4adbb664d905410312936b79d9b",
		},
		{
			ID:         "apk-tools@2.10.4-r3",
			Name:       "apk-tools",
			Version:    "2.10.4-r3",
			SrcName:    "apk-tools",
			SrcVersion: "2.10.4-r3",
			Licenses:   []string{"GPL-2.0"},
			Digest:     "sha1:b15ad0c90e4493dfdc948d6b90a8e020da8936ef",
			DependsOn: []string{
				"libcrypto1.1@1.1.1d-r3",
				"libssl1.1@1.1.1d-r3",
				"musl@1.1.24-r2",
				"zlib@1.2.11-r3",
			},
			Arch: "x86_64",
		},
		{
			ID:         "busybox@1.31.1-r9",
			Name:       "busybox",
			Version:    "1.31.1-r9",
			SrcName:    "busybox",
			SrcVersion: "1.31.1-r9",
			Licenses:   []string{"GPL-2.0"},
			Digest:     "sha1:a457703d71654811ea28d8d27a5cfc49ece27b34",
			DependsOn: []string{
				"musl@1.1.24-r2",
			},
			Arch: "x86_64",
		},
		{
			ID:         "ca-certificates-cacert@20191127-r1",
			Name:       "ca-certificates-cacert",
			Version:    "20191127-r1",
			SrcName:    "ca-certificates",
			SrcVersion: "20191127-r1",
			Licenses: []string{
				"MPL-2.0",
				"GPL-2.0",
			},
			Arch:   "x86_64",
			Digest: "sha1:3aeb8a90d7179d2a187782e980a964494e08c5fb",
		},
		{
			ID:         "libc-utils@0.7.2-r0",
			Name:       "libc-utils",
			Version:    "0.7.2-r0",
			SrcName:    "libc-dev",
			SrcVersion: "0.7.2-r0",
			Licenses:   []string{"BSD-3-Clause"},
			Digest:     "sha1:a7bf32bd32c6d3de2d1c4d7e753a0919b998cd01",
			DependsOn: []string{
				"musl-utils@1.1.24-r2",
			},
			Arch: "x86_64",
		},
		{
			ID:         "libcrypto1.1@1.1.1d-r3",
			Name:       "libcrypto1.1",
			Version:    "1.1.1d-r3",
			SrcName:    "openssl",
			SrcVersion: "1.1.1d-r3",
			Licenses:   []string{"OpenSSL"},
			Digest:     "sha1:dd8fb9a3cce7b2bcf954271da62fb85dac2b106a",
			DependsOn: []string{
				"musl@1.1.24-r2",
			},
			Arch: "x86_64",
		},
		{
			ID:         "libssl1.1@1.1.1d-r3",
			Name:       "libssl1.1",
			Version:    "1.1.1d-r3",
			SrcName:    "openssl",
			SrcVersion: "1.1.1d-r3",
			Licenses:   []string{"OpenSSL"},
			Digest:     "sha1:938d46e41b3e56b339a3aeb2d02fad3d75728f35",
			DependsOn: []string{
				"libcrypto1.1@1.1.1d-r3",
				"musl@1.1.24-r2",
			},
			Arch: "x86_64",
		},
		{
			ID:         "libtls-standalone@2.9.1-r0",
			Name:       "libtls-standalone",
			Version:    "2.9.1-r0",
			SrcName:    "libtls-standalone",
			SrcVersion: "2.9.1-r0",
			Licenses:   []string{"ISC"},
			Digest:     "sha1:b2e5627a56378ea6eeb962a8f33722df9393c1c5",
			DependsOn: []string{
				"ca-certificates-cacert@20191127-r1",
				"libcrypto1.1@1.1.1d-r3",
				"libssl1.1@1.1.1d-r3",
				"musl@1.1.24-r2",
			},
			Arch: "x86_64",
		},
		{
			ID:         "musl@1.1.24-r2",
			Name:       "musl",
			Version:    "1.1.24-r2",
			SrcName:    "musl",
			SrcVersion: "1.1.24-r2",
			Licenses:   []string{"MIT"},
			Arch:       "x86_64",
			Digest:     "sha1:cb2316a189ebee5282c4a9bd98794cc2477a74c6",
		},
		{
			ID:         "musl-utils@1.1.24-r2",
			Name:       "musl-utils",
			Version:    "1.1.24-r2",
			SrcName:    "musl",
			SrcVersion: "1.1.24-r2",
			Licenses: []string{
				"MIT",
				"BSD-3-Clause",
				"GPL-2.0",
			},
			Digest: "sha1:6d3b45e79dbab444ca7cbfa59e2833203be6fb6a",
			DependsOn: []string{
				"musl@1.1.24-r2",
				"scanelf@1.2.4-r0",
			},
			Arch: "x86_64",
		},
		{
			ID:         "scanelf@1.2.4-r0",
			Name:       "scanelf",
			Version:    "1.2.4-r0",
			SrcName:    "pax-utils",
			SrcVersion: "1.2.4-r0",
			Licenses:   []string{"GPL-2.0"},
			Digest:     "sha1:d6147beb32bff803b5d9f83a3bec7ab319087185",
			DependsOn: []string{
				"musl@1.1.24-r2",
			},
			Arch: "x86_64",
		},
		{
			ID:         "ssl_client@1.31.1-r9",
			Name:       "ssl_client",
			Version:    "1.31.1-r9",
			SrcName:    "busybox",
			SrcVersion: "1.31.1-r9",
			Licenses:   []string{"GPL-2.0"},
			Digest:     "sha1:3b685152af320120ae8941c740d3376b54e43c10",
			DependsOn: []string{
				"libtls-standalone@2.9.1-r0",
				"musl@1.1.24-r2",
			},
			Arch: "x86_64",
		},
		{
			ID:         "zlib@1.2.11-r3",
			Name:       "zlib",
			Version:    "1.2.11-r3",
			SrcName:    "zlib",
			SrcVersion: "1.2.11-r3",
			Licenses:   []string{"Zlib"},
			Digest:     "sha1:acca078ee8baa93e005f57b2fae359c1efd443cd",
			DependsOn: []string{
				"musl@1.1.24-r2",
			},
			Arch: "x86_64",
		},
	}

	tests := []struct {
		name                    string
		imagePath               string
		artifactOpt             artifact.Option
		missingBlobsExpectation cache.ArtifactCacheMissingBlobsExpectation
		putBlobExpectations     []cache.ArtifactCachePutBlobExpectation
		putArtifactExpectations []cache.ArtifactCachePutArtifactExpectation
		want                    types.ArtifactReference
		wantErr                 string
	}{
		{
			name:      "happy path",
			imagePath: "../../test/testdata/alpine-311.tar.gz",
			artifactOpt: artifact.Option{
				LicenseScannerOption: analyzer.LicenseScannerOption{Full: true},
			},
			missingBlobsExpectation: cache.ArtifactCacheMissingBlobsExpectation{
				Args: cache.ArtifactCacheMissingBlobsArgs{
					ArtifactID: "sha256:c232b7d8ac8aa08aa767313d0b53084c4380d1c01a213a5971bdb039e6538313",
					BlobIDs:    []string{"sha256:0366f81c3cbeac047536f9ca133b5632544c8342544922c3ed8a3e51c0250897"},
				},
				Returns: cache.ArtifactCacheMissingBlobsReturns{
					MissingArtifact: true,
					MissingBlobIDs:  []string{"sha256:0366f81c3cbeac047536f9ca133b5632544c8342544922c3ed8a3e51c0250897"},
				},
			},
			putBlobExpectations: []cache.ArtifactCachePutBlobExpectation{
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:0366f81c3cbeac047536f9ca133b5632544c8342544922c3ed8a3e51c0250897",
						BlobInfo: types.BlobInfo{
							SchemaVersion: types.BlobJSONSchemaVersion,
							Digest:        "",
							DiffID:        "sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203",
							CreatedBy:     "ADD file:0c4555f363c2672e350001f1293e689875a3760afe7b3f9146886afe67121cba in / ",
							OS: types.OS{
								Family: "alpine",
								Name:   "3.11.5",
							},
							Repository: &types.Repository{
								Family:  "alpine",
								Release: "3.11",
							},
							PackageInfos: []types.PackageInfo{
								{
									FilePath: "lib/apk/db/installed",
									Packages: alpinePkgs,
								},
							},
							Licenses: []types.LicenseFile{
								{
									Type:     "header",
									FilePath: "etc/ssl/misc/CA.pl",
									Findings: []types.LicenseFinding{
										{
											Name:       "OpenSSL",
											Confidence: 1,
											Link:       "https://spdx.org/licenses/OpenSSL.html",
										},
									},
								},
								{
									Type:     "header",
									FilePath: "etc/ssl/misc/tsget.pl",
									Findings: []types.LicenseFinding{
										{
											Name:       "OpenSSL",
											Confidence: 1,
											Link:       "https://spdx.org/licenses/OpenSSL.html",
										},
									},
								},
							},
						},
					},
					Returns: cache.ArtifactCachePutBlobReturns{},
				},
			},
			putArtifactExpectations: []cache.ArtifactCachePutArtifactExpectation{
				{
					Args: cache.ArtifactCachePutArtifactArgs{
						ArtifactID: "sha256:c232b7d8ac8aa08aa767313d0b53084c4380d1c01a213a5971bdb039e6538313",
						ArtifactInfo: types.ArtifactInfo{
							SchemaVersion: types.ArtifactJSONSchemaVersion,
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
				ID:      "sha256:c232b7d8ac8aa08aa767313d0b53084c4380d1c01a213a5971bdb039e6538313",
				BlobIDs: []string{"sha256:0366f81c3cbeac047536f9ca133b5632544c8342544922c3ed8a3e51c0250897"},
				ImageMetadata: types.ImageMetadata{
					ID: "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
					DiffIDs: []string{
						"sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203",
					},
					ConfigFile: v1.ConfigFile{
						Architecture:  "amd64",
						Author:        "",
						Container:     "fb71ddde5f6411a82eb056a9190f0cc1c80d7f77a8509ee90a2054428edb0024",
						Created:       v1.Time{Time: time.Date(2020, 3, 23, 21, 19, 34, 196162891, time.UTC)},
						DockerVersion: "18.09.7",
						History: []v1.History{
							{
								Author:     "",
								Created:    v1.Time{Time: time.Date(2020, 3, 23, 21, 19, 34, 27725872, time.UTC)},
								CreatedBy:  "/bin/sh -c #(nop) ADD file:0c4555f363c2672e350001f1293e689875a3760afe7b3f9146886afe67121cba in / ",
								Comment:    "",
								EmptyLayer: false,
							},
							{
								Author:     "",
								Created:    v1.Time{Time: time.Date(2020, 3, 23, 21, 19, 34, 196162891, time.UTC)},
								CreatedBy:  "/bin/sh -c #(nop)  CMD [\"/bin/sh\"]",
								Comment:    "",
								EmptyLayer: true,
							},
						},
						OS: "linux",
						RootFS: v1.RootFS{
							Type: "layers",
							DiffIDs: []v1.Hash{
								{
									Algorithm: "sha256",
									Hex:       "beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203",
								},
							},
						},
						Config: v1.Config{
							Cmd:         []string{"/bin/sh"},
							Env:         []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
							Hostname:    "",
							Image:       "sha256:74df73bb19fbfc7fb5ab9a8234b3d98ee2fb92df5b824496679802685205ab8c",
							ArgsEscaped: true,
						},
					},
				},
			},
		},
		{
			name:      "happy path: include lock files",
			imagePath: "../../test/testdata/vuln-image.tar.gz",
			artifactOpt: artifact.Option{
				LicenseScannerOption: analyzer.LicenseScannerOption{Full: true},
			},
			missingBlobsExpectation: cache.ArtifactCacheMissingBlobsExpectation{
				Args: cache.ArtifactCacheMissingBlobsArgs{
					ArtifactID: "sha256:33f9415ed2cd5a9cef5d5144333619745b9ec0f851f0684dd45fa79c6b26a650",
					BlobIDs: []string{
						"sha256:db2b5b2f26f320b80ee549495888f111151fdb44fecb2c432dfd928e96978e74",
						"sha256:718d6a3d0a24966f2d9f64e0c86695d1bb896fe81df634b85300d34142c80174",
						"sha256:9f6bc14198fa983fd47079bcd82df1391bee8e529a8a131a0305874eb0a51ca0",
						"sha256:44264715b7132cd14cd956bf385d5f875603461f5adeafde7fdecabe2e266291",
					},
				},
				Returns: cache.ArtifactCacheMissingBlobsReturns{
					MissingBlobIDs: []string{
						"sha256:db2b5b2f26f320b80ee549495888f111151fdb44fecb2c432dfd928e96978e74",
						"sha256:718d6a3d0a24966f2d9f64e0c86695d1bb896fe81df634b85300d34142c80174",
						"sha256:9f6bc14198fa983fd47079bcd82df1391bee8e529a8a131a0305874eb0a51ca0",
						"sha256:44264715b7132cd14cd956bf385d5f875603461f5adeafde7fdecabe2e266291",
					},
				},
			},
			putBlobExpectations: []cache.ArtifactCachePutBlobExpectation{
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:db2b5b2f26f320b80ee549495888f111151fdb44fecb2c432dfd928e96978e74",
						BlobInfo: types.BlobInfo{
							SchemaVersion: types.BlobJSONSchemaVersion,
							Digest:        "",
							DiffID:        "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
							CreatedBy:     "bazel build ...",
							OS: types.OS{
								Family: "debian",
								Name:   "9.9",
							},
							PackageInfos: []types.PackageInfo{
								{
									FilePath: "var/lib/dpkg/status.d/base",
									Packages: types.Packages{
										{
											ID:         "base-files@9.9+deb9u9",
											Name:       "base-files",
											Version:    "9.9+deb9u9",
											SrcName:    "base-files",
											SrcVersion: "9.9+deb9u9",
											Maintainer: "Santiago Vila <sanvila@debian.org>",
											Arch:       "amd64",
										},
									},
								},
								{
									FilePath: "var/lib/dpkg/status.d/netbase",
									Packages: types.Packages{
										{
											ID:         "netbase@5.4",
											Name:       "netbase",
											Version:    "5.4",
											SrcName:    "netbase",
											SrcVersion: "5.4",
											Maintainer: "Marco d'Itri <md@linux.it>",
											Arch:       "all",
										},
									},
								},
								{
									FilePath: "var/lib/dpkg/status.d/tzdata",
									Packages: types.Packages{
										{
											ID:         "tzdata@2019a-0+deb9u1",
											Name:       "tzdata",
											Version:    "2019a",
											SrcName:    "tzdata",
											Release:    "0+deb9u1",
											SrcVersion: "2019a",
											SrcRelease: "0+deb9u1",
											Maintainer: "GNU Libc Maintainers <debian-glibc@lists.debian.org>",
											Arch:       "all",
										},
									},
								},
							},
							Licenses: []types.LicenseFile{
								{
									Type:     types.LicenseTypeDpkg,
									FilePath: "usr/share/doc/base-files/copyright",
									Findings: []types.LicenseFinding{
										{Name: "GPL-3.0"},
									},
									PkgName: "base-files",
								},
								{
									Type:     types.LicenseTypeDpkg,
									FilePath: "usr/share/doc/ca-certificates/copyright",
									Findings: []types.LicenseFinding{
										{Name: "GPL-2.0"},
										{Name: "MPL-2.0"},
									},
									PkgName: "ca-certificates",
								},
								{
									Type:     types.LicenseTypeDpkg,
									FilePath: "usr/share/doc/netbase/copyright",
									Findings: []types.LicenseFinding{
										{Name: "GPL-2.0"},
									},
									PkgName: "netbase",
								},
							},
						},
					},
				},
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:718d6a3d0a24966f2d9f64e0c86695d1bb896fe81df634b85300d34142c80174",
						BlobInfo: types.BlobInfo{
							SchemaVersion: types.BlobJSONSchemaVersion,
							Digest:        "",
							DiffID:        "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
							CreatedBy:     "bazel build ...",
							PackageInfos: []types.PackageInfo{
								{
									FilePath: "var/lib/dpkg/status.d/libc6",
									Packages: types.Packages{
										{
											ID:         "libc6@2.24-11+deb9u4",
											Name:       "libc6",
											Version:    "2.24",
											Release:    "11+deb9u4",
											SrcName:    "glibc",
											SrcVersion: "2.24",
											SrcRelease: "11+deb9u4",
											Maintainer: "GNU Libc Maintainers <debian-glibc@lists.debian.org>",
											Arch:       "amd64",
										},
									},
								},
								{
									FilePath: "var/lib/dpkg/status.d/libssl1",
									Packages: types.Packages{
										{
											ID:         "libssl1.1@1.1.0k-1~deb9u1",
											Name:       "libssl1.1",
											Version:    "1.1.0k",
											SrcName:    "openssl",
											Release:    "1~deb9u1",
											SrcVersion: "1.1.0k",
											SrcRelease: "1~deb9u1",
											Maintainer: "Debian OpenSSL Team <pkg-openssl-devel@lists.alioth.debian.org>",
											Arch:       "amd64",
										},
									},
								},
								{
									FilePath: "var/lib/dpkg/status.d/openssl",
									Packages: types.Packages{
										{
											ID:         "openssl@1.1.0k-1~deb9u1",
											Name:       "openssl",
											Version:    "1.1.0k",
											SrcName:    "openssl",
											Release:    "1~deb9u1",
											SrcVersion: "1.1.0k",
											SrcRelease: "1~deb9u1",
											Maintainer: "Debian OpenSSL Team <pkg-openssl-devel@lists.alioth.debian.org>",
											Arch:       "amd64",
										},
									},
								},
							},
							Licenses: []types.LicenseFile{
								{
									Type:     types.LicenseTypeDpkg,
									FilePath: "usr/share/doc/libc6/copyright",
									Findings: []types.LicenseFinding{
										{Name: "LGPL-2.1"},
										{Name: "GPL-2.0"},
									},
									PkgName: "libc6",
								},
								{
									Type:     types.LicenseTypeDpkg,
									FilePath: "usr/share/doc/libssl1.1/copyright",
									Findings: []types.LicenseFinding{
										{
											Name:       "OpenSSL",
											Confidence: 0.9960474308300395,
											Link:       "https://spdx.org/licenses/OpenSSL.html",
										},
									},
									PkgName: "libssl1.1",
								},
								{
									Type:     types.LicenseTypeDpkg,
									FilePath: "usr/share/doc/openssl/copyright",
									Findings: []types.LicenseFinding{
										{
											Name:       "OpenSSL",
											Confidence: 0.9960474308300395,
											Link:       "https://spdx.org/licenses/OpenSSL.html",
										},
									},
									PkgName: "openssl",
								},
							},
						},
					},
				},
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:9f6bc14198fa983fd47079bcd82df1391bee8e529a8a131a0305874eb0a51ca0",
						BlobInfo: types.BlobInfo{
							SchemaVersion: types.BlobJSONSchemaVersion,
							Digest:        "",
							DiffID:        "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
							CreatedBy:     "COPY file:842584685f26edb24dc305d76894f51cfda2bad0c24a05e727f9d4905d184a70 in /php-app/composer.lock ",
							Applications: []types.Application{
								{
									Type:     "composer",
									FilePath: "php-app/composer.lock",
									Libraries: types.Packages{
										{
											ID:       "guzzlehttp/guzzle@6.2.0",
											Name:     "guzzlehttp/guzzle",
											Version:  "6.2.0",
											Licenses: []string{"MIT"},
											DependsOn: []string{
												"guzzlehttp/promises@v1.3.1",
												"guzzlehttp/psr7@1.5.2",
											},
											Locations: []types.Location{
												{
													StartLine: 9,
													EndLine:   73,
												},
											},
										},
										{
											ID:       "guzzlehttp/promises@v1.3.1",
											Name:     "guzzlehttp/promises",
											Version:  "v1.3.1",
											Licenses: []string{"MIT"},
											Locations: []types.Location{
												{
													StartLine: 74,
													EndLine:   124,
												},
											},
										},
										{
											ID:       "guzzlehttp/psr7@1.5.2",
											Name:     "guzzlehttp/psr7",
											Version:  "1.5.2",
											Licenses: []string{"MIT"},
											DependsOn: []string{
												"psr/http-message@1.0.1",
												"ralouphie/getallheaders@2.0.5",
											},
											Locations: []types.Location{
												{
													StartLine: 125,
													EndLine:   191,
												},
											},
										},
										{
											ID:       "laravel/installer@v2.0.1",
											Name:     "laravel/installer",
											Version:  "v2.0.1",
											Licenses: []string{"MIT"},
											DependsOn: []string{
												"guzzlehttp/guzzle@6.2.0",
												"symfony/console@v4.2.7",
												"symfony/filesystem@v4.2.7",
												"symfony/process@v4.2.7",
											},
											Locations: []types.Location{
												{
													StartLine: 192,
													EndLine:   237,
												},
											},
										},
										{
											ID:        "pear/log@1.13.1",
											Name:      "pear/log",
											Version:   "1.13.1",
											Licenses:  []string{"MIT"},
											DependsOn: []string{"pear/pear_exception@v1.0.0"},
											Locations: []types.Location{
												{
													StartLine: 238,
													EndLine:   290,
												},
											},
										},
										{
											ID:       "pear/pear_exception@v1.0.0",
											Name:     "pear/pear_exception",
											Version:  "v1.0.0",
											Licenses: []string{"BSD-2-Clause"},
											Locations: []types.Location{
												{
													StartLine: 291,
													EndLine:   345,
												},
											},
										},
										{
											ID:       "psr/http-message@1.0.1",
											Name:     "psr/http-message",
											Version:  "1.0.1",
											Licenses: []string{"MIT"},
											Locations: []types.Location{
												{
													StartLine: 346,
													EndLine:   395,
												},
											},
										},
										{
											ID:       "ralouphie/getallheaders@2.0.5",
											Name:     "ralouphie/getallheaders",
											Version:  "2.0.5",
											Licenses: []string{"MIT"},
											Locations: []types.Location{
												{
													StartLine: 396,
													EndLine:   435,
												},
											},
										},
										{
											ID:       "symfony/console@v4.2.7",
											Name:     "symfony/console",
											Version:  "v4.2.7",
											Licenses: []string{"MIT"},
											DependsOn: []string{
												"symfony/contracts@v1.0.2",
												"symfony/polyfill-mbstring@v1.11.0",
											},
											Locations: []types.Location{
												{
													StartLine: 436,
													EndLine:   507,
												},
											},
										},
										{
											ID:       "symfony/contracts@v1.0.2",
											Name:     "symfony/contracts",
											Version:  "v1.0.2",
											Licenses: []string{"MIT"},
											Locations: []types.Location{
												{
													StartLine: 508,
													EndLine:   575,
												},
											},
										},
										{
											ID:        "symfony/filesystem@v4.2.7",
											Name:      "symfony/filesystem",
											Version:   "v4.2.7",
											Licenses:  []string{"MIT"},
											DependsOn: []string{"symfony/polyfill-ctype@v1.11.0"},
											Locations: []types.Location{
												{
													StartLine: 576,
													EndLine:   625,
												},
											},
										},
										{
											ID:       "symfony/polyfill-ctype@v1.11.0",
											Name:     "symfony/polyfill-ctype",
											Version:  "v1.11.0",
											Licenses: []string{"MIT"},
											Locations: []types.Location{
												{
													StartLine: 626,
													EndLine:   683,
												},
											},
										},
										{
											ID:       "symfony/polyfill-mbstring@v1.11.0",
											Name:     "symfony/polyfill-mbstring",
											Version:  "v1.11.0",
											Licenses: []string{"MIT"},
											Locations: []types.Location{
												{
													StartLine: 684,
													EndLine:   742,
												},
											},
										},
										{
											ID:       "symfony/process@v4.2.7",
											Name:     "symfony/process",
											Version:  "v4.2.7",
											Licenses: []string{"MIT"},
											Locations: []types.Location{
												{
													StartLine: 743,
													EndLine:   791,
												},
											},
										},
									},
								},
							},
							OpaqueDirs: []string{"php-app/"},
						},
					},
				},
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:44264715b7132cd14cd956bf385d5f875603461f5adeafde7fdecabe2e266291",
						BlobInfo: types.BlobInfo{
							SchemaVersion: types.BlobJSONSchemaVersion,
							Digest:        "",
							DiffID:        "sha256:a4595c43a874856bf95f3bfc4fbf78bbaa04c92c726276d4f64193a47ced0566",
							CreatedBy:     "COPY file:c6d0373d380252b91829a5bb3c81d5b1afa574c91cef7752d18170a231c31f6d in /ruby-app/Gemfile.lock ",
							Applications: []types.Application{
								{
									Type:     "bundler",
									FilePath: "ruby-app/Gemfile.lock",
									Libraries: types.Packages{
										{
											ID:       "actioncable@5.2.3",
											Name:     "actioncable",
											Version:  "5.2.3",
											Indirect: true,
											DependsOn: []string{
												"actionpack@5.2.3",
												"nio4r@2.3.1",
												"websocket-driver@0.7.0",
											},
											Locations: []types.Location{
												{
													StartLine: 4,
													EndLine:   4,
												},
											},
										},
										{
											ID:       "actionmailer@5.2.3",
											Name:     "actionmailer",
											Version:  "5.2.3",
											Indirect: true,
											DependsOn: []string{
												"actionpack@5.2.3",
												"actionview@5.2.3",
												"activejob@5.2.3",
												"mail@2.7.1",
												"rails-dom-testing@2.0.3",
											},
											Locations: []types.Location{
												{
													StartLine: 8,
													EndLine:   8,
												},
											},
										},
										{
											ID:       "actionpack@5.2.3",
											Name:     "actionpack",
											Version:  "5.2.3",
											Indirect: true,
											DependsOn: []string{
												"actionview@5.2.3",
												"activesupport@5.2.3",
												"rack@2.0.7",
												"rack-test@1.1.0",
												"rails-dom-testing@2.0.3",
												"rails-html-sanitizer@1.0.3",
											},
											Locations: []types.Location{
												{
													StartLine: 14,
													EndLine:   14,
												},
											},
										},
										{
											ID:       "actionview@5.2.3",
											Name:     "actionview",
											Version:  "5.2.3",
											Indirect: true,
											DependsOn: []string{
												"activesupport@5.2.3",
												"builder@3.2.3",
												"erubi@1.8.0",
												"rails-dom-testing@2.0.3",
												"rails-html-sanitizer@1.0.3",
											},
											Locations: []types.Location{
												{
													StartLine: 21,
													EndLine:   21,
												},
											},
										},
										{
											ID:       "activejob@5.2.3",
											Name:     "activejob",
											Version:  "5.2.3",
											Indirect: true,
											DependsOn: []string{
												"activesupport@5.2.3",
												"globalid@0.4.2",
											},
											Locations: []types.Location{
												{
													StartLine: 27,
													EndLine:   27,
												},
											},
										},
										{
											ID:        "activemodel@5.2.3",
											Name:      "activemodel",
											Version:   "5.2.3",
											Indirect:  true,
											DependsOn: []string{"activesupport@5.2.3"},
											Locations: []types.Location{
												{
													StartLine: 30,
													EndLine:   30,
												},
											},
										},
										{
											ID:       "activerecord@5.2.3",
											Name:     "activerecord",
											Version:  "5.2.3",
											Indirect: true,
											DependsOn: []string{
												"activemodel@5.2.3",
												"activesupport@5.2.3",
												"arel@9.0.0",
											},
											Locations: []types.Location{
												{
													StartLine: 32,
													EndLine:   32,
												},
											},
										},
										{
											ID:       "activestorage@5.2.3",
											Name:     "activestorage",
											Version:  "5.2.3",
											Indirect: true,
											DependsOn: []string{
												"actionpack@5.2.3",
												"activerecord@5.2.3",
												"marcel@0.3.3",
											},
											Locations: []types.Location{
												{
													StartLine: 36,
													EndLine:   36,
												},
											},
										},
										{
											ID:       "activesupport@5.2.3",
											Name:     "activesupport",
											Version:  "5.2.3",
											Indirect: true,
											DependsOn: []string{
												"concurrent-ruby@1.1.5",
												"i18n@1.6.0",
												"minitest@5.11.3",
												"tzinfo@1.2.5",
											},
											Locations: []types.Location{
												{
													StartLine: 40,
													EndLine:   40,
												},
											},
										},
										{
											ID:        "arel@9.0.0",
											Name:      "arel",
											Version:   "9.0.0",
											Indirect:  true,
											DependsOn: []string(nil),
											Locations: []types.Location{
												{
													StartLine: 45,
													EndLine:   45,
												},
											},
										},
										{
											ID:        "ast@2.4.0",
											Name:      "ast",
											Version:   "2.4.0",
											Indirect:  true,
											DependsOn: []string(nil),
											Locations: []types.Location{
												{
													StartLine: 46,
													EndLine:   46,
												},
											},
										},
										{
											ID:        "builder@3.2.3",
											Name:      "builder",
											Version:   "3.2.3",
											Indirect:  true,
											DependsOn: []string(nil),
											Locations: []types.Location{
												{
													StartLine: 47,
													EndLine:   47,
												},
											},
										},
										{
											ID:        "coderay@1.1.2",
											Name:      "coderay",
											Version:   "1.1.2",
											Indirect:  true,
											DependsOn: []string(nil),
											Locations: []types.Location{
												{
													StartLine: 48,
													EndLine:   48,
												},
											},
										},
										{
											ID:        "concurrent-ruby@1.1.5",
											Name:      "concurrent-ruby",
											Version:   "1.1.5",
											Indirect:  true,
											DependsOn: []string(nil),
											Locations: []types.Location{
												{
													StartLine: 49,
													EndLine:   49,
												},
											},
										},
										{
											ID:        "crass@1.0.4",
											Name:      "crass",
											Version:   "1.0.4",
											Indirect:  true,
											DependsOn: []string(nil),
											Locations: []types.Location{
												{
													StartLine: 50,
													EndLine:   50,
												},
											},
										},
										{
											ID:        "dotenv@2.7.2",
											Name:      "dotenv",
											Version:   "2.7.2",
											Indirect:  false,
											DependsOn: []string(nil),
											Locations: []types.Location{
												{
													StartLine: 51,
													EndLine:   51,
												},
											},
										},
										{
											ID:        "erubi@1.8.0",
											Name:      "erubi",
											Version:   "1.8.0",
											Indirect:  true,
											DependsOn: []string(nil),
											Locations: []types.Location{
												{
													StartLine: 52,
													EndLine:   52,
												},
											},
										},
										{
											ID:        "faker@1.9.3",
											Name:      "faker",
											Version:   "1.9.3",
											Indirect:  false,
											DependsOn: []string{"i18n@1.6.0"},
											Locations: []types.Location{
												{
													StartLine: 53,
													EndLine:   53,
												},
											},
										},
										{
											ID:        "globalid@0.4.2",
											Name:      "globalid",
											Version:   "0.4.2",
											Indirect:  true,
											DependsOn: []string{"activesupport@5.2.3"},
											Locations: []types.Location{
												{
													StartLine: 55,
													EndLine:   55,
												},
											},
										},
										{
											ID:        "i18n@1.6.0",
											Name:      "i18n",
											Version:   "1.6.0",
											Indirect:  true,
											DependsOn: []string{"concurrent-ruby@1.1.5"},
											Locations: []types.Location{
												{
													StartLine: 57,
													EndLine:   57,
												},
											},
										},
										{
											ID:        "jaro_winkler@1.5.2",
											Name:      "jaro_winkler",
											Version:   "1.5.2",
											Indirect:  true,
											DependsOn: []string(nil),
											Locations: []types.Location{
												{
													StartLine: 59,
													EndLine:   59,
												},
											},
										},
										{
											ID:        "json@2.2.0",
											Name:      "json",
											Version:   "2.2.0",
											Indirect:  false,
											DependsOn: []string(nil),
											Locations: []types.Location{
												{
													StartLine: 60,
													EndLine:   60,
												},
											},
										},
										{
											ID:       "loofah@2.2.3",
											Name:     "loofah",
											Version:  "2.2.3",
											Indirect: true,
											DependsOn: []string{
												"crass@1.0.4",
												"nokogiri@1.10.3",
											},
											Locations: []types.Location{
												{
													StartLine: 61,
													EndLine:   61,
												},
											},
										},
										{
											ID:        "mail@2.7.1",
											Name:      "mail",
											Version:   "2.7.1",
											Indirect:  true,
											DependsOn: []string{"mini_mime@1.0.1"},
											Locations: []types.Location{
												{
													StartLine: 64,
													EndLine:   64,
												},
											},
										},
										{
											ID:        "marcel@0.3.3",
											Name:      "marcel",
											Version:   "0.3.3",
											Indirect:  true,
											DependsOn: []string{"mimemagic@0.3.3"},
											Locations: []types.Location{
												{
													StartLine: 66,
													EndLine:   66,
												},
											},
										},
										{
											ID:        "method_source@0.9.2",
											Name:      "method_source",
											Version:   "0.9.2",
											Indirect:  true,
											DependsOn: []string(nil),
											Locations: []types.Location{
												{
													StartLine: 68,
													EndLine:   68,
												},
											},
										},
										{
											ID:        "mimemagic@0.3.3",
											Name:      "mimemagic",
											Version:   "0.3.3",
											Indirect:  true,
											DependsOn: []string(nil),
											Locations: []types.Location{
												{
													StartLine: 69,
													EndLine:   69,
												},
											},
										},
										{
											ID:        "mini_mime@1.0.1",
											Name:      "mini_mime",
											Version:   "1.0.1",
											Indirect:  true,
											DependsOn: []string(nil),
											Locations: []types.Location{
												{
													StartLine: 70,
													EndLine:   70,
												},
											},
										},
										{
											ID:        "mini_portile2@2.4.0",
											Name:      "mini_portile2",
											Version:   "2.4.0",
											Indirect:  true,
											DependsOn: []string(nil),
											Locations: []types.Location{
												{
													StartLine: 71,
													EndLine:   71,
												},
											},
										},
										{
											ID:        "minitest@5.11.3",
											Name:      "minitest",
											Version:   "5.11.3",
											Indirect:  true,
											DependsOn: []string(nil),
											Locations: []types.Location{
												{
													StartLine: 72,
													EndLine:   72,
												},
											},
										},
										{
											ID:        "nio4r@2.3.1",
											Name:      "nio4r",
											Version:   "2.3.1",
											Indirect:  true,
											DependsOn: []string(nil),
											Locations: []types.Location{
												{
													StartLine: 73,
													EndLine:   73,
												},
											},
										},
										{
											ID:        "nokogiri@1.10.3",
											Name:      "nokogiri",
											Version:   "1.10.3",
											Indirect:  true,
											DependsOn: []string{"mini_portile2@2.4.0"},
											Locations: []types.Location{
												{
													StartLine: 74,
													EndLine:   74,
												},
											},
										},
										{
											ID:        "parallel@1.17.0",
											Name:      "parallel",
											Version:   "1.17.0",
											Indirect:  true,
											DependsOn: []string(nil),
											Locations: []types.Location{
												{
													StartLine: 76,
													EndLine:   76,
												},
											},
										},
										{
											ID:        "parser@2.6.3.0",
											Name:      "parser",
											Version:   "2.6.3.0",
											Indirect:  true,
											DependsOn: []string{"ast@2.4.0"},
											Locations: []types.Location{
												{
													StartLine: 77,
													EndLine:   77,
												},
											},
										},
										{
											ID:       "pry@0.12.2",
											Name:     "pry",
											Version:  "0.12.2",
											Indirect: false,
											DependsOn: []string{
												"coderay@1.1.2",
												"method_source@0.9.2",
											},
											Locations: []types.Location{
												{
													StartLine: 79,
													EndLine:   79,
												},
											},
										},
										{
											ID:        "psych@3.1.0",
											Name:      "psych",
											Version:   "3.1.0",
											Indirect:  true,
											DependsOn: []string(nil),
											Locations: []types.Location{
												{
													StartLine: 82,
													EndLine:   82,
												},
											},
										},
										{
											ID:        "rack@2.0.7",
											Name:      "rack",
											Version:   "2.0.7",
											Indirect:  true,
											DependsOn: []string(nil),
											Locations: []types.Location{
												{
													StartLine: 83,
													EndLine:   83,
												},
											},
										},
										{
											ID:        "rack-test@1.1.0",
											Name:      "rack-test",
											Version:   "1.1.0",
											Indirect:  true,
											DependsOn: []string{"rack@2.0.7"},
											Locations: []types.Location{
												{
													StartLine: 84,
													EndLine:   84,
												},
											},
										},
										{
											ID:       "rails@5.2.0",
											Name:     "rails",
											Version:  "5.2.0",
											Indirect: false,
											DependsOn: []string{
												"actioncable@5.2.3",
												"actionmailer@5.2.3",
												"actionpack@5.2.3",
												"actionview@5.2.3",
												"activejob@5.2.3",
												"activemodel@5.2.3",
												"activerecord@5.2.3",
												"activestorage@5.2.3",
												"activesupport@5.2.3",
												"railties@5.2.3",
												"sprockets-rails@3.2.1",
											},
											Locations: []types.Location{
												{
													StartLine: 86,
													EndLine:   86,
												},
											},
										},
										{
											ID:       "rails-dom-testing@2.0.3",
											Name:     "rails-dom-testing",
											Version:  "2.0.3",
											Indirect: true,
											DependsOn: []string{
												"activesupport@5.2.3",
												"nokogiri@1.10.3",
											},
											Locations: []types.Location{
												{
													StartLine: 99,
													EndLine:   99,
												},
											},
										},
										{
											ID:        "rails-html-sanitizer@1.0.3",
											Name:      "rails-html-sanitizer",
											Version:   "1.0.3",
											Indirect:  true,
											DependsOn: []string{"loofah@2.2.3"},
											Locations: []types.Location{
												{
													StartLine: 102,
													EndLine:   102,
												},
											},
										},
										{
											ID:       "railties@5.2.3",
											Name:     "railties",
											Version:  "5.2.3",
											Indirect: true,
											DependsOn: []string{
												"actionpack@5.2.3",
												"activesupport@5.2.3",
												"method_source@0.9.2",
												"rake@12.3.2",
												"thor@0.20.3",
											},
											Locations: []types.Location{
												{
													StartLine: 104,
													EndLine:   104,
												},
											},
										},
										{
											ID:        "rainbow@3.0.0",
											Name:      "rainbow",
											Version:   "3.0.0",
											Indirect:  true,
											DependsOn: []string(nil),
											Locations: []types.Location{
												{
													StartLine: 110,
													EndLine:   110,
												},
											},
										},
										{
											ID:        "rake@12.3.2",
											Name:      "rake",
											Version:   "12.3.2",
											Indirect:  true,
											DependsOn: []string(nil),
											Locations: []types.Location{
												{
													StartLine: 111,
													EndLine:   111,
												},
											},
										},
										{
											ID:       "rubocop@0.67.2",
											Name:     "rubocop",
											Version:  "0.67.2",
											Indirect: false,
											DependsOn: []string{
												"jaro_winkler@1.5.2",
												"parallel@1.17.0",
												"parser@2.6.3.0",
												"psych@3.1.0",
												"rainbow@3.0.0",
												"ruby-progressbar@1.10.0",
												"unicode-display_width@1.5.0",
											},
											Locations: []types.Location{
												{
													StartLine: 112,
													EndLine:   112,
												},
											},
										},
										{
											ID:        "ruby-progressbar@1.10.0",
											Name:      "ruby-progressbar",
											Version:   "1.10.0",
											Indirect:  true,
											DependsOn: []string(nil),
											Locations: []types.Location{
												{
													StartLine: 120,
													EndLine:   120,
												},
											},
										},
										{
											ID:       "sprockets@3.7.2",
											Name:     "sprockets",
											Version:  "3.7.2",
											Indirect: true,
											DependsOn: []string{
												"concurrent-ruby@1.1.5",
												"rack@2.0.7",
											},
											Locations: []types.Location{
												{
													StartLine: 121,
													EndLine:   121,
												},
											},
										},
										{
											ID:       "sprockets-rails@3.2.1",
											Name:     "sprockets-rails",
											Version:  "3.2.1",
											Indirect: true,
											DependsOn: []string{
												"actionpack@5.2.3",
												"activesupport@5.2.3",
												"sprockets@3.7.2",
											},
											Locations: []types.Location{
												{
													StartLine: 124,
													EndLine:   124,
												},
											},
										},
										{
											ID:        "thor@0.20.3",
											Name:      "thor",
											Version:   "0.20.3",
											Indirect:  true,
											DependsOn: []string(nil),
											Locations: []types.Location{
												{
													StartLine: 128,
													EndLine:   128,
												},
											},
										},
										{
											ID:        "thread_safe@0.3.6",
											Name:      "thread_safe",
											Version:   "0.3.6",
											Indirect:  true,
											DependsOn: []string(nil),
											Locations: []types.Location{
												{
													StartLine: 129,
													EndLine:   129,
												},
											},
										},
										{
											ID:        "tzinfo@1.2.5",
											Name:      "tzinfo",
											Version:   "1.2.5",
											Indirect:  true,
											DependsOn: []string{"thread_safe@0.3.6"},
											Locations: []types.Location{
												{
													StartLine: 130,
													EndLine:   130,
												},
											},
										},
										{
											ID:        "unicode-display_width@1.5.0",
											Name:      "unicode-display_width",
											Version:   "1.5.0",
											Indirect:  true,
											DependsOn: []string(nil),
											Locations: []types.Location{
												{
													StartLine: 132,
													EndLine:   132,
												},
											},
										},
										{
											ID:        "websocket-driver@0.7.0",
											Name:      "websocket-driver",
											Version:   "0.7.0",
											Indirect:  true,
											DependsOn: []string{"websocket-extensions@0.1.3"},
											Locations: []types.Location{
												{
													StartLine: 133,
													EndLine:   133,
												},
											},
										},
										{
											ID:        "websocket-extensions@0.1.3",
											Name:      "websocket-extensions",
											Version:   "0.1.3",
											Indirect:  true,
											DependsOn: []string(nil),
											Locations: []types.Location{
												{
													StartLine: 135,
													EndLine:   135,
												},
											},
										},
									},
								},
							},
							OpaqueDirs: []string{
								"ruby-app/",
							},
						},
					},
				},
			},
			want: types.ArtifactReference{
				Name: "../../test/testdata/vuln-image.tar.gz",
				Type: types.ArtifactContainerImage,
				ID:   "sha256:33f9415ed2cd5a9cef5d5144333619745b9ec0f851f0684dd45fa79c6b26a650",
				BlobIDs: []string{
					"sha256:db2b5b2f26f320b80ee549495888f111151fdb44fecb2c432dfd928e96978e74",
					"sha256:718d6a3d0a24966f2d9f64e0c86695d1bb896fe81df634b85300d34142c80174",
					"sha256:9f6bc14198fa983fd47079bcd82df1391bee8e529a8a131a0305874eb0a51ca0",
					"sha256:44264715b7132cd14cd956bf385d5f875603461f5adeafde7fdecabe2e266291",
				},
				ImageMetadata: types.ImageMetadata{
					ID: "sha256:58701fd185bda36cab0557bb6438661831267aa4a9e0b54211c4d5317a48aff4",
					DiffIDs: []string{
						"sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
						"sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
						"sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
						"sha256:a4595c43a874856bf95f3bfc4fbf78bbaa04c92c726276d4f64193a47ced0566",
					},
					ConfigFile: v1.ConfigFile{
						Architecture:  "amd64",
						Author:        "",
						Created:       v1.Time{Time: time.Date(2020, 2, 16, 10, 38, 41, 114114788, time.UTC)},
						DockerVersion: "19.03.5",
						History: []v1.History{
							{
								Author:     "Bazel",
								Created:    v1.Time{Time: time.Date(1970, 01, 01, 0, 0, 0, 0, time.UTC)},
								CreatedBy:  "bazel build ...",
								EmptyLayer: false,
							},
							{
								Author:     "Bazel",
								Created:    v1.Time{Time: time.Date(1970, 01, 01, 0, 0, 0, 0, time.UTC)},
								CreatedBy:  "bazel build ...",
								EmptyLayer: false,
							},
							{
								Author:     "",
								Created:    v1.Time{Time: time.Date(2020, 2, 16, 10, 38, 40, 976530082, time.UTC)},
								CreatedBy:  "/bin/sh -c #(nop) COPY file:842584685f26edb24dc305d76894f51cfda2bad0c24a05e727f9d4905d184a70 in /php-app/composer.lock ",
								Comment:    "",
								EmptyLayer: false,
							},
							{
								Author:     "",
								Created:    v1.Time{Time: time.Date(2020, 2, 16, 10, 38, 41, 114114788, time.UTC)},
								CreatedBy:  "/bin/sh -c #(nop) COPY file:c6d0373d380252b91829a5bb3c81d5b1afa574c91cef7752d18170a231c31f6d in /ruby-app/Gemfile.lock ",
								Comment:    "",
								EmptyLayer: false,
							},
						},
						OS: "linux",
						RootFS: v1.RootFS{
							Type: "layers",
							DiffIDs: []v1.Hash{
								{
									Algorithm: "sha256",
									Hex:       "932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
								},
								{
									Algorithm: "sha256",
									Hex:       "dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
								},
								{
									Algorithm: "sha256",
									Hex:       "24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
								},
								{
									Algorithm: "sha256",
									Hex:       "a4595c43a874856bf95f3bfc4fbf78bbaa04c92c726276d4f64193a47ced0566",
								},
							},
						},
						Config: v1.Config{
							Env: []string{
								"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
								"SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt",
							},
							Image: "sha256:916390dcf84a1c7852e298f24fb5389a6e7801102086924e55eb08cd58d6a741",
						},
					},
				},
			},
		},
		{
			name:      "happy path: disable analyzers",
			imagePath: "../../test/testdata/vuln-image.tar.gz",
			artifactOpt: artifact.Option{
				DisabledAnalyzers: []analyzer.Type{
					analyzer.TypeDebian,
					analyzer.TypeDpkg,
					analyzer.TypeDpkgLicense,
					analyzer.TypeComposer,
					analyzer.TypeBundler,
					analyzer.TypeLicenseFile,
				},
				LicenseScannerOption: analyzer.LicenseScannerOption{Full: true},
			},
			missingBlobsExpectation: cache.ArtifactCacheMissingBlobsExpectation{
				Args: cache.ArtifactCacheMissingBlobsArgs{
					ArtifactID: "sha256:33f9415ed2cd5a9cef5d5144333619745b9ec0f851f0684dd45fa79c6b26a650",
					BlobIDs: []string{
						"sha256:dc2c102de2a4dc82bc017564a2c1a46646f071367bd51d3ddd80171dc5a78ffe",
						"sha256:e6bc45e7459162f5a27dd7bd310a420f27378f2ea24c6ed5f0a083f2377bde24",
						"sha256:8184bee7b1985e0abd72288946c246b90e1847b36fdcd50ca3d588b9371ec920",
						"sha256:f1bb0ccf476528c6165a2f1a74d0e5a0cb06c9b254a0def6b1183db662e83dd4",
					},
				},
				Returns: cache.ArtifactCacheMissingBlobsReturns{
					MissingBlobIDs: []string{
						"sha256:dc2c102de2a4dc82bc017564a2c1a46646f071367bd51d3ddd80171dc5a78ffe",
						"sha256:e6bc45e7459162f5a27dd7bd310a420f27378f2ea24c6ed5f0a083f2377bde24",
						"sha256:8184bee7b1985e0abd72288946c246b90e1847b36fdcd50ca3d588b9371ec920",
						"sha256:f1bb0ccf476528c6165a2f1a74d0e5a0cb06c9b254a0def6b1183db662e83dd4",
					},
				},
			},
			putBlobExpectations: []cache.ArtifactCachePutBlobExpectation{
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:dc2c102de2a4dc82bc017564a2c1a46646f071367bd51d3ddd80171dc5a78ffe",
						BlobInfo: types.BlobInfo{
							SchemaVersion: types.BlobJSONSchemaVersion,
							Digest:        "",
							DiffID:        "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
							CreatedBy:     "bazel build ...",
						},
					},
				},
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:e6bc45e7459162f5a27dd7bd310a420f27378f2ea24c6ed5f0a083f2377bde24",
						BlobInfo: types.BlobInfo{
							SchemaVersion: types.BlobJSONSchemaVersion,
							Digest:        "",
							DiffID:        "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
							CreatedBy:     "bazel build ...",
						},
					},
				},
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:8184bee7b1985e0abd72288946c246b90e1847b36fdcd50ca3d588b9371ec920",
						BlobInfo: types.BlobInfo{
							SchemaVersion: types.BlobJSONSchemaVersion,
							Digest:        "",
							DiffID:        "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
							CreatedBy:     "COPY file:842584685f26edb24dc305d76894f51cfda2bad0c24a05e727f9d4905d184a70 in /php-app/composer.lock ",
							OpaqueDirs:    []string{"php-app/"},
						},
					},
				},
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:f1bb0ccf476528c6165a2f1a74d0e5a0cb06c9b254a0def6b1183db662e83dd4",
						BlobInfo: types.BlobInfo{
							SchemaVersion: types.BlobJSONSchemaVersion,
							Digest:        "",
							DiffID:        "sha256:a4595c43a874856bf95f3bfc4fbf78bbaa04c92c726276d4f64193a47ced0566",
							CreatedBy:     "COPY file:c6d0373d380252b91829a5bb3c81d5b1afa574c91cef7752d18170a231c31f6d in /ruby-app/Gemfile.lock ",
							OpaqueDirs:    []string{"ruby-app/"},
						},
					},
				},
			},
			want: types.ArtifactReference{
				Name: "../../test/testdata/vuln-image.tar.gz",
				Type: types.ArtifactContainerImage,
				ID:   "sha256:33f9415ed2cd5a9cef5d5144333619745b9ec0f851f0684dd45fa79c6b26a650",
				BlobIDs: []string{
					"sha256:dc2c102de2a4dc82bc017564a2c1a46646f071367bd51d3ddd80171dc5a78ffe",
					"sha256:e6bc45e7459162f5a27dd7bd310a420f27378f2ea24c6ed5f0a083f2377bde24",
					"sha256:8184bee7b1985e0abd72288946c246b90e1847b36fdcd50ca3d588b9371ec920",
					"sha256:f1bb0ccf476528c6165a2f1a74d0e5a0cb06c9b254a0def6b1183db662e83dd4",
				},
				ImageMetadata: types.ImageMetadata{
					ID: "sha256:58701fd185bda36cab0557bb6438661831267aa4a9e0b54211c4d5317a48aff4",
					DiffIDs: []string{
						"sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
						"sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
						"sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
						"sha256:a4595c43a874856bf95f3bfc4fbf78bbaa04c92c726276d4f64193a47ced0566",
					},
					ConfigFile: v1.ConfigFile{
						Architecture:  "amd64",
						Author:        "",
						Created:       v1.Time{Time: time.Date(2020, 2, 16, 10, 38, 41, 114114788, time.UTC)},
						DockerVersion: "19.03.5",
						History: []v1.History{
							{
								Author:     "Bazel",
								Created:    v1.Time{Time: time.Date(1970, 01, 01, 0, 0, 0, 0, time.UTC)},
								CreatedBy:  "bazel build ...",
								Comment:    "",
								EmptyLayer: false,
							},
							{
								Author:     "Bazel",
								Created:    v1.Time{Time: time.Date(1970, 01, 01, 0, 0, 0, 0, time.UTC)},
								CreatedBy:  "bazel build ...",
								Comment:    "",
								EmptyLayer: false,
							},
							{
								Created:    v1.Time{Time: time.Date(2020, 2, 16, 10, 38, 40, 976530082, time.UTC)},
								CreatedBy:  "/bin/sh -c #(nop) COPY file:842584685f26edb24dc305d76894f51cfda2bad0c24a05e727f9d4905d184a70 in /php-app/composer.lock ",
								Comment:    "",
								EmptyLayer: false,
							},
							{
								Created:    v1.Time{Time: time.Date(2020, 2, 16, 10, 38, 41, 114114788, time.UTC)},
								CreatedBy:  "/bin/sh -c #(nop) COPY file:c6d0373d380252b91829a5bb3c81d5b1afa574c91cef7752d18170a231c31f6d in /ruby-app/Gemfile.lock ",
								Comment:    "",
								EmptyLayer: false,
							},
						},
						OS: "linux",
						RootFS: v1.RootFS{
							Type: "layers",
							DiffIDs: []v1.Hash{
								{
									Algorithm: "sha256",
									Hex:       "932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
								},
								{
									Algorithm: "sha256",
									Hex:       "dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
								},
								{
									Algorithm: "sha256",
									Hex:       "24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
								},
								{
									Algorithm: "sha256",
									Hex:       "a4595c43a874856bf95f3bfc4fbf78bbaa04c92c726276d4f64193a47ced0566",
								},
							},
						},
						Config: v1.Config{
							Env: []string{
								"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
								"SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt",
							},
							Hostname: "",
							Image:    "sha256:916390dcf84a1c7852e298f24fb5389a6e7801102086924e55eb08cd58d6a741",
						},
					},
				},
			},
		},
		{
			name:      "sad path, MissingBlobs returns an error",
			imagePath: "../../test/testdata/alpine-311.tar.gz",
			missingBlobsExpectation: cache.ArtifactCacheMissingBlobsExpectation{
				Args: cache.ArtifactCacheMissingBlobsArgs{
					ArtifactID: "sha256:c232b7d8ac8aa08aa767313d0b53084c4380d1c01a213a5971bdb039e6538313",
					BlobIDs:    []string{"sha256:0366f81c3cbeac047536f9ca133b5632544c8342544922c3ed8a3e51c0250897"},
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
					ArtifactID: "sha256:c232b7d8ac8aa08aa767313d0b53084c4380d1c01a213a5971bdb039e6538313",
					BlobIDs:    []string{"sha256:0366f81c3cbeac047536f9ca133b5632544c8342544922c3ed8a3e51c0250897"},
				},
				Returns: cache.ArtifactCacheMissingBlobsReturns{
					MissingBlobIDs: []string{"sha256:0366f81c3cbeac047536f9ca133b5632544c8342544922c3ed8a3e51c0250897"},
				},
			},
			putBlobExpectations: []cache.ArtifactCachePutBlobExpectation{
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:0366f81c3cbeac047536f9ca133b5632544c8342544922c3ed8a3e51c0250897",
						BlobInfo: types.BlobInfo{
							SchemaVersion: types.BlobJSONSchemaVersion,
							Digest:        "",
							DiffID:        "sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203",
							CreatedBy:     "ADD file:0c4555f363c2672e350001f1293e689875a3760afe7b3f9146886afe67121cba in / ",
							OS: types.OS{
								Family: "alpine",
								Name:   "3.11.5",
							},
							Repository: &types.Repository{
								Family:  "alpine",
								Release: "3.11",
							},
							PackageInfos: []types.PackageInfo{
								{
									FilePath: "lib/apk/db/installed",
									Packages: alpinePkgs,
								},
							},
							Licenses: []types.LicenseFile{
								{
									Type:     "header",
									FilePath: "etc/ssl/misc/CA.pl",
									Findings: []types.LicenseFinding{
										{
											Name:       "OpenSSL",
											Confidence: 1,
											Link:       "https://spdx.org/licenses/OpenSSL.html",
										},
									},
								},
								{
									Type:     "header",
									FilePath: "etc/ssl/misc/tsget.pl",
									Findings: []types.LicenseFinding{
										{
											Name:       "OpenSSL",
											Confidence: 1,
											Link:       "https://spdx.org/licenses/OpenSSL.html",
										},
									},
								},
							},
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
			name:      "sad path, PutBlob returns an error with multiple layers and Slow enabled",
			imagePath: "../../test/testdata/vuln-image.tar.gz",
			artifactOpt: artifact.Option{
				Slow: true,
			},
			missingBlobsExpectation: cache.ArtifactCacheMissingBlobsExpectation{
				Args: cache.ArtifactCacheMissingBlobsArgs{
					ArtifactID: "sha256:33f9415ed2cd5a9cef5d5144333619745b9ec0f851f0684dd45fa79c6b26a650",
					BlobIDs: []string{
						"sha256:db2b5b2f26f320b80ee549495888f111151fdb44fecb2c432dfd928e96978e74",
						"sha256:718d6a3d0a24966f2d9f64e0c86695d1bb896fe81df634b85300d34142c80174",
						"sha256:9f6bc14198fa983fd47079bcd82df1391bee8e529a8a131a0305874eb0a51ca0",
						"sha256:44264715b7132cd14cd956bf385d5f875603461f5adeafde7fdecabe2e266291",
					},
				},
				Returns: cache.ArtifactCacheMissingBlobsReturns{
					MissingBlobIDs: []string{
						"sha256:db2b5b2f26f320b80ee549495888f111151fdb44fecb2c432dfd928e96978e74",
						"sha256:718d6a3d0a24966f2d9f64e0c86695d1bb896fe81df634b85300d34142c80174",
						"sha256:9f6bc14198fa983fd47079bcd82df1391bee8e529a8a131a0305874eb0a51ca0",
						"sha256:44264715b7132cd14cd956bf385d5f875603461f5adeafde7fdecabe2e266291",
					},
				},
			},
			putBlobExpectations: []cache.ArtifactCachePutBlobExpectation{
				{

					Args: cache.ArtifactCachePutBlobArgs{
						BlobID:           "sha256:db2b5b2f26f320b80ee549495888f111151fdb44fecb2c432dfd928e96978e74",
						BlobInfoAnything: true,
					},

					Returns: cache.ArtifactCachePutBlobReturns{
						Err: errors.New("put layer failed"),
					},
				},
				{

					Args: cache.ArtifactCachePutBlobArgs{
						BlobID:           "sha256:718d6a3d0a24966f2d9f64e0c86695d1bb896fe81df634b85300d34142c80174",
						BlobInfoAnything: true,
					},

					Returns: cache.ArtifactCachePutBlobReturns{
						Err: errors.New("put layer failed"),
					},
				},
				{

					Args: cache.ArtifactCachePutBlobArgs{
						BlobID:           "sha256:9f6bc14198fa983fd47079bcd82df1391bee8e529a8a131a0305874eb0a51ca0",
						BlobInfoAnything: true,
					},

					Returns: cache.ArtifactCachePutBlobReturns{
						Err: errors.New("put layer failed"),
					},
				},
				{

					Args: cache.ArtifactCachePutBlobArgs{
						BlobID:           "sha256:44264715b7132cd14cd956bf385d5f875603461f5adeafde7fdecabe2e266291",
						BlobInfoAnything: true,
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
					ArtifactID: "sha256:c232b7d8ac8aa08aa767313d0b53084c4380d1c01a213a5971bdb039e6538313",
					BlobIDs:    []string{"sha256:0366f81c3cbeac047536f9ca133b5632544c8342544922c3ed8a3e51c0250897"},
				},
				Returns: cache.ArtifactCacheMissingBlobsReturns{
					MissingArtifact: true,
					MissingBlobIDs:  []string{"sha256:0366f81c3cbeac047536f9ca133b5632544c8342544922c3ed8a3e51c0250897"},
				},
			},
			putBlobExpectations: []cache.ArtifactCachePutBlobExpectation{
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:0366f81c3cbeac047536f9ca133b5632544c8342544922c3ed8a3e51c0250897",
						BlobInfo: types.BlobInfo{
							SchemaVersion: types.BlobJSONSchemaVersion,
							Digest:        "",
							DiffID:        "sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203",
							CreatedBy:     "ADD file:0c4555f363c2672e350001f1293e689875a3760afe7b3f9146886afe67121cba in / ",
							OS: types.OS{
								Family: "alpine",
								Name:   "3.11.5",
							},
							Repository: &types.Repository{
								Family:  "alpine",
								Release: "3.11",
							},
							PackageInfos: []types.PackageInfo{
								{
									FilePath: "lib/apk/db/installed",
									Packages: alpinePkgs,
								},
							},
							Licenses: []types.LicenseFile{
								{
									Type:     "header",
									FilePath: "etc/ssl/misc/CA.pl",
									Findings: []types.LicenseFinding{
										{
											Name:       "OpenSSL",
											Confidence: 1,
											Link:       "https://spdx.org/licenses/OpenSSL.html",
										},
									},
								},
								{
									Type:     "header",
									FilePath: "etc/ssl/misc/tsget.pl",
									Findings: []types.LicenseFinding{
										{
											Name:       "OpenSSL",
											Confidence: 1,
											Link:       "https://spdx.org/licenses/OpenSSL.html",
										},
									},
								},
							},
						},
					},
					Returns: cache.ArtifactCachePutBlobReturns{},
				},
			},
			putArtifactExpectations: []cache.ArtifactCachePutArtifactExpectation{
				{
					Args: cache.ArtifactCachePutArtifactArgs{
						ArtifactID: "sha256:c232b7d8ac8aa08aa767313d0b53084c4380d1c01a213a5971bdb039e6538313",
						ArtifactInfo: types.ArtifactInfo{
							SchemaVersion: types.ArtifactJSONSchemaVersion,
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

			a, err := image2.NewArtifact(img, mockCache, tt.artifactOpt)
			require.NoError(t, err)

			got, err := a.Inspect(context.Background())
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr, tt.name)
				return
			}
			require.NoError(t, err, tt.name)
			assert.Equal(t, tt.want, got)
		})
	}
}
