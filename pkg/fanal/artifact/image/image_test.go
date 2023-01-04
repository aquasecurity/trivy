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
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/command/apk"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/config/all"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/php/composer"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/ruby/bundler"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/licensing"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/alpine"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/debian"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/pkg/apk"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/pkg/dpkg"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/repo/apk"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/secret"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	image2 "github.com/aquasecurity/trivy/pkg/fanal/artifact/image"
	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	_ "github.com/aquasecurity/trivy/pkg/fanal/handler/misconf"
	_ "github.com/aquasecurity/trivy/pkg/fanal/handler/sysfile"
	"github.com/aquasecurity/trivy/pkg/fanal/image"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestArtifact_Inspect(t *testing.T) {
	alpinePkgs := []types.Package{
		{
			ID:   "alpine-baselayout@3.2.0-r3",
			Name: "alpine-baselayout", Version: "3.2.0-r3",
			SrcName: "alpine-baselayout", SrcVersion: "3.2.0-r3",
			Licenses: []string{"GPL-2.0"},
			DependsOn: []string{
				"busybox@1.31.1-r9",
				"musl@1.1.24-r2",
			},
		},
		{
			ID:   "alpine-keys@2.1-r2",
			Name: "alpine-keys", Version: "2.1-r2", SrcName: "alpine-keys",
			SrcVersion: "2.1-r2", Licenses: []string{"MIT"},
		},
		{
			ID:   "apk-tools@2.10.4-r3",
			Name: "apk-tools", Version: "2.10.4-r3", SrcName: "apk-tools",
			SrcVersion: "2.10.4-r3", Licenses: []string{"GPL-2.0"},
			DependsOn: []string{
				"libcrypto1.1@1.1.1d-r3",
				"libssl1.1@1.1.1d-r3",
				"musl@1.1.24-r2",
				"zlib@1.2.11-r3",
			},
		},
		{
			ID:   "busybox@1.31.1-r9",
			Name: "busybox", Version: "1.31.1-r9", SrcName: "busybox",
			SrcVersion: "1.31.1-r9", Licenses: []string{"GPL-2.0"},
			DependsOn: []string{
				"musl@1.1.24-r2",
			},
		},
		{
			ID:   "ca-certificates-cacert@20191127-r1",
			Name: "ca-certificates-cacert", Version: "20191127-r1",
			SrcName: "ca-certificates", SrcVersion: "20191127-r1",
			Licenses: []string{"MPL-2.0", "GPL-2.0"},
		},
		{
			ID:   "libc-utils@0.7.2-r0",
			Name: "libc-utils", Version: "0.7.2-r0", SrcName: "libc-dev",
			SrcVersion: "0.7.2-r0", Licenses: []string{"BSD-3-Clause"},
			DependsOn: []string{
				"musl-utils@1.1.24-r2",
			},
		},
		{
			ID:   "libcrypto1.1@1.1.1d-r3",
			Name: "libcrypto1.1", Version: "1.1.1d-r3", SrcName: "openssl",
			SrcVersion: "1.1.1d-r3", Licenses: []string{"OpenSSL"},
			DependsOn: []string{
				"musl@1.1.24-r2",
			},
		},
		{
			ID:   "libssl1.1@1.1.1d-r3",
			Name: "libssl1.1", Version: "1.1.1d-r3", SrcName: "openssl",
			SrcVersion: "1.1.1d-r3", Licenses: []string{"OpenSSL"},
			DependsOn: []string{
				"libcrypto1.1@1.1.1d-r3",
				"musl@1.1.24-r2",
			},
		},
		{
			ID:   "libtls-standalone@2.9.1-r0",
			Name: "libtls-standalone", Version: "2.9.1-r0",
			SrcName: "libtls-standalone", SrcVersion: "2.9.1-r0",
			Licenses: []string{"ISC"},
			DependsOn: []string{
				"ca-certificates-cacert@20191127-r1",
				"libcrypto1.1@1.1.1d-r3",
				"libssl1.1@1.1.1d-r3",
				"musl@1.1.24-r2",
			},
		},
		{
			ID:   "musl@1.1.24-r2",
			Name: "musl", Version: "1.1.24-r2", SrcName: "musl",
			SrcVersion: "1.1.24-r2", Licenses: []string{"MIT"},
		},
		{
			ID:   "musl-utils@1.1.24-r2",
			Name: "musl-utils", Version: "1.1.24-r2", SrcName: "musl",
			SrcVersion: "1.1.24-r2", Licenses: []string{"MIT", "BSD-3-Clause", "GPL-2.0"},
			DependsOn: []string{
				"musl@1.1.24-r2",
				"scanelf@1.2.4-r0",
			},
		},
		{
			ID:   "scanelf@1.2.4-r0",
			Name: "scanelf", Version: "1.2.4-r0", SrcName: "pax-utils",
			SrcVersion: "1.2.4-r0", Licenses: []string{"GPL-2.0"},
			DependsOn: []string{
				"musl@1.1.24-r2",
			},
		},
		{
			ID:   "ssl_client@1.31.1-r9",
			Name: "ssl_client", Version: "1.31.1-r9", SrcName: "busybox",
			SrcVersion: "1.31.1-r9", Licenses: []string{"GPL-2.0"},
			DependsOn: []string{
				"libtls-standalone@2.9.1-r0",
				"musl@1.1.24-r2",
			},
		},
		{
			ID:   "zlib@1.2.11-r3",
			Name: "zlib", Version: "1.2.11-r3", SrcName: "zlib",
			SrcVersion: "1.2.11-r3", Licenses: []string{"Zlib"},
			DependsOn: []string{
				"musl@1.1.24-r2",
			},
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
					ArtifactID: "sha256:059741cfbdc039e88e337d621e57e03e99b0e0a75df32f2027ebef13f839af65",
					BlobIDs:    []string{"sha256:a07b19e0e0a4339c00d982f6d80f305cd9dbb98f88b3c74e57b97574b9ce9ba3"},
				},
				Returns: cache.ArtifactCacheMissingBlobsReturns{
					MissingArtifact: true,
					MissingBlobIDs:  []string{"sha256:a07b19e0e0a4339c00d982f6d80f305cd9dbb98f88b3c74e57b97574b9ce9ba3"},
				},
			},
			putBlobExpectations: []cache.ArtifactCachePutBlobExpectation{
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:a07b19e0e0a4339c00d982f6d80f305cd9dbb98f88b3c74e57b97574b9ce9ba3",
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
						ArtifactID: "sha256:059741cfbdc039e88e337d621e57e03e99b0e0a75df32f2027ebef13f839af65",
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
				ID:      "sha256:059741cfbdc039e88e337d621e57e03e99b0e0a75df32f2027ebef13f839af65",
				BlobIDs: []string{"sha256:a07b19e0e0a4339c00d982f6d80f305cd9dbb98f88b3c74e57b97574b9ce9ba3"},
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
							Type: "layers", DiffIDs: []v1.Hash{
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
					ArtifactID: "sha256:a646bb11d39c149d4aaf9b888233048e0848304e5abd75667ea6f21d540d800c",
					BlobIDs: []string{
						"sha256:3bfd543b4467abb972bfeeaa7a7d75ee18e7c92f077600d48fd1532f09129b54",
						"sha256:9f8cf74dff8cad6bb4df8fc0fa81dca446bd6f44c2d811a167ffca34ab90a6f8",
						"sha256:7487a77e30f32bd00fc35322a7fa308686bf3da17bb63f6a2bb2e9398a9a0357",
						"sha256:9aead687f9207ee718401fef3174f8e5b9a99114f3bcdcae18ddc34d88ed4906",
					},
				},
				Returns: cache.ArtifactCacheMissingBlobsReturns{
					MissingBlobIDs: []string{
						"sha256:3bfd543b4467abb972bfeeaa7a7d75ee18e7c92f077600d48fd1532f09129b54",
						"sha256:9f8cf74dff8cad6bb4df8fc0fa81dca446bd6f44c2d811a167ffca34ab90a6f8",
						"sha256:7487a77e30f32bd00fc35322a7fa308686bf3da17bb63f6a2bb2e9398a9a0357",
						"sha256:9aead687f9207ee718401fef3174f8e5b9a99114f3bcdcae18ddc34d88ed4906",
					},
				},
			},
			putBlobExpectations: []cache.ArtifactCachePutBlobExpectation{
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:3bfd543b4467abb972bfeeaa7a7d75ee18e7c92f077600d48fd1532f09129b54",
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
									Packages: []types.Package{
										{
											ID:   "base-files@9.9+deb9u9",
											Name: "base-files", Version: "9.9+deb9u9", SrcName: "base-files",
											SrcVersion: "9.9+deb9u9",
											Maintainer: "Santiago Vila <sanvila@debian.org>",
										},
									},
								},
								{
									FilePath: "var/lib/dpkg/status.d/netbase",
									Packages: []types.Package{
										{ID: "netbase@5.4", Name: "netbase", Version: "5.4",
											SrcName: "netbase", SrcVersion: "5.4", Maintainer: "Marco d'Itri <md@linux.it>"},
									},
								},
								{
									FilePath: "var/lib/dpkg/status.d/tzdata",
									Packages: []types.Package{
										{
											ID:   "tzdata@2019a-0+deb9u1",
											Name: "tzdata", Version: "2019a-0+deb9u1", SrcName: "tzdata",
											SrcVersion: "2019a-0+deb9u1",
											Maintainer: "GNU Libc Maintainers <debian-glibc@lists.debian.org>",
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
						BlobID: "sha256:9f8cf74dff8cad6bb4df8fc0fa81dca446bd6f44c2d811a167ffca34ab90a6f8",
						BlobInfo: types.BlobInfo{
							SchemaVersion: types.BlobJSONSchemaVersion,
							Digest:        "",
							DiffID:        "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
							CreatedBy:     "bazel build ...",
							PackageInfos: []types.PackageInfo{
								{
									FilePath: "var/lib/dpkg/status.d/libc6",
									Packages: []types.Package{
										{
											ID:   "libc6@2.24-11+deb9u4",
											Name: "libc6", Version: "2.24-11+deb9u4", SrcName: "glibc",
											SrcVersion: "2.24-11+deb9u4",
											Maintainer: "GNU Libc Maintainers <debian-glibc@lists.debian.org>",
										},
									},
								},
								{
									FilePath: "var/lib/dpkg/status.d/libssl1",
									Packages: []types.Package{
										{
											ID:   "libssl1.1@1.1.0k-1~deb9u1",
											Name: "libssl1.1", Version: "1.1.0k-1~deb9u1", SrcName: "openssl",
											SrcVersion: "1.1.0k-1~deb9u1",
											Maintainer: "Debian OpenSSL Team <pkg-openssl-devel@lists.alioth.debian.org>",
										},
									},
								},
								{
									FilePath: "var/lib/dpkg/status.d/openssl",
									Packages: []types.Package{
										{
											ID:   "openssl@1.1.0k-1~deb9u1",
											Name: "openssl", Version: "1.1.0k-1~deb9u1", SrcName: "openssl",
											SrcVersion: "1.1.0k-1~deb9u1",
											Maintainer: "Debian OpenSSL Team <pkg-openssl-devel@lists.alioth.debian.org>",
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
						BlobID: "sha256:7487a77e30f32bd00fc35322a7fa308686bf3da17bb63f6a2bb2e9398a9a0357",
						BlobInfo: types.BlobInfo{
							SchemaVersion: types.BlobJSONSchemaVersion,
							Digest:        "",
							DiffID:        "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
							CreatedBy:     "COPY file:842584685f26edb24dc305d76894f51cfda2bad0c24a05e727f9d4905d184a70 in /php-app/composer.lock ",
							Applications: []types.Application{
								{
									Type: "composer", FilePath: "php-app/composer.lock",
									Libraries: []types.Package{
										{Name: "guzzlehttp/guzzle", Version: "6.2.0"},
										{Name: "guzzlehttp/promises", Version: "v1.3.1"},
										{Name: "guzzlehttp/psr7", Version: "1.5.2"},
										{Name: "laravel/installer", Version: "v2.0.1"},
										{Name: "pear/log", Version: "1.13.1"},
										{Name: "pear/pear_exception", Version: "v1.0.0"},
										{Name: "psr/http-message", Version: "1.0.1"},
										{Name: "ralouphie/getallheaders", Version: "2.0.5"},
										{Name: "symfony/console", Version: "v4.2.7"},
										{Name: "symfony/contracts", Version: "v1.0.2"},
										{Name: "symfony/filesystem", Version: "v4.2.7"},
										{Name: "symfony/polyfill-ctype", Version: "v1.11.0"},
										{Name: "symfony/polyfill-mbstring", Version: "v1.11.0"},
										{Name: "symfony/process", Version: "v4.2.7"},
									},
								},
							},
							OpaqueDirs: []string{"php-app/"},
						},
					},
				},
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:9aead687f9207ee718401fef3174f8e5b9a99114f3bcdcae18ddc34d88ed4906",
						BlobInfo: types.BlobInfo{
							SchemaVersion: types.BlobJSONSchemaVersion,
							Digest:        "",
							DiffID:        "sha256:a4595c43a874856bf95f3bfc4fbf78bbaa04c92c726276d4f64193a47ced0566",
							CreatedBy:     "COPY file:c6d0373d380252b91829a5bb3c81d5b1afa574c91cef7752d18170a231c31f6d in /ruby-app/Gemfile.lock ",
							Applications: []types.Application{
								{
									Type: types.Bundler, FilePath: "ruby-app/Gemfile.lock",
									Libraries: []types.Package{
										{Name: "actioncable", Version: "5.2.3"},
										{Name: "actionmailer", Version: "5.2.3"},
										{Name: "actionpack", Version: "5.2.3"},
										{Name: "actionview", Version: "5.2.3"},
										{Name: "activejob", Version: "5.2.3"},
										{Name: "activemodel", Version: "5.2.3"},
										{Name: "activerecord", Version: "5.2.3"},
										{Name: "activestorage", Version: "5.2.3"},
										{Name: "activesupport", Version: "5.2.3"},
										{Name: "arel", Version: "9.0.0"},
										{Name: "ast", Version: "2.4.0"},
										{Name: "builder", Version: "3.2.3"},
										{Name: "coderay", Version: "1.1.2"},
										{Name: "concurrent-ruby", Version: "1.1.5"},
										{Name: "crass", Version: "1.0.4"},
										{Name: "dotenv", Version: "2.7.2"},
										{Name: "erubi", Version: "1.8.0"},
										{Name: "faker", Version: "1.9.3"},
										{Name: "globalid", Version: "0.4.2"},
										{Name: "i18n", Version: "1.6.0"},
										{Name: "jaro_winkler", Version: "1.5.2"},
										{Name: "json", Version: "2.2.0"},
										{Name: "loofah", Version: "2.2.3"},
										{Name: "mail", Version: "2.7.1"},
										{Name: "marcel", Version: "0.3.3"},
										{Name: "method_source", Version: "0.9.2"},
										{Name: "mimemagic", Version: "0.3.3"},
										{Name: "mini_mime", Version: "1.0.1"},
										{Name: "mini_portile2", Version: "2.4.0"},
										{Name: "minitest", Version: "5.11.3"},
										{Name: "nio4r", Version: "2.3.1"},
										{Name: "nokogiri", Version: "1.10.3"},
										{Name: "parallel", Version: "1.17.0"},
										{Name: "parser", Version: "2.6.3.0"},
										{Name: "pry", Version: "0.12.2"},
										{Name: "psych", Version: "3.1.0"},
										{Name: "rack", Version: "2.0.7"},
										{Name: "rack-test", Version: "1.1.0"},
										{Name: "rails", Version: "5.2.0"},
										{Name: "rails-dom-testing", Version: "2.0.3"},
										{Name: "rails-html-sanitizer", Version: "1.0.3"},
										{Name: "railties", Version: "5.2.3"},
										{Name: "rainbow", Version: "3.0.0"},
										{Name: "rake", Version: "12.3.2"},
										{Name: "rubocop", Version: "0.67.2"},
										{Name: "ruby-progressbar", Version: "1.10.0"},
										{Name: "sprockets", Version: "3.7.2"},
										{Name: "sprockets-rails", Version: "3.2.1"},
										{Name: "thor", Version: "0.20.3"},
										{Name: "thread_safe", Version: "0.3.6"},
										{Name: "tzinfo", Version: "1.2.5"},
										{Name: "unicode-display_width", Version: "1.5.0"},
										{Name: "websocket-driver", Version: "0.7.0"},
										{Name: "websocket-extensions", Version: "0.1.3"},
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
				ID:   "sha256:a646bb11d39c149d4aaf9b888233048e0848304e5abd75667ea6f21d540d800c",
				BlobIDs: []string{
					"sha256:3bfd543b4467abb972bfeeaa7a7d75ee18e7c92f077600d48fd1532f09129b54",
					"sha256:9f8cf74dff8cad6bb4df8fc0fa81dca446bd6f44c2d811a167ffca34ab90a6f8",
					"sha256:7487a77e30f32bd00fc35322a7fa308686bf3da17bb63f6a2bb2e9398a9a0357",
					"sha256:9aead687f9207ee718401fef3174f8e5b9a99114f3bcdcae18ddc34d88ed4906",
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
								}, {
									Algorithm: "sha256",
									Hex:       "dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
								}, {
									Algorithm: "sha256",
									Hex:       "24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
								}, {
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
					analyzer.TypeDebian, analyzer.TypeDpkg, analyzer.TypeDpkgLicense, analyzer.TypeComposer,
					analyzer.TypeBundler, analyzer.TypeLicenseFile,
				},
				LicenseScannerOption: analyzer.LicenseScannerOption{Full: true},
			},
			missingBlobsExpectation: cache.ArtifactCacheMissingBlobsExpectation{
				Args: cache.ArtifactCacheMissingBlobsArgs{
					ArtifactID: "sha256:a646bb11d39c149d4aaf9b888233048e0848304e5abd75667ea6f21d540d800c",
					BlobIDs: []string{
						"sha256:ef7f3617f4e698a7378c222861ad779caf39293eb75bc40a297feb0f04997773",
						"sha256:47b4982cb2f3465af796707b5d3204ecebff8904a7de34b994b0f349b00749e3",
						"sha256:4c59618ffe6b2dd606b9342bc7cf5673d87e562789b7f132e5234b2e7412a01f",
						"sha256:3943af1221bbd84efc398958163456fca57e1400c24eeb2db9e2ddad7c1f37c0",
					},
				},
				Returns: cache.ArtifactCacheMissingBlobsReturns{
					MissingBlobIDs: []string{
						"sha256:ef7f3617f4e698a7378c222861ad779caf39293eb75bc40a297feb0f04997773",
						"sha256:47b4982cb2f3465af796707b5d3204ecebff8904a7de34b994b0f349b00749e3",
						"sha256:4c59618ffe6b2dd606b9342bc7cf5673d87e562789b7f132e5234b2e7412a01f",
						"sha256:3943af1221bbd84efc398958163456fca57e1400c24eeb2db9e2ddad7c1f37c0",
					},
				},
			},
			putBlobExpectations: []cache.ArtifactCachePutBlobExpectation{
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:ef7f3617f4e698a7378c222861ad779caf39293eb75bc40a297feb0f04997773",
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
						BlobID: "sha256:47b4982cb2f3465af796707b5d3204ecebff8904a7de34b994b0f349b00749e3",
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
						BlobID: "sha256:4c59618ffe6b2dd606b9342bc7cf5673d87e562789b7f132e5234b2e7412a01f",
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
						BlobID: "sha256:3943af1221bbd84efc398958163456fca57e1400c24eeb2db9e2ddad7c1f37c0",
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
				ID:   "sha256:a646bb11d39c149d4aaf9b888233048e0848304e5abd75667ea6f21d540d800c",
				BlobIDs: []string{
					"sha256:ef7f3617f4e698a7378c222861ad779caf39293eb75bc40a297feb0f04997773",
					"sha256:47b4982cb2f3465af796707b5d3204ecebff8904a7de34b994b0f349b00749e3",
					"sha256:4c59618ffe6b2dd606b9342bc7cf5673d87e562789b7f132e5234b2e7412a01f",
					"sha256:3943af1221bbd84efc398958163456fca57e1400c24eeb2db9e2ddad7c1f37c0",
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
					ArtifactID: "sha256:059741cfbdc039e88e337d621e57e03e99b0e0a75df32f2027ebef13f839af65",
					BlobIDs:    []string{"sha256:a07b19e0e0a4339c00d982f6d80f305cd9dbb98f88b3c74e57b97574b9ce9ba3"},
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
					ArtifactID: "sha256:059741cfbdc039e88e337d621e57e03e99b0e0a75df32f2027ebef13f839af65",
					BlobIDs:    []string{"sha256:a07b19e0e0a4339c00d982f6d80f305cd9dbb98f88b3c74e57b97574b9ce9ba3"},
				},
				Returns: cache.ArtifactCacheMissingBlobsReturns{
					MissingBlobIDs: []string{"sha256:a07b19e0e0a4339c00d982f6d80f305cd9dbb98f88b3c74e57b97574b9ce9ba3"},
				},
			},
			putBlobExpectations: []cache.ArtifactCachePutBlobExpectation{
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:a07b19e0e0a4339c00d982f6d80f305cd9dbb98f88b3c74e57b97574b9ce9ba3",
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
			name:      "sad path, PutArtifact returns an error",
			imagePath: "../../test/testdata/alpine-311.tar.gz",
			missingBlobsExpectation: cache.ArtifactCacheMissingBlobsExpectation{
				Args: cache.ArtifactCacheMissingBlobsArgs{
					ArtifactID: "sha256:059741cfbdc039e88e337d621e57e03e99b0e0a75df32f2027ebef13f839af65",
					BlobIDs:    []string{"sha256:a07b19e0e0a4339c00d982f6d80f305cd9dbb98f88b3c74e57b97574b9ce9ba3"},
				},
				Returns: cache.ArtifactCacheMissingBlobsReturns{
					MissingArtifact: true,
					MissingBlobIDs:  []string{"sha256:a07b19e0e0a4339c00d982f6d80f305cd9dbb98f88b3c74e57b97574b9ce9ba3"},
				},
			},
			putBlobExpectations: []cache.ArtifactCachePutBlobExpectation{
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:a07b19e0e0a4339c00d982f6d80f305cd9dbb98f88b3c74e57b97574b9ce9ba3",
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
						ArtifactID: "sha256:059741cfbdc039e88e337d621e57e03e99b0e0a75df32f2027ebef13f839af65",
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
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
			} else {
				require.NoError(t, err, tt.name)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}
