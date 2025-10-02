package image_test

import (
	"math/rand"
	"testing"
	"time"

	"github.com/docker/go-units"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/cachetest"
	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	image2 "github.com/aquasecurity/trivy/pkg/fanal/artifact/image"
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

// Common blob IDs used across multiple test cases to reduce duplication
const (
	alpineBaseLayerID     = "sha256:be60f1fe61fc63ab50b10fe0779614e605a973a38cd7d2a02f3f20b081e56d4a"
	alpineBaseLayerDiffID = "sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203"
	alpineArtifactID      = "sha256:3c709d2a158be3a97051e10cd0e30f047225cb9505101feb3fadcd395c2e0408"
	composerImageID       = "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72"
)

func TestArtifact_Inspect(t *testing.T) {
	alpinePkgs := types.Packages{
		{
			ID:         "alpine-baselayout@3.2.0-r3",
			Name:       "alpine-baselayout",
			Version:    "3.2.0-r3",
			SrcName:    "alpine-baselayout",
			SrcVersion: "3.2.0-r3",
			Licenses:   []string{"GPL-2.0-only"},
			Maintainer: "Natanael Copa <ncopa@alpinelinux.org>",
			Digest:     "sha1:8f373f5b329c3aaf136eb30c63a387661ee0f3d0",
			DependsOn: []string{
				"busybox@1.31.1-r9",
				"musl@1.1.24-r2",
			},
			Arch: "x86_64",
			InstalledFiles: []string{
				"etc/hosts",
				"etc/sysctl.conf",
				"etc/group",
				"etc/protocols",
				"etc/fstab",
				"etc/mtab",
				"etc/profile",
				"etc/shells",
				"etc/motd",
				"etc/inittab",
				"etc/hostname",
				"etc/modules",
				"etc/services",
				"etc/shadow",
				"etc/passwd",
				"etc/profile.d/locale",
				"etc/profile.d/color_prompt",
				"etc/sysctl.d/00-alpine.conf",
				"etc/modprobe.d/i386.conf",
				"etc/modprobe.d/blacklist.conf",
				"etc/modprobe.d/aliases.conf",
				"etc/modprobe.d/kms.conf",
				"etc/crontabs/root",
				"sbin/mkmntdirs",
				"var/run",
				"var/spool/mail",
				"var/spool/cron/crontabs",
			},
		},
		{
			ID:         "alpine-keys@2.1-r2",
			Name:       "alpine-keys",
			Version:    "2.1-r2",
			SrcName:    "alpine-keys",
			SrcVersion: "2.1-r2",
			Licenses:   []string{"MIT"},
			Maintainer: "Natanael Copa <ncopa@alpinelinux.org>",
			Arch:       "x86_64",
			Digest:     "sha1:64929f85b7f8b4adbb664d905410312936b79d9b",
			InstalledFiles: []string{
				"etc/apk/keys/alpine-devel@lists.alpinelinux.org-5243ef4b.rsa.pub",
				"etc/apk/keys/alpine-devel@lists.alpinelinux.org-5261cecb.rsa.pub",
				"etc/apk/keys/alpine-devel@lists.alpinelinux.org-4a6a0840.rsa.pub",
				"usr/share/apk/keys/alpine-devel@lists.alpinelinux.org-524d27bb.rsa.pub",
				"usr/share/apk/keys/alpine-devel@lists.alpinelinux.org-5243ef4b.rsa.pub",
				"usr/share/apk/keys/alpine-devel@lists.alpinelinux.org-5261cecb.rsa.pub",
				"usr/share/apk/keys/alpine-devel@lists.alpinelinux.org-58cbb476.rsa.pub",
				"usr/share/apk/keys/alpine-devel@lists.alpinelinux.org-58199dcc.rsa.pub",
				"usr/share/apk/keys/alpine-devel@lists.alpinelinux.org-4a6a0840.rsa.pub",
				"usr/share/apk/keys/alpine-devel@lists.alpinelinux.org-58e4f17d.rsa.pub",
				"usr/share/apk/keys/aarch64/alpine-devel@lists.alpinelinux.org-58199dcc.rsa.pub",
				"usr/share/apk/keys/ppc64le/alpine-devel@lists.alpinelinux.org-58cbb476.rsa.pub",
				"usr/share/apk/keys/x86/alpine-devel@lists.alpinelinux.org-5243ef4b.rsa.pub",
				"usr/share/apk/keys/x86/alpine-devel@lists.alpinelinux.org-4a6a0840.rsa.pub",
				"usr/share/apk/keys/s390x/alpine-devel@lists.alpinelinux.org-58e4f17d.rsa.pub",
				"usr/share/apk/keys/armhf/alpine-devel@lists.alpinelinux.org-524d27bb.rsa.pub",
				"usr/share/apk/keys/x86_64/alpine-devel@lists.alpinelinux.org-5261cecb.rsa.pub",
				"usr/share/apk/keys/x86_64/alpine-devel@lists.alpinelinux.org-4a6a0840.rsa.pub",
			},
		},
		{
			ID:         "apk-tools@2.10.4-r3",
			Name:       "apk-tools",
			Version:    "2.10.4-r3",
			SrcName:    "apk-tools",
			SrcVersion: "2.10.4-r3",
			Licenses:   []string{"GPL-2.0-only"},
			Maintainer: "Natanael Copa <ncopa@alpinelinux.org>",
			Digest:     "sha1:b15ad0c90e4493dfdc948d6b90a8e020da8936ef",
			DependsOn: []string{
				"libcrypto1.1@1.1.1d-r3",
				"libssl1.1@1.1.1d-r3",
				"musl@1.1.24-r2",
				"zlib@1.2.11-r3",
			},
			Arch: "x86_64",
			InstalledFiles: []string{
				"sbin/apk",
			},
		},
		{
			ID:         "busybox@1.31.1-r9",
			Name:       "busybox",
			Version:    "1.31.1-r9",
			SrcName:    "busybox",
			SrcVersion: "1.31.1-r9",
			Licenses:   []string{"GPL-2.0-only"},
			Maintainer: "Natanael Copa <ncopa@alpinelinux.org>",
			Digest:     "sha1:a457703d71654811ea28d8d27a5cfc49ece27b34",
			DependsOn: []string{
				"musl@1.1.24-r2",
			},
			Arch: "x86_64",
			InstalledFiles: []string{
				"bin/busybox",
				"bin/sh",
				"etc/securetty",
				"etc/udhcpd.conf",
				"etc/logrotate.d/acpid",
				"etc/network/if-up.d/dad",
				"usr/share/udhcpc/default.script",
			},
		},
		{
			ID:         "ca-certificates-cacert@20191127-r1",
			Name:       "ca-certificates-cacert",
			Version:    "20191127-r1",
			SrcName:    "ca-certificates",
			SrcVersion: "20191127-r1",
			Licenses: []string{
				"MPL-2.0",
				"GPL-2.0-or-later",
			},
			Maintainer: "Natanael Copa <ncopa@alpinelinux.org>",
			Arch:       "x86_64",
			Digest:     "sha1:3aeb8a90d7179d2a187782e980a964494e08c5fb",
			InstalledFiles: []string{
				"etc/ssl/cert.pem",
			},
		},
		{
			ID:         "libc-utils@0.7.2-r0",
			Name:       "libc-utils",
			Version:    "0.7.2-r0",
			SrcName:    "libc-dev",
			SrcVersion: "0.7.2-r0",
			Licenses:   []string{"BSD-3-Clause"},
			Maintainer: "Natanael Copa <ncopa@alpinelinux.org>",
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
			Maintainer: "Timo Teras <timo.teras@iki.fi>",
			Digest:     "sha1:dd8fb9a3cce7b2bcf954271da62fb85dac2b106a",
			DependsOn: []string{
				"musl@1.1.24-r2",
			},
			Arch: "x86_64",
			InstalledFiles: []string{
				"etc/ssl/openssl.cnf.dist",
				"etc/ssl/ct_log_list.cnf",
				"etc/ssl/ct_log_list.cnf.dist",
				"etc/ssl/openssl.cnf",
				"etc/ssl/misc/CA.pl",
				"etc/ssl/misc/tsget.pl",
				"etc/ssl/misc/tsget",
				"lib/libcrypto.so.1.1",
				"usr/lib/libcrypto.so.1.1",
				"usr/lib/engines-1.1/capi.so",
				"usr/lib/engines-1.1/padlock.so",
				"usr/lib/engines-1.1/afalg.so",
			},
		},
		{
			ID:         "libssl1.1@1.1.1d-r3",
			Name:       "libssl1.1",
			Version:    "1.1.1d-r3",
			SrcName:    "openssl",
			SrcVersion: "1.1.1d-r3",
			Licenses:   []string{"OpenSSL"},
			Maintainer: "Timo Teras <timo.teras@iki.fi>",
			Digest:     "sha1:938d46e41b3e56b339a3aeb2d02fad3d75728f35",
			DependsOn: []string{
				"libcrypto1.1@1.1.1d-r3",
				"musl@1.1.24-r2",
			},
			Arch: "x86_64",
			InstalledFiles: []string{
				"lib/libssl.so.1.1",
				"usr/lib/libssl.so.1.1",
			},
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
			InstalledFiles: []string{
				"usr/lib/libtls-standalone.so.1.0.0",
				"usr/lib/libtls-standalone.so.1",
			},
		},
		{
			ID:         "musl@1.1.24-r2",
			Name:       "musl",
			Version:    "1.1.24-r2",
			SrcName:    "musl",
			SrcVersion: "1.1.24-r2",
			Licenses:   []string{"MIT"},
			Maintainer: "Timo Teräs <timo.teras@iki.fi>",
			Arch:       "x86_64",
			Digest:     "sha1:cb2316a189ebee5282c4a9bd98794cc2477a74c6",
			InstalledFiles: []string{
				"lib/libc.musl-x86_64.so.1",
				"lib/ld-musl-x86_64.so.1",
			},
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
				"GPL-2.0-or-later",
			},
			Maintainer: "Timo Teräs <timo.teras@iki.fi>",
			Digest:     "sha1:6d3b45e79dbab444ca7cbfa59e2833203be6fb6a",
			DependsOn: []string{
				"musl@1.1.24-r2",
				"scanelf@1.2.4-r0",
			},
			Arch: "x86_64",
			InstalledFiles: []string{
				"sbin/ldconfig",
				"usr/bin/iconv",
				"usr/bin/ldd",
				"usr/bin/getconf",
				"usr/bin/getent",
			},
		},
		{
			ID:         "scanelf@1.2.4-r0",
			Name:       "scanelf",
			Version:    "1.2.4-r0",
			SrcName:    "pax-utils",
			SrcVersion: "1.2.4-r0",
			Licenses:   []string{"GPL-2.0-only"},
			Maintainer: "Natanael Copa <ncopa@alpinelinux.org>",
			Digest:     "sha1:d6147beb32bff803b5d9f83a3bec7ab319087185",
			DependsOn: []string{
				"musl@1.1.24-r2",
			},
			Arch: "x86_64",
			InstalledFiles: []string{
				"usr/bin/scanelf",
			},
		},
		{
			ID:         "ssl_client@1.31.1-r9",
			Name:       "ssl_client",
			Version:    "1.31.1-r9",
			SrcName:    "busybox",
			SrcVersion: "1.31.1-r9",
			Licenses:   []string{"GPL-2.0-only"},
			Maintainer: "Natanael Copa <ncopa@alpinelinux.org>",
			Digest:     "sha1:3b685152af320120ae8941c740d3376b54e43c10",
			DependsOn: []string{
				"libtls-standalone@2.9.1-r0",
				"musl@1.1.24-r2",
			},
			Arch: "x86_64",
			InstalledFiles: []string{
				"usr/bin/ssl_client",
			},
		},
		{
			ID:         "zlib@1.2.11-r3",
			Name:       "zlib",
			Version:    "1.2.11-r3",
			SrcName:    "zlib",
			SrcVersion: "1.2.11-r3",
			Licenses:   []string{"Zlib"},
			Maintainer: "Natanael Copa <ncopa@alpinelinux.org>",
			Digest:     "sha1:acca078ee8baa93e005f57b2fae359c1efd443cd",
			DependsOn: []string{
				"musl@1.1.24-r2",
			},
			Arch: "x86_64",
			InstalledFiles: []string{
				"lib/libz.so.1.2.11",
				"lib/libz.so.1",
			},
		},
	}

	tests := []struct {
		name         string
		imagePath    string
		artifactOpt  artifact.Option
		setupCache   func(t *testing.T) cache.Cache
		wantArtifact cachetest.WantArtifact
		wantBlobs    []cachetest.WantBlob
		want         artifact.Reference
		wantErr      string
	}{
		{
			name:      "happy path",
			imagePath: "../../test/testdata/alpine-311.tar.gz",
			artifactOpt: artifact.Option{
				LicenseScannerOption: analyzer.LicenseScannerOption{Full: true},
				ImageOption:          types.ImageOptions{MaxImageSize: units.GB},
			},
			wantBlobs: []cachetest.WantBlob{
				{
					ID: alpineBaseLayerID,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Size:          5861888,
						Digest:        "",
						DiffID:        alpineBaseLayerDiffID,
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
			},
			wantArtifact: cachetest.WantArtifact{
				ID: alpineArtifactID,
				ArtifactInfo: types.ArtifactInfo{
					SchemaVersion: types.ArtifactJSONSchemaVersion,
					Architecture:  "amd64",
					Created:       time.Date(2020, 3, 23, 21, 19, 34, 196162891, time.UTC),
					DockerVersion: "18.09.7",
					OS:            "linux",
				},
			},
			want: artifact.Reference{
				Name:    "../../test/testdata/alpine-311.tar.gz",
				Type:    types.TypeContainerImage,
				ID:      alpineArtifactID,
				BlobIDs: []string{alpineBaseLayerID},
				ImageMetadata: artifact.ImageMetadata{
					ID: composerImageID,
					DiffIDs: []string{
						alpineBaseLayerDiffID,
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
			setupCache: func(t *testing.T) cache.Cache {
				c := cache.NewMemoryCache()
				require.NoError(t, c.PutArtifact(t.Context(), "sha256:0bebf0773ffd87baa7c64fbdbdf79a24ae125e3f99a8adebe52d1ccbe6bed16b", types.ArtifactInfo{
					SchemaVersion: types.ArtifactJSONSchemaVersion,
				}))
				return c
			},
			wantArtifact: cachetest.WantArtifact{
				ID: "sha256:0bebf0773ffd87baa7c64fbdbdf79a24ae125e3f99a8adebe52d1ccbe6bed16b",
				ArtifactInfo: types.ArtifactInfo{
					SchemaVersion: types.ArtifactJSONSchemaVersion,
				},
			},
			wantBlobs: []cachetest.WantBlob{
				{
					ID: "sha256:f2a647dcf780c603f864e491dca1a042b1e98062b530c813681d1bb4a85bcb18",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Size:          3061760,
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
									{Name: "GPL-2.0-or-later"},
								},
								PkgName: "base-files",
							},
							{
								Type:     types.LicenseTypeDpkg,
								FilePath: "usr/share/doc/ca-certificates/copyright",
								Findings: []types.LicenseFinding{
									{Name: "GPL-2.0-or-later"},
									{Name: "GPL-2.0-only"},
									{Name: "MPL-2.0"},
								},
								PkgName: "ca-certificates",
							},
							{
								Type:     types.LicenseTypeDpkg,
								FilePath: "usr/share/doc/netbase/copyright",
								Findings: []types.LicenseFinding{
									{Name: "GPL-2.0-only"},
								},
								PkgName: "netbase",
							},
						},
					},
				},
				{
					ID: "sha256:c988cc5a0b8f3dc542c15c303d9200dee47d4fbed0e498a5bfbf3b4bef7a5af7",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Size:          15441920,
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
									{Name: "LGPL-2.1-only"},
									{Name: "GPL-2.0-only"},
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
				{
					ID: "sha256:05c19ffd5d898588400522070abd98c770b2965a7f4867d5c882c2a8783e40cc",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Size:          29696,
						Digest:        "",
						DiffID:        "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
						CreatedBy:     "COPY file:842584685f26edb24dc305d76894f51cfda2bad0c24a05e727f9d4905d184a70 in /php-app/composer.lock ",
						OpaqueDirs:    []string{"php-app/"},
						Applications: []types.Application{
							{
								Type:     "composer",
								FilePath: "php-app/composer.lock",
								Packages: types.Packages{
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
					},
				},
				{
					ID: "sha256:c737743c0f8b35906650a02125f05c8b35916c0febf64984f4dfaacd0f72509d",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Size:          6656,
						Digest:        "",
						DiffID:        "sha256:a4595c43a874856bf95f3bfc4fbf78bbaa04c92c726276d4f64193a47ced0566",
						CreatedBy:     "COPY file:c6d0373d380252b91829a5bb3c81d5b1afa574c91cef7752d18170a231c31f6d in /ruby-app/Gemfile.lock ",
						OpaqueDirs: []string{
							"ruby-app/",
						},
						Applications: []types.Application{
							{
								Type:     "bundler",
								FilePath: "ruby-app/Gemfile.lock",
								Packages: types.Packages{
									{
										ID:           "dotenv@2.7.2",
										Name:         "dotenv",
										Version:      "2.7.2",
										Indirect:     false,
										Relationship: types.RelationshipDirect,
										DependsOn:    []string(nil),
										Locations: []types.Location{
											{
												StartLine: 51,
												EndLine:   51,
											},
										},
									},
									{
										ID:           "faker@1.9.3",
										Name:         "faker",
										Version:      "1.9.3",
										Indirect:     false,
										Relationship: types.RelationshipDirect,
										DependsOn:    []string{"i18n@1.6.0"},
										Locations: []types.Location{
											{
												StartLine: 53,
												EndLine:   53,
											},
										},
									},
									{
										ID:           "json@2.2.0",
										Name:         "json",
										Version:      "2.2.0",
										Indirect:     false,
										Relationship: types.RelationshipDirect,
										DependsOn:    []string(nil),
										Locations: []types.Location{
											{
												StartLine: 60,
												EndLine:   60,
											},
										},
									},
									{
										ID:           "pry@0.12.2",
										Name:         "pry",
										Version:      "0.12.2",
										Indirect:     false,
										Relationship: types.RelationshipDirect,
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
										ID:           "rails@5.2.0",
										Name:         "rails",
										Version:      "5.2.0",
										Indirect:     false,
										Relationship: types.RelationshipDirect,
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
										ID:           "rubocop@0.67.2",
										Name:         "rubocop",
										Version:      "0.67.2",
										Indirect:     false,
										Relationship: types.RelationshipDirect,
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
										ID:           "actioncable@5.2.3",
										Name:         "actioncable",
										Version:      "5.2.3",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
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
										ID:           "actionmailer@5.2.3",
										Name:         "actionmailer",
										Version:      "5.2.3",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
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
										ID:           "actionpack@5.2.3",
										Name:         "actionpack",
										Version:      "5.2.3",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
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
										ID:           "actionview@5.2.3",
										Name:         "actionview",
										Version:      "5.2.3",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
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
										ID:           "activejob@5.2.3",
										Name:         "activejob",
										Version:      "5.2.3",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
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
										ID:           "activemodel@5.2.3",
										Name:         "activemodel",
										Version:      "5.2.3",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
										DependsOn:    []string{"activesupport@5.2.3"},
										Locations: []types.Location{
											{
												StartLine: 30,
												EndLine:   30,
											},
										},
									},
									{
										ID:           "activerecord@5.2.3",
										Name:         "activerecord",
										Version:      "5.2.3",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
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
										ID:           "activestorage@5.2.3",
										Name:         "activestorage",
										Version:      "5.2.3",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
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
										ID:           "activesupport@5.2.3",
										Name:         "activesupport",
										Version:      "5.2.3",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
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
										ID:           "arel@9.0.0",
										Name:         "arel",
										Version:      "9.0.0",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
										DependsOn:    []string(nil),
										Locations: []types.Location{
											{
												StartLine: 45,
												EndLine:   45,
											},
										},
									},
									{
										ID:           "ast@2.4.0",
										Name:         "ast",
										Version:      "2.4.0",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
										DependsOn:    []string(nil),
										Locations: []types.Location{
											{
												StartLine: 46,
												EndLine:   46,
											},
										},
									},
									{
										ID:           "builder@3.2.3",
										Name:         "builder",
										Version:      "3.2.3",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
										DependsOn:    []string(nil),
										Locations: []types.Location{
											{
												StartLine: 47,
												EndLine:   47,
											},
										},
									},
									{
										ID:           "coderay@1.1.2",
										Name:         "coderay",
										Version:      "1.1.2",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
										DependsOn:    []string(nil),
										Locations: []types.Location{
											{
												StartLine: 48,
												EndLine:   48,
											},
										},
									},
									{
										ID:           "concurrent-ruby@1.1.5",
										Name:         "concurrent-ruby",
										Version:      "1.1.5",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
										DependsOn:    []string(nil),
										Locations: []types.Location{
											{
												StartLine: 49,
												EndLine:   49,
											},
										},
									},
									{
										ID:           "crass@1.0.4",
										Name:         "crass",
										Version:      "1.0.4",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
										DependsOn:    []string(nil),
										Locations: []types.Location{
											{
												StartLine: 50,
												EndLine:   50,
											},
										},
									},
									{
										ID:           "erubi@1.8.0",
										Name:         "erubi",
										Version:      "1.8.0",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
										DependsOn:    []string(nil),
										Locations: []types.Location{
											{
												StartLine: 52,
												EndLine:   52,
											},
										},
									},
									{
										ID:           "globalid@0.4.2",
										Name:         "globalid",
										Version:      "0.4.2",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
										DependsOn:    []string{"activesupport@5.2.3"},
										Locations: []types.Location{
											{
												StartLine: 55,
												EndLine:   55,
											},
										},
									},
									{
										ID:           "i18n@1.6.0",
										Name:         "i18n",
										Version:      "1.6.0",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
										DependsOn:    []string{"concurrent-ruby@1.1.5"},
										Locations: []types.Location{
											{
												StartLine: 57,
												EndLine:   57,
											},
										},
									},
									{
										ID:           "jaro_winkler@1.5.2",
										Name:         "jaro_winkler",
										Version:      "1.5.2",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
										DependsOn:    []string(nil),
										Locations: []types.Location{
											{
												StartLine: 59,
												EndLine:   59,
											},
										},
									},
									{
										ID:           "loofah@2.2.3",
										Name:         "loofah",
										Version:      "2.2.3",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
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
										ID:           "mail@2.7.1",
										Name:         "mail",
										Version:      "2.7.1",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
										DependsOn:    []string{"mini_mime@1.0.1"},
										Locations: []types.Location{
											{
												StartLine: 64,
												EndLine:   64,
											},
										},
									},
									{
										ID:           "marcel@0.3.3",
										Name:         "marcel",
										Version:      "0.3.3",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
										DependsOn:    []string{"mimemagic@0.3.3"},
										Locations: []types.Location{
											{
												StartLine: 66,
												EndLine:   66,
											},
										},
									},
									{
										ID:           "method_source@0.9.2",
										Name:         "method_source",
										Version:      "0.9.2",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
										DependsOn:    []string(nil),
										Locations: []types.Location{
											{
												StartLine: 68,
												EndLine:   68,
											},
										},
									},
									{
										ID:           "mimemagic@0.3.3",
										Name:         "mimemagic",
										Version:      "0.3.3",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
										DependsOn:    []string(nil),
										Locations: []types.Location{
											{
												StartLine: 69,
												EndLine:   69,
											},
										},
									},
									{
										ID:           "mini_mime@1.0.1",
										Name:         "mini_mime",
										Version:      "1.0.1",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
										DependsOn:    []string(nil),
										Locations: []types.Location{
											{
												StartLine: 70,
												EndLine:   70,
											},
										},
									},
									{
										ID:           "mini_portile2@2.4.0",
										Name:         "mini_portile2",
										Version:      "2.4.0",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
										DependsOn:    []string(nil),
										Locations: []types.Location{
											{
												StartLine: 71,
												EndLine:   71,
											},
										},
									},
									{
										ID:           "minitest@5.11.3",
										Name:         "minitest",
										Version:      "5.11.3",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
										DependsOn:    []string(nil),
										Locations: []types.Location{
											{
												StartLine: 72,
												EndLine:   72,
											},
										},
									},
									{
										ID:           "nio4r@2.3.1",
										Name:         "nio4r",
										Version:      "2.3.1",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
										DependsOn:    []string(nil),
										Locations: []types.Location{
											{
												StartLine: 73,
												EndLine:   73,
											},
										},
									},
									{
										ID:           "nokogiri@1.10.3",
										Name:         "nokogiri",
										Version:      "1.10.3",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
										DependsOn:    []string{"mini_portile2@2.4.0"},
										Locations: []types.Location{
											{
												StartLine: 74,
												EndLine:   74,
											},
										},
									},
									{
										ID:           "parallel@1.17.0",
										Name:         "parallel",
										Version:      "1.17.0",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
										DependsOn:    []string(nil),
										Locations: []types.Location{
											{
												StartLine: 76,
												EndLine:   76,
											},
										},
									},
									{
										ID:           "parser@2.6.3.0",
										Name:         "parser",
										Version:      "2.6.3.0",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
										DependsOn:    []string{"ast@2.4.0"},
										Locations: []types.Location{
											{
												StartLine: 77,
												EndLine:   77,
											},
										},
									},
									{
										ID:           "psych@3.1.0",
										Name:         "psych",
										Version:      "3.1.0",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
										DependsOn:    []string(nil),
										Locations: []types.Location{
											{
												StartLine: 82,
												EndLine:   82,
											},
										},
									},
									{
										ID:           "rack@2.0.7",
										Name:         "rack",
										Version:      "2.0.7",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
										DependsOn:    []string(nil),
										Locations: []types.Location{
											{
												StartLine: 83,
												EndLine:   83,
											},
										},
									},
									{
										ID:           "rack-test@1.1.0",
										Name:         "rack-test",
										Version:      "1.1.0",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
										DependsOn:    []string{"rack@2.0.7"},
										Locations: []types.Location{
											{
												StartLine: 84,
												EndLine:   84,
											},
										},
									},
									{
										ID:           "rails-dom-testing@2.0.3",
										Name:         "rails-dom-testing",
										Version:      "2.0.3",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
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
										ID:           "rails-html-sanitizer@1.0.3",
										Name:         "rails-html-sanitizer",
										Version:      "1.0.3",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
										DependsOn:    []string{"loofah@2.2.3"},
										Locations: []types.Location{
											{
												StartLine: 102,
												EndLine:   102,
											},
										},
									},
									{
										ID:           "railties@5.2.3",
										Name:         "railties",
										Version:      "5.2.3",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
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
										ID:           "rainbow@3.0.0",
										Name:         "rainbow",
										Version:      "3.0.0",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
										DependsOn:    []string(nil),
										Locations: []types.Location{
											{
												StartLine: 110,
												EndLine:   110,
											},
										},
									},
									{
										ID:           "rake@12.3.2",
										Name:         "rake",
										Version:      "12.3.2",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
										DependsOn:    []string(nil),
										Locations: []types.Location{
											{
												StartLine: 111,
												EndLine:   111,
											},
										},
									},
									{
										ID:           "ruby-progressbar@1.10.0",
										Name:         "ruby-progressbar",
										Version:      "1.10.0",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
										DependsOn:    []string(nil),
										Locations: []types.Location{
											{
												StartLine: 120,
												EndLine:   120,
											},
										},
									},
									{
										ID:           "sprockets@3.7.2",
										Name:         "sprockets",
										Version:      "3.7.2",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
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
										ID:           "sprockets-rails@3.2.1",
										Name:         "sprockets-rails",
										Version:      "3.2.1",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
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
										ID:           "thor@0.20.3",
										Name:         "thor",
										Version:      "0.20.3",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
										DependsOn:    []string(nil),
										Locations: []types.Location{
											{
												StartLine: 128,
												EndLine:   128,
											},
										},
									},
									{
										ID:           "thread_safe@0.3.6",
										Name:         "thread_safe",
										Version:      "0.3.6",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
										DependsOn:    []string(nil),
										Locations: []types.Location{
											{
												StartLine: 129,
												EndLine:   129,
											},
										},
									},
									{
										ID:           "tzinfo@1.2.5",
										Name:         "tzinfo",
										Version:      "1.2.5",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
										DependsOn:    []string{"thread_safe@0.3.6"},
										Locations: []types.Location{
											{
												StartLine: 130,
												EndLine:   130,
											},
										},
									},
									{
										ID:           "unicode-display_width@1.5.0",
										Name:         "unicode-display_width",
										Version:      "1.5.0",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
										DependsOn:    []string(nil),
										Locations: []types.Location{
											{
												StartLine: 132,
												EndLine:   132,
											},
										},
									},
									{
										ID:           "websocket-driver@0.7.0",
										Name:         "websocket-driver",
										Version:      "0.7.0",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
										DependsOn:    []string{"websocket-extensions@0.1.3"},
										Locations: []types.Location{
											{
												StartLine: 133,
												EndLine:   133,
											},
										},
									},
									{
										ID:           "websocket-extensions@0.1.3",
										Name:         "websocket-extensions",
										Version:      "0.1.3",
										Indirect:     true,
										Relationship: types.RelationshipIndirect,
										DependsOn:    []string(nil),
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
					},
				},
			},
			want: artifact.Reference{
				Name: "../../test/testdata/vuln-image.tar.gz",
				Type: types.TypeContainerImage,
				ID:   "sha256:0bebf0773ffd87baa7c64fbdbdf79a24ae125e3f99a8adebe52d1ccbe6bed16b",
				BlobIDs: []string{
					"sha256:f2a647dcf780c603f864e491dca1a042b1e98062b530c813681d1bb4a85bcb18",
					"sha256:c988cc5a0b8f3dc542c15c303d9200dee47d4fbed0e498a5bfbf3b4bef7a5af7",
					"sha256:05c19ffd5d898588400522070abd98c770b2965a7f4867d5c882c2a8783e40cc",
					"sha256:c737743c0f8b35906650a02125f05c8b35916c0febf64984f4dfaacd0f72509d",
				},
				ImageMetadata: artifact.ImageMetadata{
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
								Created:    v1.Time{Time: time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)},
								CreatedBy:  "bazel build ...",
								EmptyLayer: false,
							},
							{
								Author:     "Bazel",
								Created:    v1.Time{Time: time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)},
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
			setupCache: func(t *testing.T) cache.Cache {
				c := cache.NewMemoryCache()
				require.NoError(t, c.PutArtifact(t.Context(), "sha256:0bebf0773ffd87baa7c64fbdbdf79a24ae125e3f99a8adebe52d1ccbe6bed16b", types.ArtifactInfo{
					SchemaVersion: types.ArtifactJSONSchemaVersion,
				}))
				return c
			},
			wantArtifact: cachetest.WantArtifact{
				ID: "sha256:0bebf0773ffd87baa7c64fbdbdf79a24ae125e3f99a8adebe52d1ccbe6bed16b",
				ArtifactInfo: types.ArtifactInfo{
					SchemaVersion: types.ArtifactJSONSchemaVersion,
				},
			},
			wantBlobs: []cachetest.WantBlob{
				{
					ID: "sha256:48b4a983ef1ec8f0d19934ccf7fca3d2114466ad32207e16371620628f149984",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Size:          3061760,
						Digest:        "",
						DiffID:        "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
						CreatedBy:     "bazel build ...",
					},
				},
				{
					ID: "sha256:a4d2820bd2c076f6153a9053843d4a56d31147ce486ec5e4a2c0405cec506d6c",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Size:          15441920,
						Digest:        "",
						DiffID:        "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
						CreatedBy:     "bazel build ...",
					},
				},
				{
					ID: "sha256:c5fa5e736cee843c563c222963eb89fc775f0620020ff9d51d5e5db8ef62eec4",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Size:          29696,
						Digest:        "",
						DiffID:        "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
						CreatedBy:     "COPY file:842584685f26edb24dc305d76894f51cfda2bad0c24a05e727f9d4905d184a70 in /php-app/composer.lock ",
						OpaqueDirs:    []string{"php-app/"},
					},
				},
				{
					ID: "sha256:7e223b95d6d589cdb196e29ef6c6ac0acdd2c471350dd9880a420b4249f6e7bb",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Size:          6656,
						Digest:        "",
						DiffID:        "sha256:a4595c43a874856bf95f3bfc4fbf78bbaa04c92c726276d4f64193a47ced0566",
						CreatedBy:     "COPY file:c6d0373d380252b91829a5bb3c81d5b1afa574c91cef7752d18170a231c31f6d in /ruby-app/Gemfile.lock ",
						OpaqueDirs:    []string{"ruby-app/"},
					},
				},
			},
			want: artifact.Reference{
				Name: "../../test/testdata/vuln-image.tar.gz",
				Type: types.TypeContainerImage,
				ID:   "sha256:0bebf0773ffd87baa7c64fbdbdf79a24ae125e3f99a8adebe52d1ccbe6bed16b",
				BlobIDs: []string{
					"sha256:48b4a983ef1ec8f0d19934ccf7fca3d2114466ad32207e16371620628f149984",
					"sha256:a4d2820bd2c076f6153a9053843d4a56d31147ce486ec5e4a2c0405cec506d6c",
					"sha256:c5fa5e736cee843c563c222963eb89fc775f0620020ff9d51d5e5db8ef62eec4",
					"sha256:7e223b95d6d589cdb196e29ef6c6ac0acdd2c471350dd9880a420b4249f6e7bb",
				},
				ImageMetadata: artifact.ImageMetadata{
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
								Created:    v1.Time{Time: time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)},
								CreatedBy:  "bazel build ...",
								Comment:    "",
								EmptyLayer: false,
							},
							{
								Author:     "Bazel",
								Created:    v1.Time{Time: time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)},
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
			setupCache: func(_ *testing.T) cache.Cache {
				return cachetest.NewErrorCache(cachetest.ErrorCacheOptions{
					MissingBlobs: true,
				})
			},
			wantErr: "MissingBlobs failed",
		},
		{
			name:      "sad path, PutBlob returns an error",
			imagePath: "../../test/testdata/alpine-311.tar.gz",
			setupCache: func(_ *testing.T) cache.Cache {
				return cachetest.NewErrorCache(cachetest.ErrorCacheOptions{
					PutBlob: true,
				})
			},
			wantErr: "PutBlob failed",
		},
		{
			name:      "sad path, PutBlob returns an error with multiple layers",
			imagePath: "../../test/testdata/vuln-image.tar.gz",
			setupCache: func(_ *testing.T) cache.Cache {
				return cachetest.NewErrorCache(cachetest.ErrorCacheOptions{
					PutBlob: true,
				})
			},
			wantErr: "PutBlob failed",
		},
		{
			name:      "sad path, PutArtifact returns an error",
			imagePath: "../../test/testdata/alpine-311.tar.gz",
			setupCache: func(_ *testing.T) cache.Cache {
				return cachetest.NewErrorCache(cachetest.ErrorCacheOptions{
					PutArtifact: true,
				})
			},
			wantErr: "PutArtifact failed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := cachetest.NewCache(t, tt.setupCache)

			img, err := image.NewArchiveImage(tt.imagePath)
			require.NoError(t, err)

			a, err := image2.NewArtifact(img, c, tt.artifactOpt)
			require.NoError(t, err)

			got, err := a.Inspect(t.Context())
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr, tt.name)
				return
			}
			defer a.Clean(got)

			require.NoError(t, err, tt.name)
			assert.Equal(t, tt.want, got)

			cachetest.AssertArtifact(t, c, tt.wantArtifact)
			cachetest.AssertBlobs(t, c, tt.wantBlobs)
		})
	}
}

func TestArtifact_InspectWithMaxImageSize(t *testing.T) {
	randomImage, err := random.Image(1000, 2, random.WithSource(rand.NewSource(0)))
	require.NoError(t, err)

	img := &fakeImage{Image: randomImage}
	c := cachetest.NewCache(t, nil)

	tests := []struct {
		name        string
		artifactOpt artifact.Option
		wantErr     string
	}{
		{
			name: "compressed image size is larger than the maximum",
			artifactOpt: artifact.Option{
				ImageOption: types.ImageOptions{MaxImageSize: units.KB * 1},
			},
			wantErr: "compressed image size 2.44kB exceeds maximum allowed size 1kB",
		},
		{
			name: "uncompressed layers size is larger than the maximum",
			artifactOpt: artifact.Option{
				ImageOption: types.ImageOptions{MaxImageSize: units.KB * 3},
			},
			wantErr: "uncompressed layers size 5.12kB exceeds maximum allowed size 3kB",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			artifact, err := image2.NewArtifact(img, c, tt.artifactOpt)
			require.NoError(t, err)

			_, err = artifact.Inspect(t.Context())
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}
