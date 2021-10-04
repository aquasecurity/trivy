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

	"github.com/aquasecurity/fanal/analyzer"
	_ "github.com/aquasecurity/fanal/analyzer/all"
	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/artifact"
	image2 "github.com/aquasecurity/fanal/artifact/image"
	"github.com/aquasecurity/fanal/cache"
	_ "github.com/aquasecurity/fanal/hook/all"
	"github.com/aquasecurity/fanal/image"
	"github.com/aquasecurity/fanal/types"
	depTypes "github.com/aquasecurity/go-dep-parser/pkg/types"
)

func TestArtifact_Inspect(t *testing.T) {
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
			missingBlobsExpectation: cache.ArtifactCacheMissingBlobsExpectation{
				Args: cache.ArtifactCacheMissingBlobsArgs{
					ArtifactID: "sha256:059741cfbdc039e88e337d621e57e03e99b0e0a75df32f2027ebef13f839af65",
					BlobIDs:    []string{"sha256:eb524f2e4340057b02ef7e2b219fa362fa309d4aaa52f3c1ce5095e5555900fc"},
				},
				Returns: cache.ArtifactCacheMissingBlobsReturns{
					MissingArtifact: true,
					MissingBlobIDs:  []string{"sha256:eb524f2e4340057b02ef7e2b219fa362fa309d4aaa52f3c1ce5095e5555900fc"},
				},
			},
			putBlobExpectations: []cache.ArtifactCachePutBlobExpectation{
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:eb524f2e4340057b02ef7e2b219fa362fa309d4aaa52f3c1ce5095e5555900fc",
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
						ArtifactID: "sha256:059741cfbdc039e88e337d621e57e03e99b0e0a75df32f2027ebef13f839af65",
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
				ID:      "sha256:059741cfbdc039e88e337d621e57e03e99b0e0a75df32f2027ebef13f839af65",
				BlobIDs: []string{"sha256:eb524f2e4340057b02ef7e2b219fa362fa309d4aaa52f3c1ce5095e5555900fc"},
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
						OS:     "linux",
						RootFS: v1.RootFS{Type: "layers", DiffIDs: []v1.Hash{v1.Hash{Algorithm: "sha256", Hex: "beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203"}}},
						Config: v1.Config{
							Cmd:      []string{"/bin/sh"},
							Env:      []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
							Hostname: "", Image: "sha256:74df73bb19fbfc7fb5ab9a8234b3d98ee2fb92df5b824496679802685205ab8c",
							ArgsEscaped: true,
						},
					},
				},
			},
		},
		{
			name:      "happy path: include lock files",
			imagePath: "../../test/testdata/vuln-image.tar.gz",
			missingBlobsExpectation: cache.ArtifactCacheMissingBlobsExpectation{
				Args: cache.ArtifactCacheMissingBlobsArgs{
					ArtifactID: "sha256:a646bb11d39c149d4aaf9b888233048e0848304e5abd75667ea6f21d540d800c",
					BlobIDs: []string{
						"sha256:d279157a8123412d989825df8022a0a72ab5cbb60eab5f06f3803debd56132fe",
						"sha256:ae345588bd561e54a798d8150d474079b7935e461b3ec55b4be3744e6b68c9f1",
						"sha256:679c0e06fe5f0879b7e214a46b7c545bd99539e78783c1cd771717bf7acaf487",
						"sha256:3138db263af9cf54afe4dd52fbc443e33a1841f60ec24fa896c04f602d075436",
					},
				},
				Returns: cache.ArtifactCacheMissingBlobsReturns{
					MissingBlobIDs: []string{
						"sha256:d279157a8123412d989825df8022a0a72ab5cbb60eab5f06f3803debd56132fe",
						"sha256:ae345588bd561e54a798d8150d474079b7935e461b3ec55b4be3744e6b68c9f1",
						"sha256:679c0e06fe5f0879b7e214a46b7c545bd99539e78783c1cd771717bf7acaf487",
						"sha256:3138db263af9cf54afe4dd52fbc443e33a1841f60ec24fa896c04f602d075436",
					},
				},
			},
			putBlobExpectations: []cache.ArtifactCachePutBlobExpectation{
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:d279157a8123412d989825df8022a0a72ab5cbb60eab5f06f3803debd56132fe",
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
						BlobID: "sha256:ae345588bd561e54a798d8150d474079b7935e461b3ec55b4be3744e6b68c9f1",
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
						BlobID: "sha256:679c0e06fe5f0879b7e214a46b7c545bd99539e78783c1cd771717bf7acaf487",
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
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:3138db263af9cf54afe4dd52fbc443e33a1841f60ec24fa896c04f602d075436",
						BlobInfo: types.BlobInfo{
							SchemaVersion: 1,
							Digest:        "",
							DiffID:        "sha256:a4595c43a874856bf95f3bfc4fbf78bbaa04c92c726276d4f64193a47ced0566",
							Applications: []types.Application{{Type: types.Bundler, FilePath: "ruby-app/Gemfile.lock",
								Libraries: []types.LibraryInfo{
									{Library: depTypes.Library{Name: "actioncable", Version: "5.2.3"}},
									{Library: depTypes.Library{Name: "actionmailer", Version: "5.2.3"}},
									{Library: depTypes.Library{Name: "actionpack", Version: "5.2.3"}},
									{Library: depTypes.Library{Name: "actionview", Version: "5.2.3"}},
									{Library: depTypes.Library{Name: "activejob", Version: "5.2.3"}},
									{Library: depTypes.Library{Name: "activemodel", Version: "5.2.3"}},
									{Library: depTypes.Library{Name: "activerecord", Version: "5.2.3"}},
									{Library: depTypes.Library{Name: "activestorage", Version: "5.2.3"}},
									{Library: depTypes.Library{Name: "activesupport", Version: "5.2.3"}},
									{Library: depTypes.Library{Name: "arel", Version: "9.0.0"}},
									{Library: depTypes.Library{Name: "ast", Version: "2.4.0"}},
									{Library: depTypes.Library{Name: "builder", Version: "3.2.3"}},
									{Library: depTypes.Library{Name: "coderay", Version: "1.1.2"}},
									{Library: depTypes.Library{Name: "concurrent-ruby", Version: "1.1.5"}},
									{Library: depTypes.Library{Name: "crass", Version: "1.0.4"}},
									{Library: depTypes.Library{Name: "dotenv", Version: "2.7.2"}},
									{Library: depTypes.Library{Name: "erubi", Version: "1.8.0"}},
									{Library: depTypes.Library{Name: "faker", Version: "1.9.3"}},
									{Library: depTypes.Library{Name: "globalid", Version: "0.4.2"}},
									{Library: depTypes.Library{Name: "i18n", Version: "1.6.0"}},
									{Library: depTypes.Library{Name: "jaro_winkler", Version: "1.5.2"}},
									{Library: depTypes.Library{Name: "json", Version: "2.2.0"}},
									{Library: depTypes.Library{Name: "loofah", Version: "2.2.3"}},
									{Library: depTypes.Library{Name: "mail", Version: "2.7.1"}},
									{Library: depTypes.Library{Name: "marcel", Version: "0.3.3"}},
									{Library: depTypes.Library{Name: "method_source", Version: "0.9.2"}},
									{Library: depTypes.Library{Name: "mimemagic", Version: "0.3.3"}},
									{Library: depTypes.Library{Name: "mini_mime", Version: "1.0.1"}},
									{Library: depTypes.Library{Name: "mini_portile2", Version: "2.4.0"}},
									{Library: depTypes.Library{Name: "minitest", Version: "5.11.3"}},
									{Library: depTypes.Library{Name: "nio4r", Version: "2.3.1"}},
									{Library: depTypes.Library{Name: "nokogiri", Version: "1.10.3"}},
									{Library: depTypes.Library{Name: "parallel", Version: "1.17.0"}},
									{Library: depTypes.Library{Name: "parser", Version: "2.6.3.0"}},
									{Library: depTypes.Library{Name: "pry", Version: "0.12.2"}},
									{Library: depTypes.Library{Name: "psych", Version: "3.1.0"}},
									{Library: depTypes.Library{Name: "rack", Version: "2.0.7"}},
									{Library: depTypes.Library{Name: "rack-test", Version: "1.1.0"}},
									{Library: depTypes.Library{Name: "rails", Version: "5.2.0"}},
									{Library: depTypes.Library{Name: "rails-dom-testing", Version: "2.0.3"}},
									{Library: depTypes.Library{Name: "rails-html-sanitizer", Version: "1.0.3"}},
									{Library: depTypes.Library{Name: "railties", Version: "5.2.3"}},
									{Library: depTypes.Library{Name: "rainbow", Version: "3.0.0"}},
									{Library: depTypes.Library{Name: "rake", Version: "12.3.2"}},
									{Library: depTypes.Library{Name: "rubocop", Version: "0.67.2"}},
									{Library: depTypes.Library{Name: "ruby-progressbar", Version: "1.10.0"}},
									{Library: depTypes.Library{Name: "sprockets", Version: "3.7.2"}},
									{Library: depTypes.Library{Name: "sprockets-rails", Version: "3.2.1"}},
									{Library: depTypes.Library{Name: "thor", Version: "0.20.3"}},
									{Library: depTypes.Library{Name: "thread_safe", Version: "0.3.6"}},
									{Library: depTypes.Library{Name: "tzinfo", Version: "1.2.5"}},
									{Library: depTypes.Library{Name: "unicode-display_width", Version: "1.5.0"}},
									{Library: depTypes.Library{Name: "websocket-driver", Version: "0.7.0"}},
									{Library: depTypes.Library{Name: "websocket-extensions", Version: "0.1.3"}},
								},
							}},
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
					"sha256:d279157a8123412d989825df8022a0a72ab5cbb60eab5f06f3803debd56132fe",
					"sha256:ae345588bd561e54a798d8150d474079b7935e461b3ec55b4be3744e6b68c9f1",
					"sha256:679c0e06fe5f0879b7e214a46b7c545bd99539e78783c1cd771717bf7acaf487",
					"sha256:3138db263af9cf54afe4dd52fbc443e33a1841f60ec24fa896c04f602d075436",
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
							Env:   []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"},
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
				DisabledAnalyzers: []analyzer.Type{analyzer.TypeDebian, analyzer.TypeDpkg, analyzer.TypeComposer, analyzer.TypeBundler},
			},
			missingBlobsExpectation: cache.ArtifactCacheMissingBlobsExpectation{
				Args: cache.ArtifactCacheMissingBlobsArgs{
					ArtifactID: "sha256:a646bb11d39c149d4aaf9b888233048e0848304e5abd75667ea6f21d540d800c",
					BlobIDs: []string{
						"sha256:2d850affad723b172fc58dac7ed833ce0582896f9154546f1eb64e6584d5a312",
						"sha256:44da28d6ef71b50c2d678b086864317da6945922c989a3393682357c5ad83153",
						"sha256:a963df97ae16e97bc451da20dcb2e19a670c8177e3f2d5872f195ab27c03156c",
						"sha256:7a8ef141e3a60eeee8ec2b04e78e977ef817c349128ea0985410d7b94b8b187f",
					},
				},
				Returns: cache.ArtifactCacheMissingBlobsReturns{
					MissingBlobIDs: []string{
						"sha256:2d850affad723b172fc58dac7ed833ce0582896f9154546f1eb64e6584d5a312",
						"sha256:44da28d6ef71b50c2d678b086864317da6945922c989a3393682357c5ad83153",
						"sha256:a963df97ae16e97bc451da20dcb2e19a670c8177e3f2d5872f195ab27c03156c",
						"sha256:7a8ef141e3a60eeee8ec2b04e78e977ef817c349128ea0985410d7b94b8b187f",
					},
				},
			},
			putBlobExpectations: []cache.ArtifactCachePutBlobExpectation{
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:2d850affad723b172fc58dac7ed833ce0582896f9154546f1eb64e6584d5a312",
						BlobInfo: types.BlobInfo{
							SchemaVersion: 1,
							Digest:        "",
							DiffID:        "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
						},
					},
				},
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:44da28d6ef71b50c2d678b086864317da6945922c989a3393682357c5ad83153",
						BlobInfo: types.BlobInfo{
							SchemaVersion: 1,
							Digest:        "",
							DiffID:        "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
						},
					},
				},
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:a963df97ae16e97bc451da20dcb2e19a670c8177e3f2d5872f195ab27c03156c",
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
						BlobID: "sha256:7a8ef141e3a60eeee8ec2b04e78e977ef817c349128ea0985410d7b94b8b187f",
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
				ID:   "sha256:a646bb11d39c149d4aaf9b888233048e0848304e5abd75667ea6f21d540d800c",
				BlobIDs: []string{
					"sha256:2d850affad723b172fc58dac7ed833ce0582896f9154546f1eb64e6584d5a312",
					"sha256:44da28d6ef71b50c2d678b086864317da6945922c989a3393682357c5ad83153",
					"sha256:a963df97ae16e97bc451da20dcb2e19a670c8177e3f2d5872f195ab27c03156c",
					"sha256:7a8ef141e3a60eeee8ec2b04e78e977ef817c349128ea0985410d7b94b8b187f",
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
						RootFS: v1.RootFS{Type: "layers", DiffIDs: []v1.Hash{v1.Hash{
							Algorithm: "sha256", Hex: "932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02"},
							{Algorithm: "sha256", Hex: "dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5"},
							{Algorithm: "sha256", Hex: "24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7"},
							{Algorithm: "sha256", Hex: "a4595c43a874856bf95f3bfc4fbf78bbaa04c92c726276d4f64193a47ced0566"},
						},
						},
						Config: v1.Config{
							Env:      []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"},
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
					BlobIDs:    []string{"sha256:eb524f2e4340057b02ef7e2b219fa362fa309d4aaa52f3c1ce5095e5555900fc"},
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
					BlobIDs:    []string{"sha256:eb524f2e4340057b02ef7e2b219fa362fa309d4aaa52f3c1ce5095e5555900fc"},
				},
				Returns: cache.ArtifactCacheMissingBlobsReturns{
					MissingBlobIDs: []string{"sha256:eb524f2e4340057b02ef7e2b219fa362fa309d4aaa52f3c1ce5095e5555900fc"},
				},
			},
			putBlobExpectations: []cache.ArtifactCachePutBlobExpectation{
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:eb524f2e4340057b02ef7e2b219fa362fa309d4aaa52f3c1ce5095e5555900fc",
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
					ArtifactID: "sha256:059741cfbdc039e88e337d621e57e03e99b0e0a75df32f2027ebef13f839af65",
					BlobIDs:    []string{"sha256:eb524f2e4340057b02ef7e2b219fa362fa309d4aaa52f3c1ce5095e5555900fc"},
				},
				Returns: cache.ArtifactCacheMissingBlobsReturns{
					MissingArtifact: true,
					MissingBlobIDs:  []string{"sha256:eb524f2e4340057b02ef7e2b219fa362fa309d4aaa52f3c1ce5095e5555900fc"},
				},
			},
			putBlobExpectations: []cache.ArtifactCachePutBlobExpectation{
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:eb524f2e4340057b02ef7e2b219fa362fa309d4aaa52f3c1ce5095e5555900fc",
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
						ArtifactID: "sha256:059741cfbdc039e88e337d621e57e03e99b0e0a75df32f2027ebef13f839af65",
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

			a, err := image2.NewArtifact(img, mockCache, tt.artifactOpt, config.ScannerOption{})
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
