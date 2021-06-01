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
	"github.com/aquasecurity/fanal/image"
	"github.com/aquasecurity/fanal/types"
	depTypes "github.com/aquasecurity/go-dep-parser/pkg/types"
)

func TestArtifact_Inspect(t *testing.T) {
	tests := []struct {
		name                    string
		imagePath               string
		disableAnalyzers        []analyzer.Type
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
					ArtifactID: "sha256:cdb49675542ff0051aaf7bab6c7a81b6fe275a7dd57d1e0317724a51edb7d6a6",
					BlobIDs:    []string{"sha256:c49e98b78d17b37b5e7e2e1032ebf9fa1b7d0b7f7998e37b2f0918739a6ffd7f"},
				},
				Returns: cache.ArtifactCacheMissingBlobsReturns{
					MissingArtifact: true,
					MissingBlobIDs:  []string{"sha256:c49e98b78d17b37b5e7e2e1032ebf9fa1b7d0b7f7998e37b2f0918739a6ffd7f"},
				},
			},
			putBlobExpectations: []cache.ArtifactCachePutBlobExpectation{
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:c49e98b78d17b37b5e7e2e1032ebf9fa1b7d0b7f7998e37b2f0918739a6ffd7f",
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
									{Name: "alpine-baselayout", Version: "3.2.0-r3", SrcName: "alpine-baselayout", SrcVersion: "3.2.0-r3"},
									{Name: "alpine-keys", Version: "2.1-r2", SrcName: "alpine-keys", SrcVersion: "2.1-r2"},
									{Name: "apk-tools", Version: "2.10.4-r3", SrcName: "apk-tools", SrcVersion: "2.10.4-r3"},
									{Name: "busybox", Version: "1.31.1-r9", SrcName: "busybox", SrcVersion: "1.31.1-r9"},
									{Name: "ca-certificates-cacert", Version: "20191127-r1", SrcName: "ca-certificates", SrcVersion: "20191127-r1"},
									{Name: "libc-utils", Version: "0.7.2-r0", SrcName: "libc-dev", SrcVersion: "0.7.2-r0"},
									{Name: "libcrypto1.1", Version: "1.1.1d-r3", SrcName: "openssl", SrcVersion: "1.1.1d-r3"},
									{Name: "libssl1.1", Version: "1.1.1d-r3", SrcName: "openssl", SrcVersion: "1.1.1d-r3"},
									{Name: "libtls-standalone", Version: "2.9.1-r0", SrcName: "libtls-standalone", SrcVersion: "2.9.1-r0"},
									{Name: "musl", Version: "1.1.24-r2", SrcName: "musl", SrcVersion: "1.1.24-r2"},
									{Name: "musl-utils", Version: "1.1.24-r2", SrcName: "musl", SrcVersion: "1.1.24-r2"},
									{Name: "scanelf", Version: "1.2.4-r0", SrcName: "pax-utils", SrcVersion: "1.2.4-r0"},
									{Name: "ssl_client", Version: "1.31.1-r9", SrcName: "busybox", SrcVersion: "1.31.1-r9"},
									{Name: "zlib", Version: "1.2.11-r3", SrcName: "zlib", SrcVersion: "1.2.11-r3"},
								},
							}},
							Applications:  []types.Application(nil),
							OpaqueDirs:    []string(nil),
							WhiteoutFiles: []string(nil),
							Size:          5861888,
						},
					},
					Returns: cache.ArtifactCachePutBlobReturns{},
				},
			},
			putArtifactExpectations: []cache.ArtifactCachePutArtifactExpectation{
				{
					Args: cache.ArtifactCachePutArtifactArgs{
						ArtifactID: "sha256:cdb49675542ff0051aaf7bab6c7a81b6fe275a7dd57d1e0317724a51edb7d6a6",
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
				ID:      "sha256:cdb49675542ff0051aaf7bab6c7a81b6fe275a7dd57d1e0317724a51edb7d6a6",
				BlobIDs: []string{"sha256:c49e98b78d17b37b5e7e2e1032ebf9fa1b7d0b7f7998e37b2f0918739a6ffd7f"},
			},
		},
		{
			name:      "happy path: include lock files",
			imagePath: "../../test/testdata/vuln-image.tar.gz",
			missingBlobsExpectation: cache.ArtifactCacheMissingBlobsExpectation{
				Args: cache.ArtifactCacheMissingBlobsArgs{
					ArtifactID: "sha256:1a0f2e0e3a3ca6bf77692726db8b41793f3ac4edb7b64dd21a93d217ad8257e8",
					BlobIDs: []string{
						"sha256:9e39642ee1f76879f7a9bec9b89f1bdb94ec160ba7d66be9aa20a9bc7046470f",
						"sha256:4b1e28f1bccd58cbef5dd8360ff808787e8a0d06a1d05b596a26ddb2cf7c5777",
						"sha256:ebbbf6276d97ca5ea91f4efb90496650568c1961a6906555aa774594543b7576",
						"sha256:1d9a1222903af7cad433a122d81cb35084541addd878e7cc11821c93ba435480",
					},
				},
				Returns: cache.ArtifactCacheMissingBlobsReturns{
					MissingBlobIDs: []string{
						"sha256:9e39642ee1f76879f7a9bec9b89f1bdb94ec160ba7d66be9aa20a9bc7046470f",
						"sha256:4b1e28f1bccd58cbef5dd8360ff808787e8a0d06a1d05b596a26ddb2cf7c5777",
						"sha256:ebbbf6276d97ca5ea91f4efb90496650568c1961a6906555aa774594543b7576",
						"sha256:1d9a1222903af7cad433a122d81cb35084541addd878e7cc11821c93ba435480",
					},
				},
			},
			putBlobExpectations: []cache.ArtifactCachePutBlobExpectation{
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:9e39642ee1f76879f7a9bec9b89f1bdb94ec160ba7d66be9aa20a9bc7046470f",
						BlobInfo: types.BlobInfo{
							SchemaVersion: 1,
							Digest:        "",
							DiffID:        "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
							OS: &types.OS{
								Family: "debian",
								Name:   "9.9",
							},
							Size: 3056640,
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
						BlobID: "sha256:4b1e28f1bccd58cbef5dd8360ff808787e8a0d06a1d05b596a26ddb2cf7c5777",
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
							Size: 15433728,
						},
					},
				},
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:ebbbf6276d97ca5ea91f4efb90496650568c1961a6906555aa774594543b7576",
						BlobInfo: types.BlobInfo{
							SchemaVersion: 1,
							Digest:        "",
							DiffID:        "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
							Size:          29696,
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
						BlobID: "sha256:1d9a1222903af7cad433a122d81cb35084541addd878e7cc11821c93ba435480",
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
							Size: 6656,
						},
					},
				},
			},
			want: types.ArtifactReference{
				Name: "../../test/testdata/vuln-image.tar.gz",
				ID:   "sha256:1a0f2e0e3a3ca6bf77692726db8b41793f3ac4edb7b64dd21a93d217ad8257e8",
				BlobIDs: []string{
					"sha256:9e39642ee1f76879f7a9bec9b89f1bdb94ec160ba7d66be9aa20a9bc7046470f",
					"sha256:4b1e28f1bccd58cbef5dd8360ff808787e8a0d06a1d05b596a26ddb2cf7c5777",
					"sha256:ebbbf6276d97ca5ea91f4efb90496650568c1961a6906555aa774594543b7576",
					"sha256:1d9a1222903af7cad433a122d81cb35084541addd878e7cc11821c93ba435480",
				},
			},
		},
		{
			name:             "happy path: disable analyzers",
			imagePath:        "../../test/testdata/vuln-image.tar.gz",
			disableAnalyzers: []analyzer.Type{analyzer.TypeDebian, analyzer.TypeDpkg, analyzer.TypeComposer, analyzer.TypeBundler},
			missingBlobsExpectation: cache.ArtifactCacheMissingBlobsExpectation{
				Args: cache.ArtifactCacheMissingBlobsArgs{
					ArtifactID: "sha256:1a0f2e0e3a3ca6bf77692726db8b41793f3ac4edb7b64dd21a93d217ad8257e8",
					BlobIDs: []string{
						"sha256:465b29fdf2037fa14e5a48a6c0f9908ad573ef4e4760bbed36aff614231600e5",
						"sha256:135da42db81f43536be866113da80b5d330c8e3b2217108feb41e0da145af291",
						"sha256:21dbb93b630abd81afcd42a7bc7f9147da08530566f744237f37474100e9ef4f",
						"sha256:c47cef89b2d1014811c738f0b783f0ded8bddb5cff5ebf22672e7753f81941fa",
					},
				},
				Returns: cache.ArtifactCacheMissingBlobsReturns{
					MissingBlobIDs: []string{
						"sha256:465b29fdf2037fa14e5a48a6c0f9908ad573ef4e4760bbed36aff614231600e5",
						"sha256:135da42db81f43536be866113da80b5d330c8e3b2217108feb41e0da145af291",
						"sha256:21dbb93b630abd81afcd42a7bc7f9147da08530566f744237f37474100e9ef4f",
						"sha256:c47cef89b2d1014811c738f0b783f0ded8bddb5cff5ebf22672e7753f81941fa",
					},
				},
			},
			putBlobExpectations: []cache.ArtifactCachePutBlobExpectation{
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:465b29fdf2037fa14e5a48a6c0f9908ad573ef4e4760bbed36aff614231600e5",
						BlobInfo: types.BlobInfo{
							SchemaVersion: 1,
							Digest:        "",
							DiffID:        "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
							Size:          3056640,
						},
					},
				},
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:135da42db81f43536be866113da80b5d330c8e3b2217108feb41e0da145af291",
						BlobInfo: types.BlobInfo{
							SchemaVersion: 1,
							Digest:        "",
							DiffID:        "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
							Size:          15433728,
						},
					},
				},
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:21dbb93b630abd81afcd42a7bc7f9147da08530566f744237f37474100e9ef4f",
						BlobInfo: types.BlobInfo{
							SchemaVersion: 1,
							Digest:        "",
							DiffID:        "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
							OpaqueDirs:    []string{"php-app/"},
							Size:          29696,
						},
					},
				},
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:c47cef89b2d1014811c738f0b783f0ded8bddb5cff5ebf22672e7753f81941fa",
						BlobInfo: types.BlobInfo{
							SchemaVersion: 1,
							Digest:        "",
							DiffID:        "sha256:a4595c43a874856bf95f3bfc4fbf78bbaa04c92c726276d4f64193a47ced0566",
							OpaqueDirs:    []string{"ruby-app/"},
							Size:          6656,
						},
					},
				},
			},
			want: types.ArtifactReference{
				Name: "../../test/testdata/vuln-image.tar.gz",
				ID:   "sha256:1a0f2e0e3a3ca6bf77692726db8b41793f3ac4edb7b64dd21a93d217ad8257e8",
				BlobIDs: []string{
					"sha256:465b29fdf2037fa14e5a48a6c0f9908ad573ef4e4760bbed36aff614231600e5",
					"sha256:135da42db81f43536be866113da80b5d330c8e3b2217108feb41e0da145af291",
					"sha256:21dbb93b630abd81afcd42a7bc7f9147da08530566f744237f37474100e9ef4f",
					"sha256:c47cef89b2d1014811c738f0b783f0ded8bddb5cff5ebf22672e7753f81941fa",
				},
			},
		},
		{
			name:      "sad path, MissingBlobs returns an error",
			imagePath: "../../test/testdata/alpine-311.tar.gz",
			missingBlobsExpectation: cache.ArtifactCacheMissingBlobsExpectation{
				Args: cache.ArtifactCacheMissingBlobsArgs{
					ArtifactID: "sha256:cdb49675542ff0051aaf7bab6c7a81b6fe275a7dd57d1e0317724a51edb7d6a6",
					BlobIDs:    []string{"sha256:c49e98b78d17b37b5e7e2e1032ebf9fa1b7d0b7f7998e37b2f0918739a6ffd7f"},
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
					ArtifactID: "sha256:cdb49675542ff0051aaf7bab6c7a81b6fe275a7dd57d1e0317724a51edb7d6a6",
					BlobIDs:    []string{"sha256:c49e98b78d17b37b5e7e2e1032ebf9fa1b7d0b7f7998e37b2f0918739a6ffd7f"},
				},
				Returns: cache.ArtifactCacheMissingBlobsReturns{
					MissingBlobIDs: []string{"sha256:c49e98b78d17b37b5e7e2e1032ebf9fa1b7d0b7f7998e37b2f0918739a6ffd7f"},
				},
			},
			putBlobExpectations: []cache.ArtifactCachePutBlobExpectation{
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:c49e98b78d17b37b5e7e2e1032ebf9fa1b7d0b7f7998e37b2f0918739a6ffd7f",
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
									{Name: "alpine-baselayout", Version: "3.2.0-r3", SrcName: "alpine-baselayout", SrcVersion: "3.2.0-r3"},
									{Name: "alpine-keys", Version: "2.1-r2", SrcName: "alpine-keys", SrcVersion: "2.1-r2"},
									{Name: "apk-tools", Version: "2.10.4-r3", SrcName: "apk-tools", SrcVersion: "2.10.4-r3"},
									{Name: "busybox", Version: "1.31.1-r9", SrcName: "busybox", SrcVersion: "1.31.1-r9"},
									{Name: "ca-certificates-cacert", Version: "20191127-r1", SrcName: "ca-certificates", SrcVersion: "20191127-r1"},
									{Name: "libc-utils", Version: "0.7.2-r0", SrcName: "libc-dev", SrcVersion: "0.7.2-r0"},
									{Name: "libcrypto1.1", Version: "1.1.1d-r3", SrcName: "openssl", SrcVersion: "1.1.1d-r3"},
									{Name: "libssl1.1", Version: "1.1.1d-r3", SrcName: "openssl", SrcVersion: "1.1.1d-r3"},
									{Name: "libtls-standalone", Version: "2.9.1-r0", SrcName: "libtls-standalone", SrcVersion: "2.9.1-r0"},
									{Name: "musl", Version: "1.1.24-r2", SrcName: "musl", SrcVersion: "1.1.24-r2"},
									{Name: "musl-utils", Version: "1.1.24-r2", SrcName: "musl", SrcVersion: "1.1.24-r2"},
									{Name: "scanelf", Version: "1.2.4-r0", SrcName: "pax-utils", SrcVersion: "1.2.4-r0"},
									{Name: "ssl_client", Version: "1.31.1-r9", SrcName: "busybox", SrcVersion: "1.31.1-r9"},
									{Name: "zlib", Version: "1.2.11-r3", SrcName: "zlib", SrcVersion: "1.2.11-r3"},
								},
							}},
							Applications:  []types.Application(nil),
							OpaqueDirs:    []string(nil),
							WhiteoutFiles: []string(nil),
							Size:          5861888,
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
					ArtifactID: "sha256:cdb49675542ff0051aaf7bab6c7a81b6fe275a7dd57d1e0317724a51edb7d6a6",
					BlobIDs:    []string{"sha256:c49e98b78d17b37b5e7e2e1032ebf9fa1b7d0b7f7998e37b2f0918739a6ffd7f"},
				},
				Returns: cache.ArtifactCacheMissingBlobsReturns{
					MissingArtifact: true,
					MissingBlobIDs:  []string{"sha256:c49e98b78d17b37b5e7e2e1032ebf9fa1b7d0b7f7998e37b2f0918739a6ffd7f"},
				},
			},
			putBlobExpectations: []cache.ArtifactCachePutBlobExpectation{
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:c49e98b78d17b37b5e7e2e1032ebf9fa1b7d0b7f7998e37b2f0918739a6ffd7f",
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
									{Name: "alpine-baselayout", Version: "3.2.0-r3", SrcName: "alpine-baselayout", SrcVersion: "3.2.0-r3"},
									{Name: "alpine-keys", Version: "2.1-r2", SrcName: "alpine-keys", SrcVersion: "2.1-r2"},
									{Name: "apk-tools", Version: "2.10.4-r3", SrcName: "apk-tools", SrcVersion: "2.10.4-r3"},
									{Name: "busybox", Version: "1.31.1-r9", SrcName: "busybox", SrcVersion: "1.31.1-r9"},
									{Name: "ca-certificates-cacert", Version: "20191127-r1", SrcName: "ca-certificates", SrcVersion: "20191127-r1"},
									{Name: "libc-utils", Version: "0.7.2-r0", SrcName: "libc-dev", SrcVersion: "0.7.2-r0"},
									{Name: "libcrypto1.1", Version: "1.1.1d-r3", SrcName: "openssl", SrcVersion: "1.1.1d-r3"},
									{Name: "libssl1.1", Version: "1.1.1d-r3", SrcName: "openssl", SrcVersion: "1.1.1d-r3"},
									{Name: "libtls-standalone", Version: "2.9.1-r0", SrcName: "libtls-standalone", SrcVersion: "2.9.1-r0"},
									{Name: "musl", Version: "1.1.24-r2", SrcName: "musl", SrcVersion: "1.1.24-r2"},
									{Name: "musl-utils", Version: "1.1.24-r2", SrcName: "musl", SrcVersion: "1.1.24-r2"},
									{Name: "scanelf", Version: "1.2.4-r0", SrcName: "pax-utils", SrcVersion: "1.2.4-r0"},
									{Name: "ssl_client", Version: "1.31.1-r9", SrcName: "busybox", SrcVersion: "1.31.1-r9"},
									{Name: "zlib", Version: "1.2.11-r3", SrcName: "zlib", SrcVersion: "1.2.11-r3"},
								},
							}},
							Applications:  []types.Application(nil),
							OpaqueDirs:    []string(nil),
							WhiteoutFiles: []string(nil),
							Size:          5861888,
						},
					},
					Returns: cache.ArtifactCachePutBlobReturns{},
				},
			},
			putArtifactExpectations: []cache.ArtifactCachePutArtifactExpectation{
				{
					Args: cache.ArtifactCachePutArtifactArgs{
						ArtifactID: "sha256:cdb49675542ff0051aaf7bab6c7a81b6fe275a7dd57d1e0317724a51edb7d6a6",
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

			a, err := image2.NewArtifact(img, mockCache, tt.disableAnalyzers, config.ScannerOption{})
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
