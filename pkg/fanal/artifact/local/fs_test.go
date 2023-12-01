package local

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/slices"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/misconf"

	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/config/all"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/python/pip"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/alpine"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/pkg/apk"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/secret"
	_ "github.com/aquasecurity/trivy/pkg/fanal/handler/ospkgid"
	_ "github.com/aquasecurity/trivy/pkg/fanal/handler/sysfile"
)

func TestArtifact_Inspect(t *testing.T) {
	type fields struct {
		dir string
	}
	tests := []struct {
		name               string
		fields             fields
		artifactOpt        artifact.Option
		scannerOpt         misconf.ScannerOption
		disabledAnalyzers  []analyzer.Type
		disabledHandlers   []types.HandlerType
		putBlobExpectation cache.ArtifactCachePutBlobExpectation
		want               types.ArtifactReference
		wantErr            string
	}{
		{
			name: "happy path",
			fields: fields{
				dir: "./testdata/alpine",
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobID: "sha256:3936953436d207146190d966bf6331607a2b91de32e37418a98a23ef41183f92",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						OS: types.OS{
							Family: "alpine",
							Name:   "3.11.6",
						},
						PackageInfos: []types.PackageInfo{
							{
								FilePath: "lib/apk/db/installed",
								Packages: types.Packages{
									{
										ID:      "musl@1.1.24-r2",
										Name:    "musl",
										Version: "1.1.24-r2",
										Identifier: types.PkgIdentifier{
											PURL: "pkg:apk/alpine/musl@1.1.24-r2?arch=x86_64&distro=3.11.6",
										},
										SrcName:    "musl",
										SrcVersion: "1.1.24-r2",
										Licenses:   []string{"MIT"},
										Arch:       "x86_64",
										Digest:     "sha1:cb2316a189ebee5282c4a9bd98794cc2477a74c6",
										InstalledFiles: []string{
											"lib/libc.musl-x86_64.so.1",
											"lib/ld-musl-x86_64.so.1",
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "host",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:3936953436d207146190d966bf6331607a2b91de32e37418a98a23ef41183f92",
				BlobIDs: []string{
					"sha256:3936953436d207146190d966bf6331607a2b91de32e37418a98a23ef41183f92",
				},
			},
		},
		{
			name: "disable analyzers",
			fields: fields{
				dir: "./testdata/alpine",
			},
			artifactOpt: artifact.Option{
				DisabledAnalyzers: []analyzer.Type{
					analyzer.TypeAlpine,
					analyzer.TypeApk,
					analyzer.TypePip,
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobID: "sha256:e5ea60c7b2a76aab70962b3b969a8768695b35a3c945faf6424fd93742f5dec4",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "host",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:e5ea60c7b2a76aab70962b3b969a8768695b35a3c945faf6424fd93742f5dec4",
				BlobIDs: []string{
					"sha256:e5ea60c7b2a76aab70962b3b969a8768695b35a3c945faf6424fd93742f5dec4",
				},
			},
		},
		{
			name: "sad path PutBlob returns an error",
			fields: fields{
				dir: "./testdata/alpine",
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobID: "sha256:3936953436d207146190d966bf6331607a2b91de32e37418a98a23ef41183f92",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						OS: types.OS{
							Family: "alpine",
							Name:   "3.11.6",
						},
						PackageInfos: []types.PackageInfo{
							{
								FilePath: "lib/apk/db/installed",
								Packages: types.Packages{
									{
										ID:      "musl@1.1.24-r2",
										Name:    "musl",
										Version: "1.1.24-r2",
										Identifier: types.PkgIdentifier{
											PURL: "pkg:apk/alpine/musl@1.1.24-r2?arch=x86_64&distro=3.11.6",
										},
										SrcName:    "musl",
										SrcVersion: "1.1.24-r2",
										Licenses:   []string{"MIT"},
										Arch:       "x86_64",
										Digest:     "sha1:cb2316a189ebee5282c4a9bd98794cc2477a74c6",
										InstalledFiles: []string{
											"lib/libc.musl-x86_64.so.1",
											"lib/ld-musl-x86_64.so.1",
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{
					Err: errors.New("error"),
				},
			},
			wantErr: "failed to store blob",
		},
		{
			name: "sad path with no such directory",
			fields: fields{
				dir: "./testdata/unknown",
			},
			wantErr: "walk dir error",
		},
		{
			name: "happy path with single file",
			fields: fields{
				dir: "testdata/requirements.txt",
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobID: "sha256:3203d59908eb93883eb7de18ad9d8a5545bc7e9355d26b0dd5ebfcdbd9014f08",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Applications: []types.Application{
							{
								Type:     "pip",
								FilePath: "requirements.txt",
								Libraries: types.Packages{
									{
										Name:    "Flask",
										Version: "2.0.0",
										Identifier: types.PkgIdentifier{
											PURL: "pkg:pypi/flask@2.0.0",
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/requirements.txt",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:3203d59908eb93883eb7de18ad9d8a5545bc7e9355d26b0dd5ebfcdbd9014f08",
				BlobIDs: []string{
					"sha256:3203d59908eb93883eb7de18ad9d8a5545bc7e9355d26b0dd5ebfcdbd9014f08",
				},
			},
		},
		{
			name: "happy path with single file using relative path",
			fields: fields{
				dir: "./testdata/requirements.txt",
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobID: "sha256:3203d59908eb93883eb7de18ad9d8a5545bc7e9355d26b0dd5ebfcdbd9014f08",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Applications: []types.Application{
							{
								Type:     "pip",
								FilePath: "requirements.txt",
								Libraries: types.Packages{
									{
										Name:    "Flask",
										Version: "2.0.0",
										Identifier: types.PkgIdentifier{
											PURL: "pkg:pypi/flask@2.0.0",
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/requirements.txt",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:3203d59908eb93883eb7de18ad9d8a5545bc7e9355d26b0dd5ebfcdbd9014f08",
				BlobIDs: []string{
					"sha256:3203d59908eb93883eb7de18ad9d8a5545bc7e9355d26b0dd5ebfcdbd9014f08",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := new(cache.MockArtifactCache)
			c.ApplyPutBlobExpectation(tt.putBlobExpectation)

			a, err := NewArtifact(tt.fields.dir, c, tt.artifactOpt)
			require.NoError(t, err)

			got, err := a.Inspect(context.Background())
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBuildPathsToSkip(t *testing.T) {
	tests := []struct {
		name  string
		oses  []string
		paths []string
		base  string
		want  []string
	}{
		// Linux/macOS
		{
			name: "path - abs, base - abs, not joining paths",
			oses: []string{
				"linux",
				"darwin",
			},
			base:  "/foo",
			paths: []string{"/foo/bar"},
			want:  []string{"bar"},
		},
		{
			name: "path - abs, base - rel",
			oses: []string{
				"linux",
				"darwin",
			},
			base: "foo",
			paths: func() []string {
				abs, err := filepath.Abs("foo/bar")
				require.NoError(t, err)
				return []string{abs}
			}(),
			want: []string{"bar"},
		},
		{
			name: "path - rel, base - rel, joining paths",
			oses: []string{
				"linux",
				"darwin",
			},
			base:  "foo",
			paths: []string{"bar"},
			want:  []string{"bar"},
		},
		{
			name: "path - rel, base - rel, not joining paths",
			oses: []string{
				"linux",
				"darwin",
			},
			base:  "foo",
			paths: []string{"foo/bar/bar"},
			want:  []string{"bar/bar"},
		},
		{
			name: "path - rel with dot, base - rel, removing the leading dot and not joining paths",
			oses: []string{
				"linux",
				"darwin",
			},
			base:  "foo",
			paths: []string{"./foo/bar"},
			want:  []string{"bar"},
		},
		{
			name: "path - rel, base - dot",
			oses: []string{
				"linux",
				"darwin",
			},
			base:  ".",
			paths: []string{"foo/bar"},
			want:  []string{"foo/bar"},
		},
		// Windows
		{
			name:  "path - rel, base - rel. Skip common prefix",
			oses:  []string{"windows"},
			base:  "foo",
			paths: []string{"foo\\bar\\bar"},
			want:  []string{"bar/bar"},
		},
		{
			name:  "path - rel, base - dot, windows",
			oses:  []string{"windows"},
			base:  ".",
			paths: []string{"foo\\bar"},
			want:  []string{"foo/bar"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !slices.Contains(tt.oses, runtime.GOOS) {
				t.Skipf("Skip path tests for %q", tt.oses)
			}
			got := buildPathsToSkip(tt.base, tt.paths)
			assert.Equal(t, tt.want, got)
		})
	}
}

var policyMetadata = types.PolicyMetadata{
	ID:                 "TEST001",
	AVDID:              "AVD-TEST-0001",
	Type:               "Terraform Security Check",
	Title:              "Test policy",
	Description:        "This is a test policy.",
	Severity:           "LOW",
	RecommendedActions: "Have a cup of tea.",
	References:         []string{"https://trivy.dev/"},
}

func TestTerraformMisconfigurationScan(t *testing.T) {
	type fields struct {
		dir string
	}
	tests := []struct {
		name               string
		fields             fields
		putBlobExpectation cache.ArtifactCachePutBlobExpectation
		artifactOpt        artifact.Option
		want               types.ArtifactReference
	}{
		{
			name: "single failure",
			fields: fields{
				dir: "./testdata/misconfig/terraform/single-failure",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					RegoOnly:                 true,
					Namespaces:               []string{"user"},
					PolicyPaths:              []string{"./testdata/misconfig/terraform/rego"},
					DisableEmbeddedPolicies:  true,
					DisableEmbeddedLibraries: true,
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: 2,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "terraform",
								FilePath: "main.tf",
								Failures: types.MisconfResults{
									{
										Namespace:      "user.something",
										Query:          "data.user.something.deny",
										Message:        "Empty bucket name!",
										PolicyMetadata: policyMetadata,
										CauseMetadata: types.CauseMetadata{
											Resource:  "aws_s3_bucket.asd",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 1,
											EndLine:   3,
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/terraform/single-failure",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:dfded109de09778a4b75045e784adb08a3372b51ff67201d2417e1b924a86191",
				BlobIDs: []string{
					"sha256:dfded109de09778a4b75045e784adb08a3372b51ff67201d2417e1b924a86191",
				},
			},
		},
		{
			name: "multiple failures",
			fields: fields{
				dir: "./testdata/misconfig/terraform/multiple-failures",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					RegoOnly:                 true,
					Namespaces:               []string{"user"},
					PolicyPaths:              []string{"./testdata/misconfig/terraform/rego"},
					DisableEmbeddedPolicies:  true,
					DisableEmbeddedLibraries: true,
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: 2,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "terraform",
								FilePath: "main.tf",
								Failures: types.MisconfResults{
									{
										Namespace:      "user.something",
										Query:          "data.user.something.deny",
										Message:        "Empty bucket name!",
										PolicyMetadata: policyMetadata,
										CauseMetadata: types.CauseMetadata{
											Resource:  "aws_s3_bucket.one",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 1,
											EndLine:   3,
										},
									},
									{
										Namespace:      "user.something",
										Query:          "data.user.something.deny",
										Message:        "Empty bucket name!",
										PolicyMetadata: policyMetadata,
										CauseMetadata: types.CauseMetadata{
											Resource:  "aws_s3_bucket.two",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 5,
											EndLine:   7,
										},
									},
								},
							},
							{
								FileType: "terraform",
								FilePath: "more.tf",
								Failures: types.MisconfResults{
									{
										Namespace:      "user.something",
										Query:          "data.user.something.deny",
										Message:        "Empty bucket name!",
										PolicyMetadata: policyMetadata,
										CauseMetadata: types.CauseMetadata{
											Resource:  "aws_s3_bucket.three",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 1,
											EndLine:   3,
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/terraform/multiple-failures",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:92c7349709ab2483fdce8e037b669bf3d416a108cc554d4e7958617821c0e0d5",
				BlobIDs: []string{
					"sha256:92c7349709ab2483fdce8e037b669bf3d416a108cc554d4e7958617821c0e0d5",
				},
			},
		},
		{
			name: "no results",
			fields: fields{
				dir: "./testdata/misconfig/terraform/no-results",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					RegoOnly:    true,
					Namespaces:  []string{"user"},
					PolicyPaths: []string{"./testdata/misconfig/terraform/rego"},
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/terraform/no-results",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:5f021c57f927646e282ca26149ec8a335bea10b8ddd259905a031566cf8721e9",
				BlobIDs: []string{
					"sha256:5f021c57f927646e282ca26149ec8a335bea10b8ddd259905a031566cf8721e9",
				},
			},
		},
		{
			name: "passed",
			fields: fields{
				dir: "./testdata/misconfig/terraform/passed",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					RegoOnly:                 true,
					Namespaces:               []string{"user"},
					PolicyPaths:              []string{"./testdata/misconfig/terraform/rego"},
					DisableEmbeddedPolicies:  true,
					DisableEmbeddedLibraries: true,
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: 2,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "terraform",
								FilePath: ".",
								Successes: types.MisconfResults{
									{
										Namespace:      "user.something",
										Query:          "data.user.something.deny",
										PolicyMetadata: policyMetadata,
										CauseMetadata: types.CauseMetadata{
											Provider: "Generic",
											Service:  "general",
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/terraform/passed",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:79843f26038836361ee18033ea1921249f82ba9d908fd67d1843ec00c06b0d71",
				BlobIDs: []string{
					"sha256:79843f26038836361ee18033ea1921249f82ba9d908fd67d1843ec00c06b0d71",
				},
			},
		},
		{
			name: "multiple failures busted relative paths",
			fields: fields{
				dir: "./testdata/misconfig/terraform/busted-relative-paths/child/main.tf",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					RegoOnly:                 true,
					Namespaces:               []string{"user"},
					PolicyPaths:              []string{"./testdata/misconfig/terraform/rego"},
					DisableEmbeddedPolicies:  true,
					DisableEmbeddedLibraries: true,
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: 2,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "terraform",
								FilePath: "main.tf",
								Failures: types.MisconfResults{
									{
										Namespace:      "user.something",
										Query:          "data.user.something.deny",
										Message:        "Empty bucket name!",
										PolicyMetadata: policyMetadata,
										CauseMetadata: types.CauseMetadata{
											Resource:  "aws_s3_bucket.one",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 1,
											EndLine:   3,
										},
									},
									{
										Namespace:      "user.something",
										Query:          "data.user.something.deny",
										Message:        "Empty bucket name!",
										PolicyMetadata: policyMetadata,
										CauseMetadata: types.CauseMetadata{
											Resource:  "aws_s3_bucket.two",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 5,
											EndLine:   7,
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/terraform/busted-relative-paths/child/main.tf",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:f34e9426d748138026e42d462657d7ea4b85a8d056f903bdfba7adbd118cb37f",
				BlobIDs: []string{
					"sha256:f34e9426d748138026e42d462657d7ea4b85a8d056f903bdfba7adbd118cb37f",
				},
			},
		},
		{
			name: "tfvars outside the scan folder",
			fields: fields{
				dir: "./testdata/misconfig/terraform/tfvar-outside/tf",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					RegoOnly:                true,
					Namespaces:              []string{"user"},
					PolicyPaths:             []string{"./testdata/misconfig/terraform/rego"},
					TerraformTFVars:         []string{"./testdata/misconfig/terraform/tfvar-outside/main.tfvars"},
					TfExcludeDownloaded:     true,
					DisableEmbeddedPolicies: true,
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: 2,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: types.Terraform,
								FilePath: ".",
								Successes: types.MisconfResults{
									{
										Namespace:      "user.something",
										Query:          "data.user.something.deny",
										PolicyMetadata: policyMetadata,
										CauseMetadata: types.CauseMetadata{
											Provider: "Generic",
											Service:  "general",
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/terraform/tfvar-outside/tf",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:79843f26038836361ee18033ea1921249f82ba9d908fd67d1843ec00c06b0d71",
				BlobIDs: []string{
					"sha256:79843f26038836361ee18033ea1921249f82ba9d908fd67d1843ec00c06b0d71",
				},
			},
		},
		{
			name: "relative paths",
			fields: fields{
				dir: "./testdata/misconfig/terraform/relative-paths/child",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					RegoOnly:                true,
					Namespaces:              []string{"user"},
					PolicyPaths:             []string{"./testdata/misconfig/terraform/rego"},
					DisableEmbeddedPolicies: true,
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: 2,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: types.Terraform,
								FilePath: "../parent/main.tf",
								Failures: types.MisconfResults{
									{
										Namespace:      "user.something",
										Query:          "data.user.something.deny",
										Message:        "Empty bucket name!",
										PolicyMetadata: policyMetadata,
										CauseMetadata: types.CauseMetadata{
											Resource:  "aws_s3_bucket.three",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 1,
											EndLine:   3,
										},
									},
								},
							},
							{
								FileType: types.Terraform,
								FilePath: "main.tf",
								Failures: types.MisconfResults{
									{
										Namespace:      "user.something",
										Query:          "data.user.something.deny",
										Message:        "Empty bucket name!",
										PolicyMetadata: policyMetadata,
										CauseMetadata: types.CauseMetadata{
											Resource:  "aws_s3_bucket.one",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 1,
											EndLine:   3,
										},
									},
								},
							},
							{
								FileType: types.Terraform,
								FilePath: "nested/main.tf",
								Failures: types.MisconfResults{
									{
										Namespace:      "user.something",
										Query:          "data.user.something.deny",
										Message:        "Empty bucket name!",
										PolicyMetadata: policyMetadata,
										CauseMetadata: types.CauseMetadata{
											Resource:  "aws_s3_bucket.two",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 1,
											EndLine:   3,
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/terraform/relative-paths/child",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:69c4d62b0632b4926eda0138f1a2d3106d7de74d62f23c9bbbb58ba2d5dcdce7",
				BlobIDs: []string{
					"sha256:69c4d62b0632b4926eda0138f1a2d3106d7de74d62f23c9bbbb58ba2d5dcdce7",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := new(cache.MockArtifactCache)
			c.ApplyPutBlobExpectation(tt.putBlobExpectation)
			tt.artifactOpt.DisabledHandlers = []types.HandlerType{
				types.SystemFileFilteringPostHandler,
			}
			tt.artifactOpt.MisconfScannerOption.DisableEmbeddedPolicies = true
			a, err := NewArtifact(tt.fields.dir, c, tt.artifactOpt)
			require.NoError(t, err)

			got, err := a.Inspect(context.Background())
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCloudFormationMisconfigurationScan(t *testing.T) {
	type fields struct {
		dir string
	}
	tests := []struct {
		name               string
		fields             fields
		putBlobExpectation cache.ArtifactCachePutBlobExpectation
		artifactOpt        artifact.Option
		want               types.ArtifactReference
	}{
		{
			name: "single failure",
			fields: fields{
				dir: "./testdata/misconfig/cloudformation/single-failure/src",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					RegoOnly:                 true,
					Namespaces:               []string{"user"},
					PolicyPaths:              []string{"./testdata/misconfig/cloudformation/single-failure/rego"},
					DisableEmbeddedPolicies:  true,
					DisableEmbeddedLibraries: true,
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "cloudformation",
								FilePath: "main.yaml",
								Failures: types.MisconfResults{
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										Message:   "No buckets allowed!",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											AVDID:              "AVD-TEST-0001",
											Type:               "CloudFormation Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References:         []string{"https://trivy.dev/"},
										},
										CauseMetadata: types.CauseMetadata{
											Resource:  "main.yaml:3-6",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 3,
											EndLine:   6,
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/cloudformation/single-failure/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:3305a5eb2531ea65560ed013ba5dd5dd267a47e35ce2338422c527c03c8d3a6e",
				BlobIDs: []string{
					"sha256:3305a5eb2531ea65560ed013ba5dd5dd267a47e35ce2338422c527c03c8d3a6e",
				},
			},
		},
		{
			name: "multiple failures",
			fields: fields{
				dir: "./testdata/misconfig/cloudformation/multiple-failures/src",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					RegoOnly:                 true,
					Namespaces:               []string{"user"},
					PolicyPaths:              []string{"./testdata/misconfig/cloudformation/multiple-failures/rego"},
					DisableEmbeddedPolicies:  true,
					DisableEmbeddedLibraries: true,
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: 2,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "cloudformation",
								FilePath: "main.yaml",
								Failures: types.MisconfResults{
									types.MisconfResult{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										Message:   "No buckets allowed!",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											AVDID:              "AVD-TEST-0001",
											Type:               "CloudFormation Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References:         []string{"https://trivy.dev/"},
										},
										CauseMetadata: types.CauseMetadata{
											Resource:  "main.yaml:2-5",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 2,
											EndLine:   5,
										},
									},
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										Message:   "No buckets allowed!",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											AVDID:              "AVD-TEST-0001",
											Type:               "CloudFormation Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References:         []string{"https://trivy.dev/"},
										},
										CauseMetadata: types.CauseMetadata{
											Resource:  "main.yaml:6-9",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 6,
											EndLine:   9,
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/cloudformation/multiple-failures/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:1fda93ec407e35b6d41139f65b007658d34bde3d07fcd6a1fff99edf7c548ad8",
				BlobIDs: []string{
					"sha256:1fda93ec407e35b6d41139f65b007658d34bde3d07fcd6a1fff99edf7c548ad8",
				},
			},
		},
		{
			name: "no results",
			fields: fields{
				dir: "./testdata/misconfig/cloudformation/no-results/src",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					RegoOnly:                 true,
					Namespaces:               []string{"user"},
					PolicyPaths:              []string{"./testdata/misconfig/cloudformation/no-results/rego"},
					DisableEmbeddedPolicies:  true,
					DisableEmbeddedLibraries: true,
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/cloudformation/no-results/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:49bb9fb76978538cfb4ed9c2e9a1360f3b18b8e46836315d66c5ee4e882015cf",
				BlobIDs: []string{
					"sha256:49bb9fb76978538cfb4ed9c2e9a1360f3b18b8e46836315d66c5ee4e882015cf",
				},
			},
		},
		{
			name: "CloudFormation parameters outside the scan directory",
			fields: fields{
				dir: "./testdata/misconfig/cloudformation/params/code/src",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					RegoOnly:                 true,
					Namespaces:               []string{"user"},
					PolicyPaths:              []string{"./testdata/misconfig/cloudformation/params/code/rego"},
					CloudFormationParamVars:  []string{"./testdata/misconfig/cloudformation/params/cfparams.json"},
					DisableEmbeddedPolicies:  true,
					DisableEmbeddedLibraries: true,
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "cloudformation",
								FilePath: "main.yaml",
								Successes: types.MisconfResults{
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											AVDID:              "AVD-TEST-0001",
											Type:               "CloudFormation Security Check",
											Title:              "Bad stuff is bad",
											Description:        "Its not good!",
											Severity:           "HIGH",
											RecommendedActions: "Remove bad stuff",
										},
										CauseMetadata: types.CauseMetadata{
											Provider: "AWS",
											Service:  "sqs",
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/cloudformation/params/code/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:ff9478e92d4d705867dc51e03b0d1d02bd065690dac2d214fae0bc94c81b8c16",
				BlobIDs: []string{
					"sha256:ff9478e92d4d705867dc51e03b0d1d02bd065690dac2d214fae0bc94c81b8c16",
				},
			},
		},
		{
			name: "passed",
			fields: fields{
				dir: "./testdata/misconfig/cloudformation/passed/src",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					RegoOnly:                 true,
					Namespaces:               []string{"user"},
					PolicyPaths:              []string{"./testdata/misconfig/cloudformation/passed/rego"},
					DisableEmbeddedPolicies:  true,
					DisableEmbeddedLibraries: true,
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "cloudformation",
								FilePath: "main.yaml",
								Successes: types.MisconfResults{
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											AVDID:              "AVD-TEST-0001",
											Type:               "CloudFormation Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References:         []string{"https://trivy.dev/"},
										},
										CauseMetadata: types.CauseMetadata{
											Provider: "Generic",
											Service:  "general",
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/cloudformation/passed/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:c7897400396aca0c6167281fd9ecb72a960f82646cb524945c934431b386f269",
				BlobIDs: []string{
					"sha256:c7897400396aca0c6167281fd9ecb72a960f82646cb524945c934431b386f269",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := new(cache.MockArtifactCache)
			c.ApplyPutBlobExpectation(tt.putBlobExpectation)
			tt.artifactOpt.DisabledHandlers = []types.HandlerType{
				types.SystemFileFilteringPostHandler,
			}
			tt.artifactOpt.MisconfScannerOption.DisableEmbeddedPolicies = true
			a, err := NewArtifact(tt.fields.dir, c, tt.artifactOpt)
			require.NoError(t, err)

			got, err := a.Inspect(context.Background())
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDockerfileMisconfigurationScan(t *testing.T) {
	type fields struct {
		dir string
	}
	tests := []struct {
		name               string
		fields             fields
		putBlobExpectation cache.ArtifactCachePutBlobExpectation
		artifactOpt        artifact.Option
		want               types.ArtifactReference
	}{
		{
			name: "single failure",
			fields: fields{
				dir: "./testdata/misconfig/dockerfile/single-failure/src",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					RegoOnly:                 true,
					Namespaces:               []string{"user"},
					PolicyPaths:              []string{"./testdata/misconfig/dockerfile/single-failure/rego"},
					DisableEmbeddedPolicies:  true,
					DisableEmbeddedLibraries: true,
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "dockerfile",
								FilePath: "Dockerfile",
								Successes: types.MisconfResults{
									types.MisconfResult{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											AVDID:              "AVD-TEST-0001",
											Type:               "Dockerfile Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References:         []string{"https://trivy.dev/"},
										},
										CauseMetadata: types.CauseMetadata{
											Provider: "Generic",
											Service:  "general",
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/dockerfile/single-failure/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:51cece3d563e9b42ab01cfabdc88b1294b49e4c168248337f8120bed4710dcff",
				BlobIDs: []string{
					"sha256:51cece3d563e9b42ab01cfabdc88b1294b49e4c168248337f8120bed4710dcff",
				},
			},
		},
		{
			name: "multiple failures",
			fields: fields{
				dir: "./testdata/misconfig/dockerfile/multiple-failures/src",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					RegoOnly:                 true,
					Namespaces:               []string{"user"},
					PolicyPaths:              []string{"./testdata/misconfig/dockerfile/multiple-failures/rego"},
					DisableEmbeddedPolicies:  true,
					DisableEmbeddedLibraries: true,
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "dockerfile",
								FilePath: "Dockerfile",
								Successes: types.MisconfResults{
									types.MisconfResult{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											AVDID:              "AVD-TEST-0001",
											Type:               "Dockerfile Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References:         []string{"https://trivy.dev/"},
										},
										CauseMetadata: types.CauseMetadata{
											Provider: "Generic",
											Service:  "general",
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/dockerfile/multiple-failures/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:51cece3d563e9b42ab01cfabdc88b1294b49e4c168248337f8120bed4710dcff",
				BlobIDs: []string{
					"sha256:51cece3d563e9b42ab01cfabdc88b1294b49e4c168248337f8120bed4710dcff",
				},
			},
		},
		{
			name: "no results",
			fields: fields{
				dir: "./testdata/misconfig/dockerfile/no-results/src",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					RegoOnly:    true,
					Namespaces:  []string{"user"},
					PolicyPaths: []string{"./testdata/misconfig/dockerfile/no-results/rego"},
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/dockerfile/no-results/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:49bb9fb76978538cfb4ed9c2e9a1360f3b18b8e46836315d66c5ee4e882015cf",
				BlobIDs: []string{
					"sha256:49bb9fb76978538cfb4ed9c2e9a1360f3b18b8e46836315d66c5ee4e882015cf",
				},
			},
		},
		{
			name: "passed",
			fields: fields{
				dir: "./testdata/misconfig/dockerfile/passed/src",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					RegoOnly:                 true,
					Namespaces:               []string{"user"},
					PolicyPaths:              []string{"./testdata/misconfig/dockerfile/passed/rego"},
					DisableEmbeddedPolicies:  true,
					DisableEmbeddedLibraries: true,
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "dockerfile",
								FilePath: "Dockerfile",
								Successes: []types.MisconfResult{
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											AVDID:              "AVD-TEST-0001",
											Type:               "Dockerfile Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References: []string{
												"https://trivy.dev/",
											},
										},
										CauseMetadata: types.CauseMetadata{
											Provider: "Generic",
											Service:  "general",
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/dockerfile/passed/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:ac5afaa7f92bb9c8fef11c137fbf84206ddf8bb67f325e548c572e93f837dbcb",
				BlobIDs: []string{
					"sha256:ac5afaa7f92bb9c8fef11c137fbf84206ddf8bb67f325e548c572e93f837dbcb",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := new(cache.MockArtifactCache)
			c.ApplyPutBlobExpectation(tt.putBlobExpectation)
			tt.artifactOpt.DisabledHandlers = []types.HandlerType{
				types.SystemFileFilteringPostHandler,
			}
			a, err := NewArtifact(tt.fields.dir, c, tt.artifactOpt)
			require.NoError(t, err)

			got, err := a.Inspect(context.Background())
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestKubernetesMisconfigurationScan(t *testing.T) {
	type fields struct {
		dir string
	}
	tests := []struct {
		name               string
		fields             fields
		putBlobExpectation cache.ArtifactCachePutBlobExpectation
		artifactOpt        artifact.Option
		want               types.ArtifactReference
	}{
		{
			name: "single failure",
			fields: fields{
				dir: "./testdata/misconfig/kubernetes/single-failure/src",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					RegoOnly:                 true,
					Namespaces:               []string{"user"},
					PolicyPaths:              []string{"./testdata/misconfig/kubernetes/single-failure/rego"},
					DisableEmbeddedPolicies:  true,
					DisableEmbeddedLibraries: true,
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "kubernetes",
								FilePath: "test.yaml",
								Failures: []types.MisconfResult{
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										Message:   "No evil containers allowed!",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											AVDID:              "AVD-TEST-0001",
											Type:               "Kubernetes Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References: []string{
												"https://trivy.dev/",
											},
										},
										CauseMetadata: types.CauseMetadata{
											Provider:  "Generic",
											Service:   "general",
											StartLine: 7,
											EndLine:   9,
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/kubernetes/single-failure/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:d130b47507232c35d73974c11ade9ea77cdf6b1bed8c648654c21e8abba579c9",
				BlobIDs: []string{
					"sha256:d130b47507232c35d73974c11ade9ea77cdf6b1bed8c648654c21e8abba579c9",
				},
			},
		},
		{
			name: "multiple failures",
			fields: fields{
				dir: "./testdata/misconfig/kubernetes/multiple-failures/src",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					RegoOnly:                 true,
					Namespaces:               []string{"user"},
					PolicyPaths:              []string{"./testdata/misconfig/kubernetes/multiple-failures/rego"},
					DisableEmbeddedPolicies:  true,
					DisableEmbeddedLibraries: true,
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "kubernetes",
								FilePath: "test.yaml",
								Failures: []types.MisconfResult{
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										Message:   "No evil containers allowed!",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											AVDID:              "AVD-TEST-0001",
											Type:               "Kubernetes Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References: []string{
												"https://trivy.dev/",
											},
										},
										CauseMetadata: types.CauseMetadata{
											Provider:  "Generic",
											Service:   "general",
											StartLine: 7,
											EndLine:   9,
										},
									},
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										Message:   "No evil containers allowed!",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											AVDID:              "AVD-TEST-0001",
											Type:               "Kubernetes Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References: []string{
												"https://trivy.dev/",
											},
										},
										CauseMetadata: types.CauseMetadata{
											Provider:  "Generic",
											Service:   "general",
											StartLine: 10,
											EndLine:   12,
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/kubernetes/multiple-failures/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:e924358c2a37c0aae0822e2ec7f6ee2bd4dbfc3d698494d5a755b543ed776bb8",
				BlobIDs: []string{
					"sha256:e924358c2a37c0aae0822e2ec7f6ee2bd4dbfc3d698494d5a755b543ed776bb8",
				},
			},
		},
		{
			name: "no results",
			fields: fields{
				dir: "./testdata/misconfig/kubernetes/no-results/src",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					RegoOnly:    true,
					Namespaces:  []string{"user"},
					PolicyPaths: []string{"./testdata/misconfig/kubernetes/no-results/rego"},
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/kubernetes/no-results/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:c0b237e0617e048af80db544471db2e733fd40902eed689c984d6579049b13f3",
				BlobIDs: []string{
					"sha256:c0b237e0617e048af80db544471db2e733fd40902eed689c984d6579049b13f3",
				},
			},
		},
		{
			name: "passed",
			fields: fields{
				dir: "./testdata/misconfig/kubernetes/passed/src",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					RegoOnly:                 true,
					Namespaces:               []string{"user"},
					PolicyPaths:              []string{"./testdata/misconfig/kubernetes/passed/rego"},
					DisableEmbeddedPolicies:  true,
					DisableEmbeddedLibraries: true,
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "kubernetes",
								FilePath: "test.yaml",
								Successes: []types.MisconfResult{
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											AVDID:              "AVD-TEST-0001",
											Type:               "Kubernetes Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References: []string{
												"https://trivy.dev/",
											},
										},
										CauseMetadata: types.CauseMetadata{
											Provider: "Generic",
											Service:  "general",
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/kubernetes/passed/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:7ef64d7ed23c91e5abf20d825e32ba5bfc8dafe56e6a844dcf2c977d0acd28e3",
				BlobIDs: []string{
					"sha256:7ef64d7ed23c91e5abf20d825e32ba5bfc8dafe56e6a844dcf2c977d0acd28e3",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := new(cache.MockArtifactCache)
			c.ApplyPutBlobExpectation(tt.putBlobExpectation)
			tt.artifactOpt.DisabledHandlers = []types.HandlerType{
				types.SystemFileFilteringPostHandler,
			}
			a, err := NewArtifact(tt.fields.dir, c, tt.artifactOpt)
			require.NoError(t, err)

			got, err := a.Inspect(context.Background())
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAzureARMMisconfigurationScan(t *testing.T) {
	type fields struct {
		dir string
	}
	tests := []struct {
		name               string
		fields             fields
		putBlobExpectation cache.ArtifactCachePutBlobExpectation
		artifactOpt        artifact.Option
		want               types.ArtifactReference
	}{
		{
			name: "single failure",
			fields: fields{
				dir: "./testdata/misconfig/azurearm/single-failure/src",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					RegoOnly:    true,
					Namespaces:  []string{"user"},
					PolicyPaths: []string{"./testdata/misconfig/azurearm/single-failure/rego"},
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: 2,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "azure-arm",
								FilePath: "deploy.json",
								Failures: types.MisconfResults{
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										Message:   "No account allowed!",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											AVDID:              "AVD-TEST-0001",
											Type:               "Azure ARM Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References:         []string{"https://trivy.dev/"},
										},
										CauseMetadata: types.CauseMetadata{
											Resource:  "resources[0]",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 30,
											EndLine:   40,
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/azurearm/single-failure/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:ed87c87190346945d3d259e027e36696dbc49b30d7c4cbdd61e0f4fbde916bb7",
				BlobIDs: []string{
					"sha256:ed87c87190346945d3d259e027e36696dbc49b30d7c4cbdd61e0f4fbde916bb7",
				},
			},
		},
		{
			name: "multiple failures",
			fields: fields{
				dir: "./testdata/misconfig/azurearm/multiple-failures/src",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					RegoOnly:    true,
					Namespaces:  []string{"user"},
					PolicyPaths: []string{"./testdata/misconfig/azurearm/multiple-failures/rego"},
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: 2,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "azure-arm",
								FilePath: "deploy.json",
								Failures: types.MisconfResults{
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										Message:   "No account allowed!",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											AVDID:              "AVD-TEST-0001",
											Type:               "Azure ARM Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References:         []string{"https://trivy.dev/"},
										},
										CauseMetadata: types.CauseMetadata{
											Resource:  "resources[0]",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 30,
											EndLine:   40,
										},
									},
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										Message:   "No account allowed!",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											AVDID:              "AVD-TEST-0001",
											Type:               "Azure ARM Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References:         []string{"https://trivy.dev/"},
										},
										CauseMetadata: types.CauseMetadata{
											Resource:  "resources[1]",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 41,
											EndLine:   51,
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/azurearm/multiple-failures/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:f7ef587ed2728002415e9779b2a47339bfa67f24b7c62a36144aad4547f1a910",
				BlobIDs: []string{
					"sha256:f7ef587ed2728002415e9779b2a47339bfa67f24b7c62a36144aad4547f1a910",
				},
			},
		},
		{
			name: "no results",
			fields: fields{
				dir: "./testdata/misconfig/azurearm/no-results/src",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					RegoOnly:    true,
					Namespaces:  []string{"user"},
					PolicyPaths: []string{"./testdata/misconfig/azurearm/no-results/rego"},
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/azurearm/no-results/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:49bb9fb76978538cfb4ed9c2e9a1360f3b18b8e46836315d66c5ee4e882015cf",
				BlobIDs: []string{
					"sha256:49bb9fb76978538cfb4ed9c2e9a1360f3b18b8e46836315d66c5ee4e882015cf",
				},
			},
		},
		{
			name: "passed",
			fields: fields{
				dir: "./testdata/misconfig/azurearm/passed/src",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					RegoOnly:    true,
					Namespaces:  []string{"user"},
					PolicyPaths: []string{"./testdata/misconfig/azurearm/passed/rego"},
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: 2,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "azure-arm",
								FilePath: "deploy.json",
								Successes: types.MisconfResults{
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											AVDID:              "AVD-TEST-0001",
											Type:               "Azure ARM Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References:         []string{"https://trivy.dev/"},
										},
										CauseMetadata: types.CauseMetadata{
											Provider: "Generic",
											Service:  "general",
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/azurearm/passed/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:58660e5f4aa24ac2bd642f5e25fab34e8d89d294d447742bed4da01d672ef3d1",
				BlobIDs: []string{
					"sha256:58660e5f4aa24ac2bd642f5e25fab34e8d89d294d447742bed4da01d672ef3d1",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := new(cache.MockArtifactCache)
			c.ApplyPutBlobExpectation(tt.putBlobExpectation)
			tt.artifactOpt.DisabledHandlers = []types.HandlerType{
				types.SystemFileFilteringPostHandler,
			}
			a, err := NewArtifact(tt.fields.dir, c, tt.artifactOpt)
			require.NoError(t, err)

			got, err := a.Inspect(context.Background())
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMixedConfigurationScan(t *testing.T) {
	type fields struct {
		dir string
	}
	tests := []struct {
		name               string
		fields             fields
		putBlobExpectation cache.ArtifactCachePutBlobExpectation
		artifactOpt        artifact.Option
		want               types.ArtifactReference
	}{
		{
			name: "single failure each within terraform and cloudformation",
			fields: fields{
				dir: "./testdata/misconfig/mixed/src",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					RegoOnly:                 true,
					Namespaces:               []string{"user"},
					PolicyPaths:              []string{"./testdata/misconfig/mixed/rego"},
					DisableEmbeddedPolicies:  true,
					DisableEmbeddedLibraries: true,
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: 2,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "terraform",
								FilePath: "main.tf",
								Failures: types.MisconfResults{
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										Message:   "No buckets allowed!",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											AVDID:              "AVD-TEST-0001",
											Type:               "Terraform Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References:         []string{"https://trivy.dev/"},
										},
										CauseMetadata: types.CauseMetadata{
											Resource:  "aws_s3_bucket.asd",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 1,
											EndLine:   3,
										},
									},
								},
							},
							{
								FileType: "cloudformation",
								FilePath: "main.yaml",
								Failures: types.MisconfResults{
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										Message:   "No buckets allowed!",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											AVDID:              "AVD-TEST-0001",
											Type:               "CloudFormation Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References:         []string{"https://trivy.dev/"},
										},
										CauseMetadata: types.CauseMetadata{
											Resource:  "main.yaml:3-6",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 3,
											EndLine:   6,
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/mixed/src",
				Type: types.ArtifactFilesystem,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := new(cache.MockArtifactCache)
			c.ApplyPutBlobExpectation(tt.putBlobExpectation)
			tt.artifactOpt.DisabledHandlers = []types.HandlerType{
				types.SystemFileFilteringPostHandler,
			}
			a, err := NewArtifact(tt.fields.dir, c, tt.artifactOpt)
			require.NoError(t, err)

			got, err := a.Inspect(context.Background())
			require.NoError(t, err)
			require.NotNil(t, got)

			assert.Equal(t, tt.want.Name, got.Name)
			assert.Equal(t, tt.want.Type, got.Type)
		})
	}

}
