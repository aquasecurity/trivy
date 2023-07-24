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
					BlobID: "sha256:672f9ef8ca6794ee1771f25de1892d95ca62daf90b86ac139c59ba5ce46af31a",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						OS: types.OS{
							Family: "alpine",
							Name:   "3.11.6",
						},
						PackageInfos: []types.PackageInfo{
							{
								FilePath: "lib/apk/db/installed",
								Packages: []types.Package{
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
				ID:   "sha256:672f9ef8ca6794ee1771f25de1892d95ca62daf90b86ac139c59ba5ce46af31a",
				BlobIDs: []string{
					"sha256:672f9ef8ca6794ee1771f25de1892d95ca62daf90b86ac139c59ba5ce46af31a",
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
					BlobID: "sha256:fd1107d865ab0c59446ac4d6ef9bd432ae5c26b0eaf6595a88a63a552840c4ad",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "host",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:fd1107d865ab0c59446ac4d6ef9bd432ae5c26b0eaf6595a88a63a552840c4ad",
				BlobIDs: []string{
					"sha256:fd1107d865ab0c59446ac4d6ef9bd432ae5c26b0eaf6595a88a63a552840c4ad",
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
					BlobID: "sha256:672f9ef8ca6794ee1771f25de1892d95ca62daf90b86ac139c59ba5ce46af31a",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						OS: types.OS{
							Family: "alpine",
							Name:   "3.11.6",
						},
						PackageInfos: []types.PackageInfo{
							{
								FilePath: "lib/apk/db/installed",
								Packages: []types.Package{
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
			wantErr: "walk error",
		},
		{
			name: "happy path with single file",
			fields: fields{
				dir: "testdata/requirements.txt",
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobID: "sha256:645d67a882007d7e169553eeb0ff14390d98e6ffcf91cb8c5b2952beee064b48",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Applications: []types.Application{
							{
								Type:     "pip",
								FilePath: "requirements.txt",
								Libraries: []types.Package{
									{
										Name:    "Flask",
										Version: "2.0.0",
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
				ID:   "sha256:645d67a882007d7e169553eeb0ff14390d98e6ffcf91cb8c5b2952beee064b48",
				BlobIDs: []string{
					"sha256:645d67a882007d7e169553eeb0ff14390d98e6ffcf91cb8c5b2952beee064b48",
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
					BlobID: "sha256:645d67a882007d7e169553eeb0ff14390d98e6ffcf91cb8c5b2952beee064b48",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Applications: []types.Application{
							{
								Type:     "pip",
								FilePath: "requirements.txt",
								Libraries: []types.Package{
									{
										Name:    "Flask",
										Version: "2.0.0",
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
				ID:   "sha256:645d67a882007d7e169553eeb0ff14390d98e6ffcf91cb8c5b2952beee064b48",
				BlobIDs: []string{
					"sha256:645d67a882007d7e169553eeb0ff14390d98e6ffcf91cb8c5b2952beee064b48",
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
				ID:   "sha256:4ed328fab421f6058c774dd6f72afe59078cf5f94f4c7f1c5f26a358911b68d5",
				BlobIDs: []string{
					"sha256:4ed328fab421f6058c774dd6f72afe59078cf5f94f4c7f1c5f26a358911b68d5",
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
				ID:   "sha256:d744c516b47624f5ef7c526732fa55313fba7c0fffe10dc282201d79494de99f",
				BlobIDs: []string{
					"sha256:d744c516b47624f5ef7c526732fa55313fba7c0fffe10dc282201d79494de99f",
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
				ID:   "sha256:30a6ecf3504f2787f062f906f52d1b35f00517b7b392b3c6bf1ae12da4b22965",
				BlobIDs: []string{
					"sha256:30a6ecf3504f2787f062f906f52d1b35f00517b7b392b3c6bf1ae12da4b22965",
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
				ID:   "sha256:c65d70ddc5b6d5d74568b3bb14d78c648f8b006d6c3e72e00cd2163bdfcc97a2",
				BlobIDs: []string{
					"sha256:c65d70ddc5b6d5d74568b3bb14d78c648f8b006d6c3e72e00cd2163bdfcc97a2",
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
				ID:   "sha256:94407d4ef00be7a06be9494e04b1f6e05c770ca62bd8fae653efab68c670fa4e",
				BlobIDs: []string{
					"sha256:94407d4ef00be7a06be9494e04b1f6e05c770ca62bd8fae653efab68c670fa4e",
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
				ID:   "sha256:f115b62a58b10b5acb3718b08bcf4035c2288035498ed2ddbf1e496152a5dad0",
				BlobIDs: []string{
					"sha256:f115b62a58b10b5acb3718b08bcf4035c2288035498ed2ddbf1e496152a5dad0",
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
						SchemaVersion: 2,
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
				ID:   "sha256:611056ff4eccc47c62cbab18a649e15a74e078ed1d4e31b6224eebe098e3f7c2",
				BlobIDs: []string{
					"sha256:611056ff4eccc47c62cbab18a649e15a74e078ed1d4e31b6224eebe098e3f7c2",
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
				ID:   "sha256:650235071d362b7247d506d41cb49df69af8522c84350a519bb8db5dff1c3a42",
				BlobIDs: []string{
					"sha256:650235071d362b7247d506d41cb49df69af8522c84350a519bb8db5dff1c3a42",
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
				ID:   "sha256:96d6a920e15b3b266460c33ef0d398c3f2e7be97065154e8d8204694b8c88488",
				BlobIDs: []string{
					"sha256:96d6a920e15b3b266460c33ef0d398c3f2e7be97065154e8d8204694b8c88488",
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
						SchemaVersion: 2,
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
				ID:   "sha256:e643d26b51d48428bb19072158428319e179378ee1106f55b8a16e517a1e884f",
				BlobIDs: []string{
					"sha256:e643d26b51d48428bb19072158428319e179378ee1106f55b8a16e517a1e884f",
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
				ID:   "sha256:82cdddfdd8f088abea282d6cc74f79156d94a1ae45a5f023b215e52405c036a4",
				BlobIDs: []string{
					"sha256:82cdddfdd8f088abea282d6cc74f79156d94a1ae45a5f023b215e52405c036a4",
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
				ID:   "sha256:82cdddfdd8f088abea282d6cc74f79156d94a1ae45a5f023b215e52405c036a4",
				BlobIDs: []string{
					"sha256:82cdddfdd8f088abea282d6cc74f79156d94a1ae45a5f023b215e52405c036a4",
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
				ID:   "sha256:96d6a920e15b3b266460c33ef0d398c3f2e7be97065154e8d8204694b8c88488",
				BlobIDs: []string{
					"sha256:96d6a920e15b3b266460c33ef0d398c3f2e7be97065154e8d8204694b8c88488",
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
				ID:   "sha256:2a780e1bf6ba9544f430d58f264228fd3dfa29011dd931c51e3f339bbabf3643",
				BlobIDs: []string{
					"sha256:2a780e1bf6ba9544f430d58f264228fd3dfa29011dd931c51e3f339bbabf3643",
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
				ID:   "sha256:ea3e323fe8a150ff4fd2224ef7cb5d66ab441b91aa369afd309ca3de0f9df953",
				BlobIDs: []string{
					"sha256:ea3e323fe8a150ff4fd2224ef7cb5d66ab441b91aa369afd309ca3de0f9df953",
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
				ID:   "sha256:a9be0ac04c6d41f203a338622125817f3c63016437bed739b41e854ca788d4f8",
				BlobIDs: []string{
					"sha256:a9be0ac04c6d41f203a338622125817f3c63016437bed739b41e854ca788d4f8",
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
				ID:   "sha256:47d74071ea6e099bf001cb6a264623518151a8b5e277054069b51bcd3d900941",
				BlobIDs: []string{
					"sha256:47d74071ea6e099bf001cb6a264623518151a8b5e277054069b51bcd3d900941",
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
				ID:   "sha256:e60f6947d4684696b7a675ff4a5318bf64e95db0b23ab964a188d41dcf2b6fe3",
				BlobIDs: []string{
					"sha256:e60f6947d4684696b7a675ff4a5318bf64e95db0b23ab964a188d41dcf2b6fe3",
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
				ID:   "sha256:cf1369df0d0ba9632953f55b49b7c82d7aab45c67e596346c7c12add68ba506b",
				BlobIDs: []string{
					"sha256:cf1369df0d0ba9632953f55b49b7c82d7aab45c67e596346c7c12add68ba506b",
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
				ID:   "sha256:af2d0cb4bfd0d1e16def15fe5eb2311398df372db0e12630f2e334a492101d89",
				BlobIDs: []string{
					"sha256:af2d0cb4bfd0d1e16def15fe5eb2311398df372db0e12630f2e334a492101d89",
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
				ID:   "sha256:96d6a920e15b3b266460c33ef0d398c3f2e7be97065154e8d8204694b8c88488",
				BlobIDs: []string{
					"sha256:96d6a920e15b3b266460c33ef0d398c3f2e7be97065154e8d8204694b8c88488",
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
				ID:   "sha256:8ed564b5d66bf2bda3dd8ea736b6e53d2d8accd42820d4d5a5e5262bb42c6fd8",
				BlobIDs: []string{
					"sha256:8ed564b5d66bf2bda3dd8ea736b6e53d2d8accd42820d4d5a5e5262bb42c6fd8",
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
