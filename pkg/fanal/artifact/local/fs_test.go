package local

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
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
		want               artifact.Reference
		wantErr            string
	}{
		{
			name: "happy path",
			fields: fields{
				dir: "./testdata/alpine",
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobID: "sha256:e480047f53bccb8a9107a424fab43452dc59df641022a300d34326639254a0cf",
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
										ID:         "musl@1.1.24-r2",
										Name:       "musl",
										Version:    "1.1.24-r2",
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
			want: artifact.Reference{
				Name: "host",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:e480047f53bccb8a9107a424fab43452dc59df641022a300d34326639254a0cf",
				BlobIDs: []string{
					"sha256:e480047f53bccb8a9107a424fab43452dc59df641022a300d34326639254a0cf",
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
					BlobID: "sha256:7db98974b2231d3e25f4890008c4d42f6f26a7da5a8aba99e954dec97f050bd6",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifact.Reference{
				Name: "host",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:7db98974b2231d3e25f4890008c4d42f6f26a7da5a8aba99e954dec97f050bd6",
				BlobIDs: []string{
					"sha256:7db98974b2231d3e25f4890008c4d42f6f26a7da5a8aba99e954dec97f050bd6",
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
					BlobID: "sha256:e480047f53bccb8a9107a424fab43452dc59df641022a300d34326639254a0cf",
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
										ID:         "musl@1.1.24-r2",
										Name:       "musl",
										Version:    "1.1.24-r2",
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
					BlobID: "sha256:c91a594202ba114ce4d067d9cac40b545c7ba2a96520c9ca8050b437020c3ab9",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Applications: []types.Application{
							{
								Type:     "pip",
								FilePath: "requirements.txt",
								Packages: types.Packages{
									{
										Name:    "Flask",
										Version: "2.0.0",
										Locations: []types.Location{
											{
												StartLine: 1,
												EndLine:   1,
											},
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifact.Reference{
				Name: "testdata/requirements.txt",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:c91a594202ba114ce4d067d9cac40b545c7ba2a96520c9ca8050b437020c3ab9",
				BlobIDs: []string{
					"sha256:c91a594202ba114ce4d067d9cac40b545c7ba2a96520c9ca8050b437020c3ab9",
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
					BlobID: "sha256:c91a594202ba114ce4d067d9cac40b545c7ba2a96520c9ca8050b437020c3ab9",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Applications: []types.Application{
							{
								Type:     "pip",
								FilePath: "requirements.txt",
								Packages: types.Packages{
									{
										Name:    "Flask",
										Version: "2.0.0",
										Locations: []types.Location{
											{
												StartLine: 1,
												EndLine:   1,
											},
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifact.Reference{
				Name: "testdata/requirements.txt",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:c91a594202ba114ce4d067d9cac40b545c7ba2a96520c9ca8050b437020c3ab9",
				BlobIDs: []string{
					"sha256:c91a594202ba114ce4d067d9cac40b545c7ba2a96520c9ca8050b437020c3ab9",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := new(cache.MockArtifactCache)
			c.ApplyPutBlobExpectation(tt.putBlobExpectation)

			a, err := NewArtifact(tt.fields.dir, c, walker.NewFS(), tt.artifactOpt)
			require.NoError(t, err)

			got, err := a.Inspect(context.Background())
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

var terraformPolicyMetadata = types.PolicyMetadata{
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
		want               artifact.Reference
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
										PolicyMetadata: terraformPolicyMetadata,
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
			want: artifact.Reference{
				Name: "testdata/misconfig/terraform/single-failure",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:5e4ca8ffaa89f49c69acfbac6d7cebb0a372b07d4c4c9876f9a58043c8ee56e9",
				BlobIDs: []string{
					"sha256:5e4ca8ffaa89f49c69acfbac6d7cebb0a372b07d4c4c9876f9a58043c8ee56e9",
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
										PolicyMetadata: terraformPolicyMetadata,
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
										PolicyMetadata: terraformPolicyMetadata,
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
										PolicyMetadata: terraformPolicyMetadata,
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
			want: artifact.Reference{
				Name: "testdata/misconfig/terraform/multiple-failures",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:1832cedd0d8baeb172c7297acb56417c0dec454c280a79ee2a8f413e1ffca192",
				BlobIDs: []string{
					"sha256:1832cedd0d8baeb172c7297acb56417c0dec454c280a79ee2a8f413e1ffca192",
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
			want: artifact.Reference{
				Name: "testdata/misconfig/terraform/no-results",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:00e01cf7bf052dbf8f02739d281675eff16f5ddf004256472cdddb55cf974fd6",
				BlobIDs: []string{
					"sha256:00e01cf7bf052dbf8f02739d281675eff16f5ddf004256472cdddb55cf974fd6",
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
										PolicyMetadata: terraformPolicyMetadata,
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
			want: artifact.Reference{
				Name: "testdata/misconfig/terraform/passed",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:9ee9fe14c3fcff202bc8c72f9e20a3035442ae394ec5cd201e1cb29d2111b4e1",
				BlobIDs: []string{
					"sha256:9ee9fe14c3fcff202bc8c72f9e20a3035442ae394ec5cd201e1cb29d2111b4e1",
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
										PolicyMetadata: terraformPolicyMetadata,
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
										PolicyMetadata: terraformPolicyMetadata,
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
			want: artifact.Reference{
				Name: "testdata/misconfig/terraform/busted-relative-paths/child/main.tf",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:c3e6c9e68cd7a9900cd8aa690e1d5af174ddcc00ddb9438a858c3e329b9ea8f4",
				BlobIDs: []string{
					"sha256:c3e6c9e68cd7a9900cd8aa690e1d5af174ddcc00ddb9438a858c3e329b9ea8f4",
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
										PolicyMetadata: terraformPolicyMetadata,
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
			want: artifact.Reference{
				Name: "testdata/misconfig/terraform/tfvar-outside/tf",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:9ee9fe14c3fcff202bc8c72f9e20a3035442ae394ec5cd201e1cb29d2111b4e1",
				BlobIDs: []string{
					"sha256:9ee9fe14c3fcff202bc8c72f9e20a3035442ae394ec5cd201e1cb29d2111b4e1",
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
										PolicyMetadata: terraformPolicyMetadata,
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
										PolicyMetadata: terraformPolicyMetadata,
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
										PolicyMetadata: terraformPolicyMetadata,
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
			want: artifact.Reference{
				Name: "testdata/misconfig/terraform/relative-paths/child",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:44d28d3fc115f1f8dd3f8978c7e9432ba255dd82661c3810178276897e2d8fb7",
				BlobIDs: []string{
					"sha256:44d28d3fc115f1f8dd3f8978c7e9432ba255dd82661c3810178276897e2d8fb7",
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
			a, err := NewArtifact(tt.fields.dir, c, walker.NewFS(), tt.artifactOpt)
			require.NoError(t, err)

			got, err := a.Inspect(context.Background())
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

const emptyBucketCheck = `package user.something

__rego_metadata__ := {
	"id": "TEST001",
	"avd_id": "AVD-TEST-0001",
	"title": "Test policy",
	"short_code": "empty-bucket-name",
	"severity": "LOW",
	"description": "This is a test policy.",
	"recommended_actions": "Have a cup of tea.",
	"url": "https://trivy.dev/",
}

# taken from defsec rego lib to mimic behaviour
result(msg, cause) = result {
	metadata := object.get(cause, "__defsec_metadata", cause)
	result := {
		"msg": msg,
		"startline": object.get(metadata, "startline", 0),
		"endline": object.get(metadata, "endline", 0),
		"filepath": object.get(metadata, "filepath", ""),
		"explicit": object.get(metadata, "explicit", false),
		"managed": object.get(metadata, "managed", true),
		"fskey": object.get(metadata, "fskey", ""),
		"resource": object.get(metadata, "resource", ""),
	}
}

deny[res] {
	bucket := input.aws.s3.buckets[_]
	bucket.name.value == ""
	res := result("Empty bucket name!", bucket)
}`

var terraformPlanPolicyMetadata = types.PolicyMetadata{
	ID:                 "TEST001",
	AVDID:              "AVD-TEST-0001",
	Type:               "Terraform Plan Snapshot Security Check",
	Title:              "Test policy",
	Description:        "This is a test policy.",
	Severity:           "LOW",
	RecommendedActions: "Have a cup of tea.",
	References:         []string{"https://trivy.dev/"},
}

func TestTerraformPlanSnapshotMisconfScan(t *testing.T) {
	type fields struct {
		dir string
	}
	tests := []struct {
		name               string
		fields             fields
		putBlobExpectation cache.ArtifactCachePutBlobExpectation
		want               artifact.Reference
	}{
		{
			name: "single failure",
			fields: fields{

				dir: "./testdata/misconfig/terraformplan/snapshots/single-failure",
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: 2,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: types.TerraformPlanSnapshot,
								FilePath: "main.tf",
								Failures: types.MisconfResults{
									{
										Namespace:      "user.something",
										Query:          "data.user.something.deny",
										Message:        "Empty bucket name!",
										PolicyMetadata: terraformPlanPolicyMetadata,
										CauseMetadata: types.CauseMetadata{
											Resource:  "aws_s3_bucket.this",
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
			want: artifact.Reference{
				Name: "testdata/misconfig/terraformplan/snapshots/single-failure",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:39babdcb854331c58dc1e20c20dc67c2b4bda23895bf2861cc72d187de2bc716",
				BlobIDs: []string{
					"sha256:39babdcb854331c58dc1e20c20dc67c2b4bda23895bf2861cc72d187de2bc716",
				},
			},
		},
		{
			name: "multiple failures",
			fields: fields{
				dir: "./testdata/misconfig/terraformplan/snapshots/multiple-failures",
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: 2,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: types.TerraformPlanSnapshot,
								FilePath: "main.tf",
								Failures: types.MisconfResults{
									{
										Namespace:      "user.something",
										Query:          "data.user.something.deny",
										Message:        "Empty bucket name!",
										PolicyMetadata: terraformPlanPolicyMetadata,
										CauseMetadata: types.CauseMetadata{
											Resource:  "aws_s3_bucket.one",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 10,
											EndLine:   12,
										},
									},
									{
										Namespace:      "user.something",
										Query:          "data.user.something.deny",
										Message:        "Empty bucket name!",
										PolicyMetadata: terraformPlanPolicyMetadata,
										CauseMetadata: types.CauseMetadata{
											Resource:  "aws_s3_bucket.two",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 14,
											EndLine:   16,
										},
									},
								},
							},
							{
								FileType: types.TerraformPlanSnapshot,
								FilePath: "more.tf",
								Failures: types.MisconfResults{
									{
										Namespace:      "user.something",
										Query:          "data.user.something.deny",
										Message:        "Empty bucket name!",
										PolicyMetadata: terraformPlanPolicyMetadata,
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
			want: artifact.Reference{
				Name: "testdata/misconfig/terraformplan/snapshots/multiple-failures",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:32debc3c2857404ceeec978a938609a4b20f1c53c304603815955885377f286c",
				BlobIDs: []string{
					"sha256:32debc3c2857404ceeec978a938609a4b20f1c53c304603815955885377f286c",
				},
			},
		},
		{
			name: "passed",
			fields: fields{
				dir: "./testdata/misconfig/terraformplan/snapshots/passed",
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: 2,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: types.TerraformPlanSnapshot,
								FilePath: ".",
								Successes: types.MisconfResults{
									{
										Namespace:      "user.something",
										Query:          "data.user.something.deny",
										PolicyMetadata: terraformPlanPolicyMetadata,
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
			want: artifact.Reference{
				Name: "testdata/misconfig/terraformplan/snapshots/passed",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:2432b64e4583676ec1e94903d31c4faf79a1e0f4ed49bf24aef2bf9b44517ca2",
				BlobIDs: []string{
					"sha256:2432b64e4583676ec1e94903d31c4faf79a1e0f4ed49bf24aef2bf9b44517ca2",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			tmpDir := t.TempDir()
			f, err := os.Create(filepath.Join(tmpDir, "policy.rego"))
			require.NoError(t, err)
			defer f.Close()

			_, err = f.WriteString(emptyBucketCheck)
			require.NoError(t, err)

			c := new(cache.MockArtifactCache)
			c.ApplyPutBlobExpectation(tt.putBlobExpectation)

			opt := artifact.Option{
				DisabledHandlers: []types.HandlerType{
					types.SystemFileFilteringPostHandler,
				},
				MisconfScannerOption: misconf.ScannerOption{
					RegoOnly:                true,
					DisableEmbeddedPolicies: true,

					DisableEmbeddedLibraries: false,
					Namespaces:               []string{"user"},
					PolicyPaths:              []string{tmpDir},
				},
				WalkerOption: walker.Option{
					SkipFiles: []string{"*.tf"},
				},
			}

			a, err := NewArtifact(tt.fields.dir, c, walker.NewFS(), opt)
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
		want               artifact.Reference
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
			want: artifact.Reference{
				Name: "testdata/misconfig/cloudformation/single-failure/src",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:43bb7ce5253686cf96a68e6d4bd30c33e163019ae2893968602da9e5e86b1aab",
				BlobIDs: []string{
					"sha256:43bb7ce5253686cf96a68e6d4bd30c33e163019ae2893968602da9e5e86b1aab",
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
			want: artifact.Reference{
				Name: "testdata/misconfig/cloudformation/multiple-failures/src",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:4609d64f57187099483e76a979d2f74862a092a5f42a9945e6f1242c372a811c",
				BlobIDs: []string{
					"sha256:4609d64f57187099483e76a979d2f74862a092a5f42a9945e6f1242c372a811c",
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
			want: artifact.Reference{
				Name: "testdata/misconfig/cloudformation/no-results/src",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:a3d40c3290bf45542f9c0aa364f2c16aca06cdccb4868a2e442b7e6a56c6157a",
				BlobIDs: []string{
					"sha256:a3d40c3290bf45542f9c0aa364f2c16aca06cdccb4868a2e442b7e6a56c6157a",
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
			want: artifact.Reference{
				Name: "testdata/misconfig/cloudformation/params/code/src",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:abaeb2f443a59940afd63e015d0bb737127ebde06306840f529dd40d65390703",
				BlobIDs: []string{
					"sha256:abaeb2f443a59940afd63e015d0bb737127ebde06306840f529dd40d65390703",
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
			want: artifact.Reference{
				Name: "testdata/misconfig/cloudformation/passed/src",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:73bb13d7c722bfcdf6c00f51f368befda453e1acba31ba62aad31b5b04b235e8",
				BlobIDs: []string{
					"sha256:73bb13d7c722bfcdf6c00f51f368befda453e1acba31ba62aad31b5b04b235e8",
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
			a, err := NewArtifact(tt.fields.dir, c, walker.NewFS(), tt.artifactOpt)
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
		want               artifact.Reference
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
			want: artifact.Reference{
				Name: "testdata/misconfig/dockerfile/single-failure/src",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:059f081288e7ea418286bddcee78167e8ebf33b47e365c20754b6cfa180d997d",
				BlobIDs: []string{
					"sha256:059f081288e7ea418286bddcee78167e8ebf33b47e365c20754b6cfa180d997d",
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
			want: artifact.Reference{
				Name: "testdata/misconfig/dockerfile/multiple-failures/src",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:059f081288e7ea418286bddcee78167e8ebf33b47e365c20754b6cfa180d997d",
				BlobIDs: []string{
					"sha256:059f081288e7ea418286bddcee78167e8ebf33b47e365c20754b6cfa180d997d",
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
			want: artifact.Reference{
				Name: "testdata/misconfig/dockerfile/no-results/src",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:a3d40c3290bf45542f9c0aa364f2c16aca06cdccb4868a2e442b7e6a56c6157a",
				BlobIDs: []string{
					"sha256:a3d40c3290bf45542f9c0aa364f2c16aca06cdccb4868a2e442b7e6a56c6157a",
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
			want: artifact.Reference{
				Name: "testdata/misconfig/dockerfile/passed/src",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:5f6504b01b68ef1418d59210c0c7b3604fe63f8575a72721d1172d9d2fdd2e23",
				BlobIDs: []string{
					"sha256:5f6504b01b68ef1418d59210c0c7b3604fe63f8575a72721d1172d9d2fdd2e23",
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
			a, err := NewArtifact(tt.fields.dir, c, walker.NewFS(), tt.artifactOpt)
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
		want               artifact.Reference
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
			want: artifact.Reference{
				Name: "testdata/misconfig/kubernetes/single-failure/src",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:14768f3c82388c43e0af6579632535b5ecd6bd4ac802d063d74b636725191fe9",
				BlobIDs: []string{
					"sha256:14768f3c82388c43e0af6579632535b5ecd6bd4ac802d063d74b636725191fe9",
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
			want: artifact.Reference{
				Name: "testdata/misconfig/kubernetes/multiple-failures/src",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:d7b5fe7fb0e8d51cb6a06b5f2027b1e976e25a2462ff40241f86e13e69ff210c",
				BlobIDs: []string{
					"sha256:d7b5fe7fb0e8d51cb6a06b5f2027b1e976e25a2462ff40241f86e13e69ff210c",
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
			want: artifact.Reference{
				Name: "testdata/misconfig/kubernetes/no-results/src",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:ddd0e363b0ebab71250f9d36de65d485ca2faa9510ab6ddea940de7af8267b67",
				BlobIDs: []string{
					"sha256:ddd0e363b0ebab71250f9d36de65d485ca2faa9510ab6ddea940de7af8267b67",
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
			want: artifact.Reference{
				Name: "testdata/misconfig/kubernetes/passed/src",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:af77d733739a4366b6e03e95605f5282262d45905efed501d83ec7ecc97a7574",
				BlobIDs: []string{
					"sha256:af77d733739a4366b6e03e95605f5282262d45905efed501d83ec7ecc97a7574",
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
			a, err := NewArtifact(tt.fields.dir, c, walker.NewFS(), tt.artifactOpt)
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
		want               artifact.Reference
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
			want: artifact.Reference{
				Name: "testdata/misconfig/azurearm/single-failure/src",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:ff25ae7d346f724faf4d2653868bc249bf221460bcf6d364cf50372c303342d2",
				BlobIDs: []string{
					"sha256:ff25ae7d346f724faf4d2653868bc249bf221460bcf6d364cf50372c303342d2",
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
			want: artifact.Reference{
				Name: "testdata/misconfig/azurearm/multiple-failures/src",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:e5c5ad752c6ff8d26f1b6764a9fb6dec345157df7c816b86d491b0af9e9f4ae6",
				BlobIDs: []string{
					"sha256:e5c5ad752c6ff8d26f1b6764a9fb6dec345157df7c816b86d491b0af9e9f4ae6",
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
			want: artifact.Reference{
				Name: "testdata/misconfig/azurearm/no-results/src",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:a3d40c3290bf45542f9c0aa364f2c16aca06cdccb4868a2e442b7e6a56c6157a",
				BlobIDs: []string{
					"sha256:a3d40c3290bf45542f9c0aa364f2c16aca06cdccb4868a2e442b7e6a56c6157a",
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
			want: artifact.Reference{
				Name: "testdata/misconfig/azurearm/passed/src",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:0702eea6f699984f98c788c737f3adf74ae00db2b24b7d44577c7eedc31b1eb1",
				BlobIDs: []string{
					"sha256:0702eea6f699984f98c788c737f3adf74ae00db2b24b7d44577c7eedc31b1eb1",
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
			a, err := NewArtifact(tt.fields.dir, c, walker.NewFS(), tt.artifactOpt)
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
		want               artifact.Reference
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
			want: artifact.Reference{
				Name: "testdata/misconfig/mixed/src",
				Type: artifact.TypeFilesystem,
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
			a, err := NewArtifact(tt.fields.dir, c, walker.NewFS(), tt.artifactOpt)
			require.NoError(t, err)

			got, err := a.Inspect(context.Background())
			require.NoError(t, err)
			require.NotNil(t, got)

			assert.Equal(t, tt.want.Name, got.Name)
			assert.Equal(t, tt.want.Type, got.Type)
		})
	}

}
