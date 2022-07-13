package local

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/config"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/types"

	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/python/pip"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/alpine"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/pkg/apk"
	_ "github.com/aquasecurity/trivy/pkg/fanal/handler/misconf"
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
		scannerOpt         config.ScannerOption
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
					BlobID: "sha256:e29d5c9d3e152cc092c072a2327247c5877b67ef32fa57fe5e809e610581eee8",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						OS: &types.OS{
							Family: "alpine",
							Name:   "3.11.6",
						},
						PackageInfos: []types.PackageInfo{
							{
								FilePath: "lib/apk/db/installed",
								Packages: []types.Package{
									{
										Name: "musl", Version: "1.1.24-r2", SrcName: "musl", SrcVersion: "1.1.24-r2",
										Licenses: []string{"MIT"},
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
				ID:   "sha256:e29d5c9d3e152cc092c072a2327247c5877b67ef32fa57fe5e809e610581eee8",
				BlobIDs: []string{
					"sha256:e29d5c9d3e152cc092c072a2327247c5877b67ef32fa57fe5e809e610581eee8",
				},
			},
		},
		{
			name: "disable analyzers",
			fields: fields{
				dir: "./testdata/alpine",
			},
			artifactOpt: artifact.Option{
				DisabledAnalyzers: []analyzer.Type{analyzer.TypeAlpine, analyzer.TypeApk, analyzer.TypePip},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobID: "sha256:fde70b4b511bef3657811eb1b75d6f035ae384e79e102dabbcc971f4c2c092f2",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "host",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:fde70b4b511bef3657811eb1b75d6f035ae384e79e102dabbcc971f4c2c092f2",
				BlobIDs: []string{
					"sha256:fde70b4b511bef3657811eb1b75d6f035ae384e79e102dabbcc971f4c2c092f2",
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
					BlobID: "sha256:e29d5c9d3e152cc092c072a2327247c5877b67ef32fa57fe5e809e610581eee8",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						OS: &types.OS{
							Family: "alpine",
							Name:   "3.11.6",
						},
						PackageInfos: []types.PackageInfo{
							{
								FilePath: "lib/apk/db/installed",
								Packages: []types.Package{
									{
										Name: "musl", Version: "1.1.24-r2", SrcName: "musl", SrcVersion: "1.1.24-r2",
										Licenses: []string{"MIT"},
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
			wantErr: "no such file or directory",
		},
		{
			name: "happy path with single file",
			fields: fields{
				dir: "testdata/requirements.txt",
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobID: "sha256:ab8fb4bf2264989e68419e658112d84fe085fc92e6dc521c741a04a9840debc4",
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
				ID:   "sha256:ab8fb4bf2264989e68419e658112d84fe085fc92e6dc521c741a04a9840debc4",
				BlobIDs: []string{
					"sha256:ab8fb4bf2264989e68419e658112d84fe085fc92e6dc521c741a04a9840debc4",
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
					BlobID: "sha256:ab8fb4bf2264989e68419e658112d84fe085fc92e6dc521c741a04a9840debc4",
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
				ID:   "sha256:ab8fb4bf2264989e68419e658112d84fe085fc92e6dc521c741a04a9840debc4",
				BlobIDs: []string{
					"sha256:ab8fb4bf2264989e68419e658112d84fe085fc92e6dc521c741a04a9840debc4",
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

func TestBuildAbsPath(t *testing.T) {
	tests := []struct {
		name          string
		base          string
		paths         []string
		expectedPaths []string
	}{
		{"absolute path", "/testBase", []string{"/testPath"}, []string{"/testPath"}},
		{"relative path", "/testBase", []string{"testPath"}, []string{"/testBase/testPath"}},
		{"path have '.'", "/testBase", []string{"./testPath"}, []string{"/testBase/testPath"}},
		{"path have '..'", "/testBase", []string{"../testPath/"}, []string{"/testPath"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := buildAbsPaths(test.base, test.paths)
			if len(test.paths) != len(got) {
				t.Errorf("paths not equals, expected: %s, got: %s", test.expectedPaths, got)
			} else {
				for i, path := range test.expectedPaths {
					if path != got[i] {
						t.Errorf("paths not equals, expected: %s, got: %s", test.expectedPaths, got)
					}
				}
			}
		})
	}
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
				dir: "./testdata/misconfig/terraform/single-failure/src",
			},
			artifactOpt: artifact.Option{
				AnalyzerGroup:     "",
				DisabledAnalyzers: nil,
				DisabledHandlers:  nil,
				SkipFiles:         nil,
				SkipDirs:          nil,
				NoProgress:        false,
				Offline:           false,
				InsecureSkipTLS:   false,
				MisconfScannerOption: config.ScannerOption{
					RegoOnly:    true,
					Namespaces:  []string{"user"},
					PolicyPaths: []string{"./testdata/misconfig/terraform/single-failure/rego"},
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType:  "terraform",
								FilePath:  "main.tf",
								Successes: nil,
								Warnings:  nil,
								Failures: []types.MisconfResult{
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										Message:   "No buckets allowed!",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											Type:               "Terraform Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References: []string{
												"https://trivy.dev/",
											},
										},
										CauseMetadata: types.CauseMetadata{
											Resource:  "aws_s3_bucket.asd",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 1,
											EndLine:   3,
										},
										Traces: nil,
									},
								},
								Exceptions: nil,
								Layer:      types.Layer{},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/terraform/single-failure/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:03abbdc1bcc7c926d1748555471d92eb43dc536c04acf1de62596fe1f3d2c9c5",
				BlobIDs: []string{
					"sha256:03abbdc1bcc7c926d1748555471d92eb43dc536c04acf1de62596fe1f3d2c9c5",
				},
			},
		},
		{
			name: "multiple failures",
			fields: fields{
				dir: "./testdata/misconfig/terraform/multiple-failures/src",
			},
			artifactOpt: artifact.Option{
				AnalyzerGroup:     "",
				DisabledAnalyzers: nil,
				DisabledHandlers:  nil,
				SkipFiles:         nil,
				SkipDirs:          nil,
				NoProgress:        false,
				Offline:           false,
				InsecureSkipTLS:   false,
				MisconfScannerOption: config.ScannerOption{
					RegoOnly:    true,
					Namespaces:  []string{"user"},
					PolicyPaths: []string{"./testdata/misconfig/terraform/multiple-failures/rego"},
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType:  "terraform",
								FilePath:  "main.tf",
								Successes: nil,
								Warnings:  nil,
								Failures: []types.MisconfResult{
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										Message:   "No buckets allowed!",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											Type:               "Terraform Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References: []string{
												"https://trivy.dev/",
											},
										},
										CauseMetadata: types.CauseMetadata{
											Resource:  "aws_s3_bucket.two",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 5,
											EndLine:   7,
										},
										Traces: nil,
									},
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										Message:   "No buckets allowed!",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											Type:               "Terraform Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References: []string{
												"https://trivy.dev/",
											},
										},
										CauseMetadata: types.CauseMetadata{
											Resource:  "aws_s3_bucket.one",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 1,
											EndLine:   3,
										},
										Traces: nil,
									},
								},
								Exceptions: nil,
								Layer:      types.Layer{},
							},
							{
								FileType:  "terraform",
								FilePath:  "more.tf",
								Successes: nil,
								Warnings:  nil,
								Failures: []types.MisconfResult{
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										Message:   "No buckets allowed!",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											Type:               "Terraform Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References: []string{
												"https://trivy.dev/",
											},
										},
										CauseMetadata: types.CauseMetadata{
											Resource:  "aws_s3_bucket.three",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 2,
											EndLine:   4,
										},
										Traces: nil,
									},
								},
								Exceptions: nil,
								Layer:      types.Layer{},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/terraform/multiple-failures/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:bbd42aefa13f6486af696ac00235e33d46f77efba599c58983a4b4e3d03331e7",
				BlobIDs: []string{
					"sha256:bbd42aefa13f6486af696ac00235e33d46f77efba599c58983a4b4e3d03331e7",
				},
			},
		},
		{
			name: "no results",
			fields: fields{
				dir: "./testdata/misconfig/terraform/no-results/src",
			},
			artifactOpt: artifact.Option{
				AnalyzerGroup:     "",
				DisabledAnalyzers: nil,
				DisabledHandlers:  nil,
				SkipFiles:         nil,
				SkipDirs:          nil,
				NoProgress:        false,
				Offline:           false,
				InsecureSkipTLS:   false,
				MisconfScannerOption: config.ScannerOption{
					RegoOnly:    true,
					Namespaces:  []string{"user"},
					PolicyPaths: []string{"./testdata/misconfig/terraform/no-results/rego"},
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
				Name: "testdata/misconfig/terraform/no-results/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:add8251472956a3ddc6ce14fb0c5726219e018f2a0bd39678c3dcdd1003cd4d0",
				BlobIDs: []string{
					"sha256:add8251472956a3ddc6ce14fb0c5726219e018f2a0bd39678c3dcdd1003cd4d0",
				},
			},
		},
		{
			name: "passed",
			fields: fields{
				dir: "./testdata/misconfig/terraform/passed/src",
			},
			artifactOpt: artifact.Option{
				AnalyzerGroup:     "",
				DisabledAnalyzers: nil,
				DisabledHandlers:  nil,
				SkipFiles:         nil,
				SkipDirs:          nil,
				NoProgress:        false,
				Offline:           false,
				InsecureSkipTLS:   false,
				MisconfScannerOption: config.ScannerOption{
					RegoOnly:    true,
					Namespaces:  []string{"user"},
					PolicyPaths: []string{"./testdata/misconfig/terraform/passed/rego"},
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "terraform",
								FilePath: ".",
								Successes: []types.MisconfResult{
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										Message:   "",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											Type:               "Terraform Security Check",
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
											StartLine: 0,
											EndLine:   0,
										},
										Traces: nil,
									},
								},
								Layer: types.Layer{},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/terraform/passed/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:b8e52760313bc0130049eaad026cf566491fa3767d926d3ed3f397a8ba7a87db",
				BlobIDs: []string{
					"sha256:b8e52760313bc0130049eaad026cf566491fa3767d926d3ed3f397a8ba7a87db",
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
				types.GoModMergePostHandler,
			}
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
				AnalyzerGroup:     "",
				DisabledAnalyzers: nil,
				DisabledHandlers:  nil,
				SkipFiles:         nil,
				SkipDirs:          nil,
				NoProgress:        false,
				Offline:           false,
				InsecureSkipTLS:   false,
				MisconfScannerOption: config.ScannerOption{
					RegoOnly:    true,
					Namespaces:  []string{"user"},
					PolicyPaths: []string{"./testdata/misconfig/cloudformation/single-failure/rego"},
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType:  "cloudformation",
								FilePath:  "main.yaml",
								Successes: nil,
								Warnings:  nil,
								Failures: []types.MisconfResult{
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										Message:   "No buckets allowed!",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											Type:               "CloudFormation Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References: []string{
												"https://trivy.dev/",
											},
										},
										CauseMetadata: types.CauseMetadata{
											Resource:  "main.yaml:3-6",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 3,
											EndLine:   6,
										},
										Traces: nil,
									},
								},
								Exceptions: nil,
								Layer:      types.Layer{},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/cloudformation/single-failure/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:19bfaad84eb4eeb0293417f55abea8d724bf780230ccfd0ad2d2f9f1e96dfd33",
				BlobIDs: []string{
					"sha256:19bfaad84eb4eeb0293417f55abea8d724bf780230ccfd0ad2d2f9f1e96dfd33",
				},
			},
		},
		{
			name: "multiple failures",
			fields: fields{
				dir: "./testdata/misconfig/cloudformation/multiple-failures/src",
			},
			artifactOpt: artifact.Option{
				AnalyzerGroup:     "",
				DisabledAnalyzers: nil,
				DisabledHandlers:  nil,
				SkipFiles:         nil,
				SkipDirs:          nil,
				NoProgress:        false,
				Offline:           false,
				InsecureSkipTLS:   false,
				MisconfScannerOption: config.ScannerOption{
					RegoOnly:    true,
					Namespaces:  []string{"user"},
					PolicyPaths: []string{"./testdata/misconfig/cloudformation/multiple-failures/rego"},
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType:  "cloudformation",
								FilePath:  "main.yaml",
								Successes: nil,
								Warnings:  nil,
								Failures: []types.MisconfResult{
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										Message:   "No buckets allowed!",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											Type:               "CloudFormation Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References: []string{
												"https://trivy.dev/",
											},
										},
										CauseMetadata: types.CauseMetadata{
											Resource:  "main.yaml:2-5",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 2,
											EndLine:   5,
										},
										Traces: nil,
									},
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										Message:   "No buckets allowed!",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											Type:               "CloudFormation Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References: []string{
												"https://trivy.dev/",
											},
										},
										CauseMetadata: types.CauseMetadata{
											Resource:  "main.yaml:6-9",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 6,
											EndLine:   9,
										},
										Traces: nil,
									},
								},
								Exceptions: nil,
								Layer:      types.Layer{},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/cloudformation/multiple-failures/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:37d48c35d9e57b40c320ea5eebb44fb66a744e239816995f592226f414951dec",
				BlobIDs: []string{
					"sha256:37d48c35d9e57b40c320ea5eebb44fb66a744e239816995f592226f414951dec",
				},
			},
		},
		{
			name: "no results",
			fields: fields{
				dir: "./testdata/misconfig/cloudformation/no-results/src",
			},
			artifactOpt: artifact.Option{
				AnalyzerGroup:     "",
				DisabledAnalyzers: nil,
				DisabledHandlers:  nil,
				SkipFiles:         nil,
				SkipDirs:          nil,
				NoProgress:        false,
				Offline:           false,
				InsecureSkipTLS:   false,
				MisconfScannerOption: config.ScannerOption{
					RegoOnly:    true,
					Namespaces:  []string{"user"},
					PolicyPaths: []string{"./testdata/misconfig/cloudformation/no-results/rego"},
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
				ID:   "sha256:add8251472956a3ddc6ce14fb0c5726219e018f2a0bd39678c3dcdd1003cd4d0",
				BlobIDs: []string{
					"sha256:add8251472956a3ddc6ce14fb0c5726219e018f2a0bd39678c3dcdd1003cd4d0",
				},
			},
		},
		{
			name: "passed",
			fields: fields{
				dir: "./testdata/misconfig/cloudformation/passed/src",
			},
			artifactOpt: artifact.Option{
				AnalyzerGroup:     "",
				DisabledAnalyzers: nil,
				DisabledHandlers:  nil,
				SkipFiles:         nil,
				SkipDirs:          nil,
				NoProgress:        false,
				Offline:           false,
				InsecureSkipTLS:   false,
				MisconfScannerOption: config.ScannerOption{
					RegoOnly:    true,
					Namespaces:  []string{"user"},
					PolicyPaths: []string{"./testdata/misconfig/cloudformation/passed/rego"},
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
								Successes: []types.MisconfResult{
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										Message:   "",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											Type:               "CloudFormation Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References: []string{
												"https://trivy.dev/",
											},
										},
										CauseMetadata: types.CauseMetadata{
											Resource:  "",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 0,
											EndLine:   0,
										},
										Traces: nil,
									},
								},
								Layer: types.Layer{},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/cloudformation/passed/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:c038a53f562915d5f8639d502677655ecf3518c8aeb4939d99acf48aa47fd0ef",
				BlobIDs: []string{
					"sha256:c038a53f562915d5f8639d502677655ecf3518c8aeb4939d99acf48aa47fd0ef",
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
				types.GoModMergePostHandler,
			}
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
				AnalyzerGroup:     "",
				DisabledAnalyzers: nil,
				DisabledHandlers:  nil,
				SkipFiles:         nil,
				SkipDirs:          nil,
				NoProgress:        false,
				Offline:           false,
				InsecureSkipTLS:   false,
				MisconfScannerOption: config.ScannerOption{
					RegoOnly:                true,
					Namespaces:              []string{"user"},
					PolicyPaths:             []string{"./testdata/misconfig/dockerfile/single-failure/rego"},
					DisableEmbeddedPolicies: true,
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Digest:        "", DiffID: "",
						OS:           (*types.OS)(nil),
						Repository:   (*types.Repository)(nil),
						PackageInfos: []types.PackageInfo(nil),
						Applications: []types.Application(nil),
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "dockerfile",
								FilePath: "Dockerfile",
								Successes: types.MisconfResults{
									types.MisconfResult{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										Message:   "",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											Type:               "Dockerfile Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References:         []string{"https://trivy.dev/"},
										},
										CauseMetadata: types.CauseMetadata{
											Resource:  "",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 0,
											EndLine:   0,
											Code: types.Code{
												Lines: []types.Line(nil),
											},
										}, Traces: []string(nil),
									},
								},
								Warnings:   types.MisconfResults(nil),
								Failures:   types.MisconfResults(nil),
								Exceptions: types.MisconfResults(nil),
								Layer: types.Layer{
									Digest: "",
									DiffID: "",
								},
							},
						}, Secrets:      []types.Secret(nil),
						OpaqueDirs:      []string(nil),
						WhiteoutFiles:   []string(nil),
						BuildInfo:       (*types.BuildInfo)(nil),
						CustomResources: []types.CustomResource(nil),
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/dockerfile/single-failure/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:320f60bd080024711072599f58b7b42de7e1be0f7258cd8c96945cd6f468cdf5",
				BlobIDs: []string{
					"sha256:320f60bd080024711072599f58b7b42de7e1be0f7258cd8c96945cd6f468cdf5",
				},
			},
		},
		{
			name: "multiple failures",
			fields: fields{
				dir: "./testdata/misconfig/dockerfile/multiple-failures/src",
			},
			artifactOpt: artifact.Option{
				AnalyzerGroup:     "",
				DisabledAnalyzers: nil,
				DisabledHandlers:  nil,
				SkipFiles:         nil,
				SkipDirs:          nil,
				NoProgress:        false,
				Offline:           false,
				InsecureSkipTLS:   false,
				MisconfScannerOption: config.ScannerOption{
					RegoOnly:                true,
					Namespaces:              []string{"user"},
					PolicyPaths:             []string{"./testdata/misconfig/dockerfile/multiple-failures/rego"},
					DisableEmbeddedPolicies: true,
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Digest:        "",
						DiffID:        "",
						OS:            (*types.OS)(nil),
						Repository:    (*types.Repository)(nil),
						PackageInfos:  []types.PackageInfo(nil),
						Applications:  []types.Application(nil),
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "dockerfile",
								FilePath: "Dockerfile",
								Successes: types.MisconfResults{
									types.MisconfResult{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										Message:   "",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											Type:               "Dockerfile Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References:         []string{"https://trivy.dev/"},
										},
										CauseMetadata: types.CauseMetadata{
											Resource:  "",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 0,
											EndLine:   0,
											Code: types.Code{
												Lines: []types.Line(nil),
											},
										}, Traces: []string(nil),
									},
								},
								Warnings:   types.MisconfResults(nil),
								Failures:   types.MisconfResults(nil),
								Exceptions: types.MisconfResults(nil),
								Layer: types.Layer{
									Digest: "",
									DiffID: "",
								},
							},
						}, Secrets:      []types.Secret(nil),
						OpaqueDirs:      []string(nil),
						WhiteoutFiles:   []string(nil),
						BuildInfo:       (*types.BuildInfo)(nil),
						CustomResources: []types.CustomResource(nil),
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/dockerfile/multiple-failures/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:320f60bd080024711072599f58b7b42de7e1be0f7258cd8c96945cd6f468cdf5",
				BlobIDs: []string{
					"sha256:320f60bd080024711072599f58b7b42de7e1be0f7258cd8c96945cd6f468cdf5",
				},
			},
		},
		{
			name: "no results",
			fields: fields{
				dir: "./testdata/misconfig/dockerfile/no-results/src",
			},
			artifactOpt: artifact.Option{
				AnalyzerGroup:     "",
				DisabledAnalyzers: nil,
				DisabledHandlers:  nil,
				SkipFiles:         nil,
				SkipDirs:          nil,
				NoProgress:        false,
				Offline:           false,
				InsecureSkipTLS:   false,
				MisconfScannerOption: config.ScannerOption{
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
				ID:   "sha256:add8251472956a3ddc6ce14fb0c5726219e018f2a0bd39678c3dcdd1003cd4d0",
				BlobIDs: []string{
					"sha256:add8251472956a3ddc6ce14fb0c5726219e018f2a0bd39678c3dcdd1003cd4d0",
				},
			},
		},
		{
			name: "passed",
			fields: fields{
				dir: "./testdata/misconfig/dockerfile/passed/src",
			},
			artifactOpt: artifact.Option{
				AnalyzerGroup:     "",
				DisabledAnalyzers: nil,
				DisabledHandlers:  nil,
				SkipFiles:         nil,
				SkipDirs:          nil,
				NoProgress:        false,
				Offline:           false,
				InsecureSkipTLS:   false,
				MisconfScannerOption: config.ScannerOption{
					RegoOnly:                true,
					Namespaces:              []string{"user"},
					PolicyPaths:             []string{"./testdata/misconfig/dockerfile/passed/rego"},
					DisableEmbeddedPolicies: true,
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
										Message:   "",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
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
											Resource:  "",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 0,
											EndLine:   0,
										},
										Traces: nil,
									},
								},
								Layer: types.Layer{},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/dockerfile/passed/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:4f69d195ff570df5ac7330b4c93bf7986f2241ecd657b1671ecb01cc7f61adba",
				BlobIDs: []string{
					"sha256:4f69d195ff570df5ac7330b4c93bf7986f2241ecd657b1671ecb01cc7f61adba",
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
				types.GoModMergePostHandler,
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
				AnalyzerGroup:     "",
				DisabledAnalyzers: nil,
				DisabledHandlers:  nil,
				SkipFiles:         nil,
				SkipDirs:          nil,
				NoProgress:        false,
				Offline:           false,
				InsecureSkipTLS:   false,
				MisconfScannerOption: config.ScannerOption{
					RegoOnly:                true,
					Namespaces:              []string{"user"},
					PolicyPaths:             []string{"./testdata/misconfig/kubernetes/single-failure/rego"},
					DisableEmbeddedPolicies: true,
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType:  "kubernetes",
								FilePath:  "test.yaml",
								Successes: nil,
								Warnings:  nil,
								Failures: []types.MisconfResult{
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										Message:   "No evil containers allowed!",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
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
										Traces: nil,
									},
								},
								Exceptions: nil,
								Layer:      types.Layer{},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/kubernetes/single-failure/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:ca64df998fc60b05207c9eedce6d43bdb49ba2629ad50c009105911979bb7b8d",
				BlobIDs: []string{
					"sha256:ca64df998fc60b05207c9eedce6d43bdb49ba2629ad50c009105911979bb7b8d",
				},
			},
		},
		{
			name: "multiple failures",
			fields: fields{
				dir: "./testdata/misconfig/kubernetes/multiple-failures/src",
			},
			artifactOpt: artifact.Option{
				AnalyzerGroup:     "",
				DisabledAnalyzers: nil,
				DisabledHandlers:  nil,
				SkipFiles:         nil,
				SkipDirs:          nil,
				NoProgress:        false,
				Offline:           false,
				InsecureSkipTLS:   false,
				MisconfScannerOption: config.ScannerOption{
					RegoOnly:                true,
					Namespaces:              []string{"user"},
					PolicyPaths:             []string{"./testdata/misconfig/kubernetes/multiple-failures/rego"},
					DisableEmbeddedPolicies: true,
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType:  "kubernetes",
								FilePath:  "test.yaml",
								Successes: nil,
								Warnings:  nil,
								Failures: []types.MisconfResult{
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										Message:   "No evil containers allowed!",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
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
										Traces: nil,
									},
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										Message:   "No evil containers allowed!",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
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
										Traces: nil,
									},
								},
								Exceptions: nil,
								Layer:      types.Layer{},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/kubernetes/multiple-failures/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:e38f5be28202f6dcb990bdee7419549301b5df2434566d459d16be7551445e9f",
				BlobIDs: []string{
					"sha256:e38f5be28202f6dcb990bdee7419549301b5df2434566d459d16be7551445e9f",
				},
			},
		},
		{
			name: "no results",
			fields: fields{
				dir: "./testdata/misconfig/kubernetes/no-results/src",
			},
			artifactOpt: artifact.Option{
				AnalyzerGroup:     "",
				DisabledAnalyzers: nil,
				DisabledHandlers:  nil,
				SkipFiles:         nil,
				SkipDirs:          nil,
				NoProgress:        false,
				Offline:           false,
				InsecureSkipTLS:   false,
				MisconfScannerOption: config.ScannerOption{
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
				ID:   "sha256:16ac6a45b769fe27b0c6aa7307f44b01b567d7676ca42c1cdbaa9298b48f50d1",
				BlobIDs: []string{
					"sha256:16ac6a45b769fe27b0c6aa7307f44b01b567d7676ca42c1cdbaa9298b48f50d1",
				},
			},
		},
		{
			name: "passed",
			fields: fields{
				dir: "./testdata/misconfig/kubernetes/passed/src",
			},
			artifactOpt: artifact.Option{
				AnalyzerGroup:     "",
				DisabledAnalyzers: nil,
				DisabledHandlers:  nil,
				SkipFiles:         nil,
				SkipDirs:          nil,
				NoProgress:        false,
				Offline:           false,
				InsecureSkipTLS:   false,
				MisconfScannerOption: config.ScannerOption{
					RegoOnly:                true,
					Namespaces:              []string{"user"},
					PolicyPaths:             []string{"./testdata/misconfig/kubernetes/passed/rego"},
					DisableEmbeddedPolicies: true,
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
										Message:   "",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
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
											Resource:  "",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 0,
											EndLine:   0,
										},
										Traces: nil,
									},
								},
								Layer: types.Layer{},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/kubernetes/passed/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:7cd084413694a36ffb66d088e04262a60ea815ce4cfeb67040424dac4259b428",
				BlobIDs: []string{
					"sha256:7cd084413694a36ffb66d088e04262a60ea815ce4cfeb67040424dac4259b428",
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
				types.GoModMergePostHandler,
			}
			a, err := NewArtifact(tt.fields.dir, c, tt.artifactOpt)
			require.NoError(t, err)

			got, err := a.Inspect(context.Background())
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
