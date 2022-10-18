package local

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/config"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/types"

	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/config/all"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/python/pip"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/alpine"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/pkg/apk"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/secret"
	_ "github.com/aquasecurity/trivy/pkg/fanal/handler/misconf"
	_ "github.com/aquasecurity/trivy/pkg/fanal/handler/sysfile"
)

func TestArtifact_Inspect(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping test on Windows")
	}
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
				dir: filepath.Join("testdata", "alpine"),
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobID: "sha256:658c6963af963e5537c5330857d082fceeee4f916c3223b280c7b815d7be7787",
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
										ID:   "musl@1.1.24-r2",
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

				ID: "sha256:658c6963af963e5537c5330857d082fceeee4f916c3223b280c7b815d7be7787",
				BlobIDs: []string{
					"sha256:658c6963af963e5537c5330857d082fceeee4f916c3223b280c7b815d7be7787",
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
					BlobID: "sha256:44b3bdb81eb5dedef26e5c06fd6ef8a0df7b6925910942b00b6fced3a720a61c",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "host",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:44b3bdb81eb5dedef26e5c06fd6ef8a0df7b6925910942b00b6fced3a720a61c",
				BlobIDs: []string{
					"sha256:44b3bdb81eb5dedef26e5c06fd6ef8a0df7b6925910942b00b6fced3a720a61c",
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
					BlobID: "sha256:7177f27ce94e21305ba8efe2ced3533ba9be66bd251aaa217615469a29ed86a9",
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
										ID:   "musl@1.1.24-r2",
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
				dir: filepath.Join("testdata", "requirements.txt"),
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobID: "sha256:2d951e57cafb6f05f16ae0c70aad084bc613464d53beb2bfc448a7300f62dc7d",
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
				Name: filepath.Join("testdata", "requirements.txt"),
				Type: types.ArtifactFilesystem,
				ID:   "sha256:2d951e57cafb6f05f16ae0c70aad084bc613464d53beb2bfc448a7300f62dc7d",
				BlobIDs: []string{
					"sha256:2d951e57cafb6f05f16ae0c70aad084bc613464d53beb2bfc448a7300f62dc7d",
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
					BlobID: "sha256:2d951e57cafb6f05f16ae0c70aad084bc613464d53beb2bfc448a7300f62dc7d",
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
				Name: filepath.Join("testdata", "requirements.txt"),
				Type: types.ArtifactFilesystem,
				ID:   "sha256:2d951e57cafb6f05f16ae0c70aad084bc613464d53beb2bfc448a7300f62dc7d",
				BlobIDs: []string{
					"sha256:2d951e57cafb6f05f16ae0c70aad084bc613464d53beb2bfc448a7300f62dc7d",
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
		{
			"absolute path", filepath.Join(string(os.PathSeparator), "testBase"),
			[]string{filepath.Join(string(os.PathSeparator), "testPath")},
			[]string{filepath.Join(string(os.PathSeparator), "testBase", "testPath")},
		},
		{
			"relative path", filepath.Join(string(os.PathSeparator), "testBase"),
			[]string{filepath.Join("testPath")},
			[]string{filepath.Join(string(os.PathSeparator), "testBase", "testPath")},
		},
		{
			"path have '.'", filepath.Join(string(os.PathSeparator), "testBase"),
			[]string{filepath.Join(".", string(os.PathSeparator), "testPath")},
			[]string{filepath.Join(string(os.PathSeparator), "testBase", "testPath")},
		},
		{
			"path have '..'", filepath.Join(string(os.PathSeparator), "testBase"),
			[]string{filepath.Join("..", string(os.PathSeparator), "testPath")},
			[]string{filepath.Join(string(os.PathSeparator), "testPath")},
		},

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
				dir: filepath.Join("testdata", "misconfig", "terraform", "single-failure", "src"),
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
					PolicyPaths: []string{filepath.Join("testdata", "misconfig", "terraform", "single-failure", "rego")},
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: 2, Digest: "", DiffID: "", CreatedBy: "", OpaqueDirs: []string(nil),
						WhiteoutFiles: []string(nil), OS: (*types.OS)(nil), Repository: (*types.Repository)(nil),
						PackageInfos: []types.PackageInfo(nil), Applications: []types.Application(nil),
						Misconfigurations: []types.Misconfiguration{
							types.Misconfiguration{
								FileType: "terraform", FilePath: ".", Successes: types.MisconfResults{
									types.MisconfResult{
										Namespace: "builtin.aws.rds.aws0176",
										Query:     "data.builtin.aws.rds.aws0176.deny", Message: "",
										PolicyMetadata: types.PolicyMetadata{
											ID: "N/A", AVDID: "AVD-AWS-0176", Type: "Terraform Security Check",
											Title:              "RDS IAM Database Authentication Disabled",
											Description:        "Ensure IAM Database Authentication is enabled for RDS database instances to manage database access",
											Severity:           "MEDIUM",
											RecommendedActions: "Modify the PostgreSQL and MySQL type RDS instances to enable IAM database authentication.",
											References:         []string{"https://docs.aws.amazon.com/neptune/latest/userguide/iam-auth.html"},
										}, CauseMetadata: types.CauseMetadata{
											Resource: "", Provider: "AWS", Service: "rds", StartLine: 0, EndLine: 0,
											Code: types.Code{Lines: []types.Line(nil)},
										}, Traces: []string(nil),
									}, types.MisconfResult{
										Namespace: "builtin.aws.rds.aws0177",
										Query:     "data.builtin.aws.rds.aws0177.deny", Message: "",
										PolicyMetadata: types.PolicyMetadata{
											ID: "N/A", AVDID: "AVD-AWS-0177", Type: "Terraform Security Check",
											Title:              "RDS Deletion Protection Disabled",
											Description:        "Ensure deletion protection is enabled for RDS database instances.",
											Severity:           "MEDIUM",
											RecommendedActions: "Modify the RDS instances to enable deletion protection.",
											References:         []string{"https://aws.amazon.com/about-aws/whats-new/2018/09/amazon-rds-now-provides-database-deletion-protection/"},
										}, CauseMetadata: types.CauseMetadata{
											Resource: "", Provider: "AWS", Service: "rds", StartLine: 0, EndLine: 0,
											Code: types.Code{Lines: []types.Line(nil)},
										}, Traces: []string(nil),
									},
								}, Warnings: types.MisconfResults(nil), Failures: types.MisconfResults(nil),
								Exceptions: types.MisconfResults(nil),
								Layer:      types.Layer{Digest: "", DiffID: "", CreatedBy: ""},
							}, types.Misconfiguration{
								FileType: "terraform", FilePath: "main.tf", Successes: types.MisconfResults(nil),
								Warnings: types.MisconfResults(nil), Failures: types.MisconfResults{
									types.MisconfResult{
										Namespace: "user.something", Query: "data.user.something.deny",
										Message: "No buckets allowed!", PolicyMetadata: types.PolicyMetadata{
											ID: "TEST001", AVDID: "AVD-TEST-0001", Type: "Terraform Security Check",
											Title: "Test policy", Description: "This is a test policy.",
											Severity: "LOW", RecommendedActions: "Have a cup of tea.",
											References: []string{"https://trivy.dev/"},
										}, CauseMetadata: types.CauseMetadata{
											Resource: "aws_s3_bucket.asd", Provider: "Generic", Service: "general",
											StartLine: 1, EndLine: 3, Code: types.Code{Lines: []types.Line(nil)},
										}, Traces: []string(nil),
									},
								}, Exceptions: types.MisconfResults(nil),
								Layer:         types.Layer{Digest: "", DiffID: "", CreatedBy: ""},
							},
						}, Secrets: []types.Secret(nil), Licenses: []types.LicenseFile(nil),
						BuildInfo: (*types.BuildInfo)(nil), CustomResources: []types.CustomResource(nil),
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: filepath.Join("testdata", "misconfig", "terraform", "single-failure", "src"),
				Type: types.ArtifactFilesystem,
<<<<<<< HEAD
				ID:   "sha256:9827e4b06d1efa0853e8d75bafb4f95c4c778012b60cee114ce96042ea7c1b7b",
				BlobIDs: []string{
					"sha256:9827e4b06d1efa0853e8d75bafb4f95c4c778012b60cee114ce96042ea7c1b7b",
=======
				ID:   "sha256:458a1eb294c0c3f33b3c35f4d12dfb43820d4407ee970c9fb3da8a4f4123ed44",
				BlobIDs: []string{
					"sha256:458a1eb294c0c3f33b3c35f4d12dfb43820d4407ee970c9fb3da8a4f4123ed44",
>>>>>>> 4820b213 (fix: updating more tests to run on Windows)
				},
			},
		},
		{
			name: "multiple failures",
			fields: fields{
				dir: filepath.Join("testdata", "misconfig", "terraform", "multiple-failures", "src"),
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
					PolicyPaths: []string{filepath.Join("testdata", "misconfig", "terraform", "multiple-failures", "rego")},
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: 2, Digest: "", DiffID: "", CreatedBy: "", OpaqueDirs: []string(nil),
						WhiteoutFiles: []string(nil), OS: (*types.OS)(nil), Repository: (*types.Repository)(nil),
						PackageInfos: []types.PackageInfo(nil), Applications: []types.Application(nil),
						Misconfigurations: []types.Misconfiguration{
							types.Misconfiguration{
								FileType: "terraform", FilePath: ".", Successes: types.MisconfResults{
									types.MisconfResult{
										Namespace: "builtin.aws.rds.aws0176",
										Query:     "data.builtin.aws.rds.aws0176.deny", Message: "",
										PolicyMetadata: types.PolicyMetadata{
											ID: "N/A", AVDID: "AVD-AWS-0176", Type: "Terraform Security Check",
											Title:              "RDS IAM Database Authentication Disabled",
											Description:        "Ensure IAM Database Authentication is enabled for RDS database instances to manage database access",
											Severity:           "MEDIUM",
											RecommendedActions: "Modify the PostgreSQL and MySQL type RDS instances to enable IAM database authentication.",
											References:         []string{"https://docs.aws.amazon.com/neptune/latest/userguide/iam-auth.html"},
										}, CauseMetadata: types.CauseMetadata{
											Resource: "", Provider: "AWS", Service: "rds", StartLine: 0, EndLine: 0,
											Code: types.Code{Lines: []types.Line(nil)},
										}, Traces: []string(nil),
									}, types.MisconfResult{
										Namespace: "builtin.aws.rds.aws0177",
										Query:     "data.builtin.aws.rds.aws0177.deny", Message: "",
										PolicyMetadata: types.PolicyMetadata{
											ID: "N/A", AVDID: "AVD-AWS-0177", Type: "Terraform Security Check",
											Title:              "RDS Deletion Protection Disabled",
											Description:        "Ensure deletion protection is enabled for RDS database instances.",
											Severity:           "MEDIUM",
											RecommendedActions: "Modify the RDS instances to enable deletion protection.",
											References:         []string{"https://aws.amazon.com/about-aws/whats-new/2018/09/amazon-rds-now-provides-database-deletion-protection/"},
										}, CauseMetadata: types.CauseMetadata{
											Resource: "", Provider: "AWS", Service: "rds", StartLine: 0, EndLine: 0,
											Code: types.Code{Lines: []types.Line(nil)},
										}, Traces: []string(nil),
									},
								}, Warnings: types.MisconfResults(nil), Failures: types.MisconfResults(nil),
								Exceptions: types.MisconfResults(nil),
								Layer:      types.Layer{Digest: "", DiffID: "", CreatedBy: ""},
							}, types.Misconfiguration{
								FileType: "terraform", FilePath: "main.tf", Successes: types.MisconfResults(nil),
								Warnings: types.MisconfResults(nil), Failures: types.MisconfResults{
									types.MisconfResult{
										Namespace: "user.something", Query: "data.user.something.deny",
										Message: "No buckets allowed!", PolicyMetadata: types.PolicyMetadata{
											ID: "TEST001", AVDID: "AVD-TEST-0001", Type: "Terraform Security Check",
											Title: "Test policy", Description: "This is a test policy.",
											Severity: "LOW", RecommendedActions: "Have a cup of tea.",
											References: []string{"https://trivy.dev/"},
										}, CauseMetadata: types.CauseMetadata{
											Resource: "aws_s3_bucket.one", Provider: "Generic", Service: "general",
											StartLine: 1, EndLine: 3, Code: types.Code{Lines: []types.Line(nil)},
										}, Traces: []string(nil),
									}, types.MisconfResult{
										Namespace: "user.something", Query: "data.user.something.deny",
										Message: "No buckets allowed!", PolicyMetadata: types.PolicyMetadata{
											ID: "TEST001", AVDID: "AVD-TEST-0001", Type: "Terraform Security Check",
											Title: "Test policy", Description: "This is a test policy.",
											Severity: "LOW", RecommendedActions: "Have a cup of tea.",
											References: []string{"https://trivy.dev/"},
										}, CauseMetadata: types.CauseMetadata{
											Resource: "aws_s3_bucket.two", Provider: "Generic", Service: "general",
											StartLine: 5, EndLine: 7, Code: types.Code{Lines: []types.Line(nil)},
										}, Traces: []string(nil),
									},
								}, Exceptions: types.MisconfResults(nil),
								Layer:         types.Layer{Digest: "", DiffID: "", CreatedBy: ""},
							}, types.Misconfiguration{
								FileType: "terraform", FilePath: "more.tf", Successes: types.MisconfResults(nil),
								Warnings: types.MisconfResults(nil), Failures: types.MisconfResults{
									types.MisconfResult{
										Namespace: "user.something", Query: "data.user.something.deny",
										Message: "No buckets allowed!", PolicyMetadata: types.PolicyMetadata{
											ID: "TEST001", AVDID: "AVD-TEST-0001", Type: "Terraform Security Check",
											Title: "Test policy", Description: "This is a test policy.",
											Severity: "LOW", RecommendedActions: "Have a cup of tea.",
											References: []string{"https://trivy.dev/"},
										}, CauseMetadata: types.CauseMetadata{
											Resource: "aws_s3_bucket.three", Provider: "Generic", Service: "general",
											StartLine: 2, EndLine: 4, Code: types.Code{Lines: []types.Line(nil)},
										}, Traces: []string(nil),
									},
								}, Exceptions: types.MisconfResults(nil),
								Layer:         types.Layer{Digest: "", DiffID: "", CreatedBy: ""},
							},
						}, Secrets: []types.Secret(nil), Licenses: []types.LicenseFile(nil),
						BuildInfo: (*types.BuildInfo)(nil), CustomResources: []types.CustomResource(nil),
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: filepath.Join("testdata", "misconfig", "terraform", "multiple-failures", "src"),
				Type: types.ArtifactFilesystem,
<<<<<<< HEAD
				ID:   "sha256:5280d5ed00b245d916357a365dde2a87430bdef58bf8d3c26a4e9b7e67481f6b",
				BlobIDs: []string{
					"sha256:5280d5ed00b245d916357a365dde2a87430bdef58bf8d3c26a4e9b7e67481f6b",
=======
				ID:   "sha256:11fa774d1d61b577c4107418f422bb9e4a6e9b75ab453c024f15fd54855be31c",
				BlobIDs: []string{
					"sha256:11fa774d1d61b577c4107418f422bb9e4a6e9b75ab453c024f15fd54855be31c",
>>>>>>> 4820b213 (fix: updating more tests to run on Windows)
				},
			},
		},
		{
			name: "no results",
			fields: fields{
				dir: filepath.Join("testdata", "misconfig", "terraform", "no-results", "src"),
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
					PolicyPaths: []string{filepath.Join("testdata", "misconfig", "terraform", "no-results", "rego")},
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
				Name: filepath.Join("testdata", "misconfig", "terraform", "no-results", "src"),
				Type: types.ArtifactFilesystem,
<<<<<<< HEAD
				ID:   "sha256:cd80d8148f9b4cbc026f71a73d8dc1e35f79f6f39e4e52fe5e9a7821e9d09693",
				BlobIDs: []string{
					"sha256:cd80d8148f9b4cbc026f71a73d8dc1e35f79f6f39e4e52fe5e9a7821e9d09693",
=======
				ID:   "sha256:38ef4b416369d0cab47fdbae129940f97ac30ab2cf3d4fd7416f89312dae1033",
				BlobIDs: []string{
					"sha256:38ef4b416369d0cab47fdbae129940f97ac30ab2cf3d4fd7416f89312dae1033",
>>>>>>> 4820b213 (fix: updating more tests to run on Windows)
				},
			},
		},
		{
			name: "passed",
			fields: fields{
				dir: filepath.Join("testdata", "misconfig", "terraform", "passed", "src"),
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
					PolicyPaths: []string{filepath.Join("testdata", "misconfig", "terraform", "passed", "rego")},
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: 2, Digest: "", DiffID: "", CreatedBy: "", OpaqueDirs: []string(nil),
						WhiteoutFiles: []string(nil), OS: (*types.OS)(nil), Repository: (*types.Repository)(nil),
						PackageInfos: []types.PackageInfo(nil), Applications: []types.Application(nil),
						Misconfigurations: []types.Misconfiguration{
							types.Misconfiguration{
								FileType: "terraform", FilePath: ".", Successes: types.MisconfResults{
									types.MisconfResult{
										Namespace: "builtin.aws.rds.aws0176",
										Query:     "data.builtin.aws.rds.aws0176.deny", Message: "",
										PolicyMetadata: types.PolicyMetadata{
											ID: "N/A", AVDID: "AVD-AWS-0176", Type: "Terraform Security Check",
											Title:              "RDS IAM Database Authentication Disabled",
											Description:        "Ensure IAM Database Authentication is enabled for RDS database instances to manage database access",
											Severity:           "MEDIUM",
											RecommendedActions: "Modify the PostgreSQL and MySQL type RDS instances to enable IAM database authentication.",
											References:         []string{"https://docs.aws.amazon.com/neptune/latest/userguide/iam-auth.html"},
										}, CauseMetadata: types.CauseMetadata{
											Resource: "", Provider: "AWS", Service: "rds", StartLine: 0, EndLine: 0,
											Code: types.Code{Lines: []types.Line(nil)},
										}, Traces: []string(nil),
									}, types.MisconfResult{
										Namespace: "builtin.aws.rds.aws0177",
										Query:     "data.builtin.aws.rds.aws0177.deny", Message: "",
										PolicyMetadata: types.PolicyMetadata{
											ID: "N/A", AVDID: "AVD-AWS-0177", Type: "Terraform Security Check",
											Title:              "RDS Deletion Protection Disabled",
											Description:        "Ensure deletion protection is enabled for RDS database instances.",
											Severity:           "MEDIUM",
											RecommendedActions: "Modify the RDS instances to enable deletion protection.",
											References:         []string{"https://aws.amazon.com/about-aws/whats-new/2018/09/amazon-rds-now-provides-database-deletion-protection/"},
										}, CauseMetadata: types.CauseMetadata{
											Resource: "", Provider: "AWS", Service: "rds", StartLine: 0, EndLine: 0,
											Code: types.Code{Lines: []types.Line(nil)},
										}, Traces: []string(nil),
									}, types.MisconfResult{
										Namespace: "user.something", Query: "data.user.something.deny", Message: "",
										PolicyMetadata: types.PolicyMetadata{
											ID: "TEST001", AVDID: "AVD-TEST-0001", Type: "Terraform Security Check",
											Title: "Test policy", Description: "This is a test policy.",
											Severity: "LOW", RecommendedActions: "Have a cup of tea.",
											References: []string{"https://trivy.dev/"},
										}, CauseMetadata: types.CauseMetadata{
											Resource: "", Provider: "Generic", Service: "general", StartLine: 0,
											EndLine: 0, Code: types.Code{Lines: []types.Line(nil)},
										}, Traces: []string(nil),
									},
								}, Warnings: types.MisconfResults(nil), Failures: types.MisconfResults(nil),
								Exceptions: types.MisconfResults(nil),
								Layer:      types.Layer{Digest: "", DiffID: "", CreatedBy: ""},
							},
						}, Secrets: []types.Secret(nil), Licenses: []types.LicenseFile(nil),
						BuildInfo: (*types.BuildInfo)(nil), CustomResources: []types.CustomResource(nil),
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: filepath.Join("testdata", "misconfig", "terraform", "passed", "src"),
				Type: types.ArtifactFilesystem,
<<<<<<< HEAD
				ID:   "sha256:a765d67b40d8dafad114c8b57d817b3d2f03fce2b0d6cecbf057ac13a2d52662",
				BlobIDs: []string{
					"sha256:a765d67b40d8dafad114c8b57d817b3d2f03fce2b0d6cecbf057ac13a2d52662",
=======
				ID:   "sha256:a87bc349f7ac06d60af834950630a54c4aea1dbdfe8809d0b9afa2d01e0f66b3",
				BlobIDs: []string{
					"sha256:a87bc349f7ac06d60af834950630a54c4aea1dbdfe8809d0b9afa2d01e0f66b3",
>>>>>>> 4820b213 (fix: updating more tests to run on Windows)
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
				dir: filepath.Join("testdata", "misconfig", "cloudformation", "single-failure", "src"),
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
					PolicyPaths: []string{filepath.Join("testdata", "misconfig", "cloudformation", "single-failure", "rego")},
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: 2, Digest: "", DiffID: "", CreatedBy: "", OpaqueDirs: []string(nil),
						WhiteoutFiles: []string(nil), OS: (*types.OS)(nil), Repository: (*types.Repository)(nil),
						PackageInfos: []types.PackageInfo(nil), Applications: []types.Application(nil),
						Misconfigurations: []types.Misconfiguration{
							types.Misconfiguration{
								FileType: "cloudformation", FilePath: "main.yaml", Successes: types.MisconfResults{
									types.MisconfResult{
										Namespace: "builtin.aws.rds.aws0176",
										Query:     "data.builtin.aws.rds.aws0176.deny", Message: "",
										PolicyMetadata: types.PolicyMetadata{
											ID: "N/A", AVDID: "AVD-AWS-0176", Type: "CloudFormation Security Check",
											Title:              "RDS IAM Database Authentication Disabled",
											Description:        "Ensure IAM Database Authentication is enabled for RDS database instances to manage database access",
											Severity:           "MEDIUM",
											RecommendedActions: "Modify the PostgreSQL and MySQL type RDS instances to enable IAM database authentication.",
											References:         []string{"https://docs.aws.amazon.com/neptune/latest/userguide/iam-auth.html"},
										}, CauseMetadata: types.CauseMetadata{
											Resource: "", Provider: "AWS", Service: "rds", StartLine: 0, EndLine: 0,
											Code: types.Code{Lines: []types.Line(nil)},
										}, Traces: []string(nil),
									}, types.MisconfResult{
										Namespace: "builtin.aws.rds.aws0177",
										Query:     "data.builtin.aws.rds.aws0177.deny", Message: "",
										PolicyMetadata: types.PolicyMetadata{
											ID: "N/A", AVDID: "AVD-AWS-0177", Type: "CloudFormation Security Check",
											Title:              "RDS Deletion Protection Disabled",
											Description:        "Ensure deletion protection is enabled for RDS database instances.",
											Severity:           "MEDIUM",
											RecommendedActions: "Modify the RDS instances to enable deletion protection.",
											References:         []string{"https://aws.amazon.com/about-aws/whats-new/2018/09/amazon-rds-now-provides-database-deletion-protection/"},
										}, CauseMetadata: types.CauseMetadata{
											Resource: "", Provider: "AWS", Service: "rds", StartLine: 0, EndLine: 0,
											Code: types.Code{Lines: []types.Line(nil)},
										}, Traces: []string(nil),
									},
								}, Warnings: types.MisconfResults(nil), Failures: types.MisconfResults{
									types.MisconfResult{
										Namespace: "user.something", Query: "data.user.something.deny",
										Message: "No buckets allowed!", PolicyMetadata: types.PolicyMetadata{
											ID: "TEST001", AVDID: "AVD-TEST-0001",
											Type: "CloudFormation Security Check", Title: "Test policy",
											Description: "This is a test policy.", Severity: "LOW",
											RecommendedActions: "Have a cup of tea.",
											References:         []string{"https://trivy.dev/"},
										}, CauseMetadata: types.CauseMetadata{
											Resource: "main.yaml:3-6", Provider: "Generic", Service: "general",
											StartLine: 3, EndLine: 6, Code: types.Code{Lines: []types.Line(nil)},
										}, Traces: []string(nil),
									},
								}, Exceptions: types.MisconfResults(nil),
								Layer:         types.Layer{Digest: "", DiffID: "", CreatedBy: ""},
							},
						}, Secrets: []types.Secret(nil), Licenses: []types.LicenseFile(nil),
						BuildInfo: (*types.BuildInfo)(nil), CustomResources: []types.CustomResource(nil),
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: filepath.Join("testdata", "misconfig", "cloudformation", "single-failure", "src"),
				Type: types.ArtifactFilesystem,
<<<<<<< HEAD
				ID:   "sha256:16af3ef12417f03bab139674ad17636f5fb032a9f4e20f2092aeaa9ff0e3bc38",
				BlobIDs: []string{
					"sha256:16af3ef12417f03bab139674ad17636f5fb032a9f4e20f2092aeaa9ff0e3bc38",
=======
				ID:   "sha256:744c0600de76e82fcad6a6632fa6f4ef7171c93df59334615a0a77e10c5ebae0",
				BlobIDs: []string{
					"sha256:744c0600de76e82fcad6a6632fa6f4ef7171c93df59334615a0a77e10c5ebae0",
>>>>>>> 4820b213 (fix: updating more tests to run on Windows)
				},
			},
		},
		{
			name: "multiple failures",
			fields: fields{
				dir: filepath.Join("testdata", "misconfig", "cloudformation", "multiple-failures", "src"),
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
					PolicyPaths: []string{filepath.Join("testdata", "misconfig", "cloudformation", "multiple-failures", "rego")},
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: 2, Digest: "", DiffID: "", CreatedBy: "", OpaqueDirs: []string(nil),
						WhiteoutFiles: []string(nil), OS: (*types.OS)(nil), Repository: (*types.Repository)(nil),
						PackageInfos: []types.PackageInfo(nil), Applications: []types.Application(nil),
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "cloudformation", FilePath: "main.yaml", Successes: types.MisconfResults{
								types.MisconfResult{
									Namespace: "builtin.aws.rds.aws0176",
									Query:     "data.builtin.aws.rds.aws0176.deny", Message: "",
									PolicyMetadata: types.PolicyMetadata{
										ID: "N/A", AVDID: "AVD-AWS-0176", Type: "CloudFormation Security Check",
										Title:              "RDS IAM Database Authentication Disabled",
										Description:        "Ensure IAM Database Authentication is enabled for RDS database instances to manage database access",
										Severity:           "MEDIUM",
										RecommendedActions: "Modify the PostgreSQL and MySQL type RDS instances to enable IAM database authentication.",
										References:         []string{"https://docs.aws.amazon.com/neptune/latest/userguide/iam-auth.html"},
									}, CauseMetadata: types.CauseMetadata{
										Resource: "", Provider: "AWS", Service: "rds", StartLine: 0, EndLine: 0,
										Code: types.Code{Lines: []types.Line(nil)},
									}, Traces: []string(nil),
								}, types.MisconfResult{
									Namespace: "builtin.aws.rds.aws0177",
									Query:     "data.builtin.aws.rds.aws0177.deny", Message: "",
									PolicyMetadata: types.PolicyMetadata{
										ID: "N/A", AVDID: "AVD-AWS-0177", Type: "CloudFormation Security Check",
										Title:              "RDS Deletion Protection Disabled",
										Description:        "Ensure deletion protection is enabled for RDS database instances.",
										Severity:           "MEDIUM",
										RecommendedActions: "Modify the RDS instances to enable deletion protection.",
										References:         []string{"https://aws.amazon.com/about-aws/whats-new/2018/09/amazon-rds-now-provides-database-deletion-protection/"},
									}, CauseMetadata: types.CauseMetadata{
										Resource: "", Provider: "AWS", Service: "rds", StartLine: 0, EndLine: 0,
										Code: types.Code{Lines: []types.Line(nil)},
									}, Traces: []string(nil),
								},
							}, Warnings: types.MisconfResults(nil), Failures: types.MisconfResults{
								types.MisconfResult{
									Namespace: "user.something", Query: "data.user.something.deny",
									Message: "No buckets allowed!", PolicyMetadata: types.PolicyMetadata{
										ID: "TEST001", AVDID: "AVD-TEST-0001",
										Type: "CloudFormation Security Check", Title: "Test policy",
										Description: "This is a test policy.", Severity: "LOW",
										RecommendedActions: "Have a cup of tea.",
										References:         []string{"https://trivy.dev/"},
									}, CauseMetadata: types.CauseMetadata{
										Resource: "main.yaml:2-5", Provider: "Generic", Service: "general",
										StartLine: 2, EndLine: 5, Code: types.Code{Lines: []types.Line(nil)},
									}, Traces: []string(nil),
								}, types.MisconfResult{
									Namespace: "user.something", Query: "data.user.something.deny",
									Message: "No buckets allowed!", PolicyMetadata: types.PolicyMetadata{
										ID: "TEST001", AVDID: "AVD-TEST-0001",
										Type: "CloudFormation Security Check", Title: "Test policy",
										Description: "This is a test policy.", Severity: "LOW",
										RecommendedActions: "Have a cup of tea.",
										References:         []string{"https://trivy.dev/"},
									}, CauseMetadata: types.CauseMetadata{
										Resource: "main.yaml:6-9", Provider: "Generic", Service: "general",
										StartLine: 6, EndLine: 9, Code: types.Code{Lines: []types.Line(nil)},
									}, Traces: []string(nil),
								},
							}, Exceptions: types.MisconfResults(nil),
								Layer:     types.Layer{Digest: "", DiffID: "", CreatedBy: ""},
							},
						}, Secrets: []types.Secret(nil), Licenses: []types.LicenseFile(nil),
						BuildInfo: (*types.BuildInfo)(nil), CustomResources: []types.CustomResource(nil),
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: filepath.Join("testdata", "misconfig", "cloudformation", "multiple-failures", "src"),
				Type: types.ArtifactFilesystem,
<<<<<<< HEAD
				ID:   "sha256:10801795d3e822d09f0810255a82deeb572f4e298f91af3abe5fc358c10ba68c",
				BlobIDs: []string{
					"sha256:10801795d3e822d09f0810255a82deeb572f4e298f91af3abe5fc358c10ba68c",
=======
				ID:   "sha256:677f317d1fa4cff2f05060f1423ac13566f14c01abd2f379dfc7801e272549e7",
				BlobIDs: []string{
					"sha256:677f317d1fa4cff2f05060f1423ac13566f14c01abd2f379dfc7801e272549e7",
>>>>>>> 4820b213 (fix: updating more tests to run on Windows)
				},
			},
		},
		{
			name: "no results",
			fields: fields{
				dir: filepath.Join("testdata", "misconfig", "cloudformation", "no-results", "src"),
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
					PolicyPaths: []string{filepath.Join("testdata", "misconfig", "cloudformation", "no-results", "rego")},
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
				Name: filepath.Join("testdata", "misconfig", "cloudformation", "no-results", "src"),
				Type: types.ArtifactFilesystem,
<<<<<<< HEAD
				ID:   "sha256:cd80d8148f9b4cbc026f71a73d8dc1e35f79f6f39e4e52fe5e9a7821e9d09693",
				BlobIDs: []string{
					"sha256:cd80d8148f9b4cbc026f71a73d8dc1e35f79f6f39e4e52fe5e9a7821e9d09693",
=======
				ID:   "sha256:38ef4b416369d0cab47fdbae129940f97ac30ab2cf3d4fd7416f89312dae1033",
				BlobIDs: []string{
					"sha256:38ef4b416369d0cab47fdbae129940f97ac30ab2cf3d4fd7416f89312dae1033",
>>>>>>> 4820b213 (fix: updating more tests to run on Windows)
				},
			},
		},
		{
			name: "passed",
			fields: fields{
				dir: filepath.Join("testdata", "misconfig", "cloudformation", "passed", "src"),
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
					PolicyPaths: []string{filepath.Join("testdata", "misconfig", "cloudformation", "passed", "rego")},
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: 2, Digest: "", DiffID: "", CreatedBy: "", OpaqueDirs: []string(nil),
						WhiteoutFiles: []string(nil), OS: (*types.OS)(nil), Repository: (*types.Repository)(nil),
						PackageInfos: []types.PackageInfo(nil), Applications: []types.Application(nil),
						Misconfigurations: []types.Misconfiguration{
							types.Misconfiguration{
								FileType: "cloudformation", FilePath: "main.yaml", Successes: types.MisconfResults{
									types.MisconfResult{
										Namespace: "builtin.aws.rds.aws0176",
										Query:     "data.builtin.aws.rds.aws0176.deny", Message: "",
										PolicyMetadata: types.PolicyMetadata{
											ID: "N/A", AVDID: "AVD-AWS-0176", Type: "CloudFormation Security Check",
											Title:              "RDS IAM Database Authentication Disabled",
											Description:        "Ensure IAM Database Authentication is enabled for RDS database instances to manage database access",
											Severity:           "MEDIUM",
											RecommendedActions: "Modify the PostgreSQL and MySQL type RDS instances to enable IAM database authentication.",
											References:         []string{"https://docs.aws.amazon.com/neptune/latest/userguide/iam-auth.html"},
										}, CauseMetadata: types.CauseMetadata{
											Resource: "", Provider: "AWS", Service: "rds", StartLine: 0, EndLine: 0,
											Code: types.Code{Lines: []types.Line(nil)},
										}, Traces: []string(nil),
									}, types.MisconfResult{
										Namespace: "builtin.aws.rds.aws0177",
										Query:     "data.builtin.aws.rds.aws0177.deny", Message: "",
										PolicyMetadata: types.PolicyMetadata{
											ID: "N/A", AVDID: "AVD-AWS-0177", Type: "CloudFormation Security Check",
											Title:              "RDS Deletion Protection Disabled",
											Description:        "Ensure deletion protection is enabled for RDS database instances.",
											Severity:           "MEDIUM",
											RecommendedActions: "Modify the RDS instances to enable deletion protection.",
											References:         []string{"https://aws.amazon.com/about-aws/whats-new/2018/09/amazon-rds-now-provides-database-deletion-protection/"},
										}, CauseMetadata: types.CauseMetadata{
											Resource: "", Provider: "AWS", Service: "rds", StartLine: 0, EndLine: 0,
											Code: types.Code{Lines: []types.Line(nil)},
										}, Traces: []string(nil),
									}, types.MisconfResult{
										Namespace: "user.something", Query: "data.user.something.deny", Message: "",
										PolicyMetadata: types.PolicyMetadata{
											ID: "TEST001", AVDID: "AVD-TEST-0001",
											Type: "CloudFormation Security Check", Title: "Test policy",
											Description: "This is a test policy.", Severity: "LOW",
											RecommendedActions: "Have a cup of tea.",
											References:         []string{"https://trivy.dev/"},
										}, CauseMetadata: types.CauseMetadata{
											Resource: "", Provider: "Generic", Service: "general", StartLine: 0,
											EndLine: 0, Code: types.Code{Lines: []types.Line(nil)},
										}, Traces: []string(nil),
									},
								}, Warnings: types.MisconfResults(nil), Failures: types.MisconfResults(nil),
								Exceptions: types.MisconfResults(nil),
								Layer:      types.Layer{Digest: "", DiffID: "", CreatedBy: ""},
							},
						}, Secrets: []types.Secret(nil), Licenses: []types.LicenseFile(nil),
						BuildInfo: (*types.BuildInfo)(nil), CustomResources: []types.CustomResource(nil),
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: filepath.Join("testdata", "misconfig", "cloudformation", "passed", "src"),
				Type: types.ArtifactFilesystem,
<<<<<<< HEAD
				ID:   "sha256:30bc323c6eb7af47b561df826948fe3981ddd63c27c8a1f5bb516eeb0d361fef",
				BlobIDs: []string{
					"sha256:30bc323c6eb7af47b561df826948fe3981ddd63c27c8a1f5bb516eeb0d361fef",
=======
				ID:   "sha256:bebdb490cce18ffe93b0f228757935adf7570838c3ea5224ffcf268134818047",
				BlobIDs: []string{
					"sha256:bebdb490cce18ffe93b0f228757935adf7570838c3ea5224ffcf268134818047",
>>>>>>> 4820b213 (fix: updating more tests to run on Windows)
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
				dir: filepath.Join("testdata", "misconfig", "dockerfile", "single-failure", "src"),
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
					PolicyPaths:             []string{filepath.Join("testdata", "misconfig", "dockerfile", "single-failure", "rego")},
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
											AVDID:              "AVD-TEST-0001",
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
				Name: filepath.Join("testdata", "misconfig", "dockerfile", "single-failure", "src"),
				Type: types.ArtifactFilesystem,
<<<<<<< HEAD
				ID:   "sha256:d93b33f51c455c07767196c2b2eb3312e2b055b0e0db40704092d258fc0ed6ec",
				BlobIDs: []string{
					"sha256:d93b33f51c455c07767196c2b2eb3312e2b055b0e0db40704092d258fc0ed6ec",
=======
				ID:   "sha256:6867f245c495612965b32f5b47df6fd2e07de2fc9ba893a8a03f7c56873d6dbc",
				BlobIDs: []string{
					"sha256:6867f245c495612965b32f5b47df6fd2e07de2fc9ba893a8a03f7c56873d6dbc",
>>>>>>> 4820b213 (fix: updating more tests to run on Windows)
				},
			},
		},
		{
			name: "multiple failures",
			fields: fields{
				dir: filepath.Join("testdata", "misconfig", "dockerfile", "multiple-failures", "src"),
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
					PolicyPaths:             []string{filepath.Join("testdata", "misconfig", "dockerfile", "multiple-failures", "rego")},
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
											AVDID:              "AVD-TEST-0001",
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
				Name: filepath.Join("testdata", "misconfig", "dockerfile", "multiple-failures", "src"),
				Type: types.ArtifactFilesystem,
<<<<<<< HEAD
				ID:   "sha256:d93b33f51c455c07767196c2b2eb3312e2b055b0e0db40704092d258fc0ed6ec",
				BlobIDs: []string{
					"sha256:d93b33f51c455c07767196c2b2eb3312e2b055b0e0db40704092d258fc0ed6ec",
=======
				ID:   "sha256:6867f245c495612965b32f5b47df6fd2e07de2fc9ba893a8a03f7c56873d6dbc",
				BlobIDs: []string{
					"sha256:6867f245c495612965b32f5b47df6fd2e07de2fc9ba893a8a03f7c56873d6dbc",
>>>>>>> 4820b213 (fix: updating more tests to run on Windows)
				},
			},
		},
		{
			name: "no results",
			fields: fields{
				dir: filepath.Join("testdata", "misconfig", "dockerfile", "no-results", "src"),
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
					PolicyPaths: []string{filepath.Join("testdata", "misconfig", "dockerfile", "no-results", "rego")},
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
				Name: filepath.Join("testdata", "misconfig", "dockerfile", "no-results", "src"),
				Type: types.ArtifactFilesystem,
<<<<<<< HEAD
				ID:   "sha256:cd80d8148f9b4cbc026f71a73d8dc1e35f79f6f39e4e52fe5e9a7821e9d09693",
				BlobIDs: []string{
					"sha256:cd80d8148f9b4cbc026f71a73d8dc1e35f79f6f39e4e52fe5e9a7821e9d09693",
=======
				ID:   "sha256:38ef4b416369d0cab47fdbae129940f97ac30ab2cf3d4fd7416f89312dae1033",
				BlobIDs: []string{
					"sha256:38ef4b416369d0cab47fdbae129940f97ac30ab2cf3d4fd7416f89312dae1033",
>>>>>>> 4820b213 (fix: updating more tests to run on Windows)
				},
			},
		},
		{
			name: "passed",
			fields: fields{
				dir: filepath.Join("testdata", "misconfig", "dockerfile", "passed", "src"),
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
					PolicyPaths:             []string{filepath.Join("testdata", "misconfig", "dockerfile", "passed", "rego")},
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
				Name: filepath.Join("testdata", "misconfig", "dockerfile", "passed", "src"),
				Type: types.ArtifactFilesystem,
<<<<<<< HEAD
				ID:   "sha256:7218a8e53d2e3eb08efe9f9864767eb0fe6084eaaaef1480064096bbdc2c3f71",
				BlobIDs: []string{
					"sha256:7218a8e53d2e3eb08efe9f9864767eb0fe6084eaaaef1480064096bbdc2c3f71",
=======
				ID:   "sha256:82da45486da05060dd22c3242e2b285a3bd0c0e5868bfdc5bd06a14b28732e75",
				BlobIDs: []string{
					"sha256:82da45486da05060dd22c3242e2b285a3bd0c0e5868bfdc5bd06a14b28732e75",
>>>>>>> 4820b213 (fix: updating more tests to run on Windows)
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
				dir: filepath.Join("testdata", "misconfig", "kubernetes", "single-failure", "src"),
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
					PolicyPaths:             []string{filepath.Join("testdata", "misconfig", "kubernetes", "single-failure", "rego")},
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
				Name: filepath.Join("testdata", "misconfig", "kubernetes", "single-failure", "src"),
				Type: types.ArtifactFilesystem,
<<<<<<< HEAD
				ID:   "sha256:599ae82c0d032acbe75e24379b4320fb7f0a9818da50b4635c4f0645504d5a72",
				BlobIDs: []string{
					"sha256:599ae82c0d032acbe75e24379b4320fb7f0a9818da50b4635c4f0645504d5a72",
=======
				ID:   "sha256:2fd8622fab1a0c0fa5aa9ff584eadb6b239bea62349b9068784eefb2a1ff699c",
				BlobIDs: []string{
					"sha256:2fd8622fab1a0c0fa5aa9ff584eadb6b239bea62349b9068784eefb2a1ff699c",
>>>>>>> 4820b213 (fix: updating more tests to run on Windows)
				},
			},
		},
		{
			name: "multiple failures",
			fields: fields{
				dir: filepath.Join("testdata", "misconfig", "kubernetes", "multiple-failures", "src"),
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
					PolicyPaths:             []string{filepath.Join("testdata", "misconfig", "kubernetes", "multiple-failures", "rego")},
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
										Traces: nil,
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
				Name: filepath.Join("testdata", "misconfig", "kubernetes", "multiple-failures", "src"),
				Type: types.ArtifactFilesystem,
<<<<<<< HEAD
				ID:   "sha256:fd62e7fdfeffa3df4653c100cc87fe0bc83ddbca918c41b73c7a5724a64619df",
				BlobIDs: []string{
					"sha256:fd62e7fdfeffa3df4653c100cc87fe0bc83ddbca918c41b73c7a5724a64619df",
=======
				ID:   "sha256:4f1689e1988bafe397c1262ebdbbb268bb7492fe39345339a1dc1e1ab4325281",
				BlobIDs: []string{
					"sha256:4f1689e1988bafe397c1262ebdbbb268bb7492fe39345339a1dc1e1ab4325281",
>>>>>>> 4820b213 (fix: updating more tests to run on Windows)
				},
			},
		},
		{
			name: "no results",
			fields: fields{
				dir: filepath.Join("testdata", "misconfig", "kubernetes", "no-results", "src"),
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
					PolicyPaths: []string{filepath.Join("testdata", "misconfig", "kubernetes", "no-results", "rego")},
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
				Name: filepath.Join("testdata", "misconfig", "kubernetes", "no-results", "src"),
				Type: types.ArtifactFilesystem,
<<<<<<< HEAD
				ID:   "sha256:b46953af7375260e0bf264328c8b156ee3341ff46794c0f09c65bce78b0eddb9",
				BlobIDs: []string{
					"sha256:b46953af7375260e0bf264328c8b156ee3341ff46794c0f09c65bce78b0eddb9",
=======
				ID:   "sha256:3318ddda456d1a315da7768c3bf1d5cb7bb9b19906309bff8f89a7a7096da031",
				BlobIDs: []string{
					"sha256:3318ddda456d1a315da7768c3bf1d5cb7bb9b19906309bff8f89a7a7096da031",
>>>>>>> 4820b213 (fix: updating more tests to run on Windows)
				},
			},
		},
		{
			name: "passed",
			fields: fields{
				dir: filepath.Join("testdata", "misconfig", "kubernetes", "passed", "src"),
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
					PolicyPaths:             []string{filepath.Join("testdata", "misconfig", "kubernetes", "passed", "rego")},
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
				Name: filepath.Join("testdata", "misconfig", "kubernetes", "passed", "src"),
				Type: types.ArtifactFilesystem,
<<<<<<< HEAD
				ID:   "sha256:5b110611834af3e26a4c7aa5623f9e20098c46b394a29a0881a1a3852a114578",
				BlobIDs: []string{
					"sha256:5b110611834af3e26a4c7aa5623f9e20098c46b394a29a0881a1a3852a114578",
=======
				ID:   "sha256:605ff77f900c99e8ad22d3d9169e61e7bedd4980ca184f15530d79dcc09c7531",
				BlobIDs: []string{
					"sha256:605ff77f900c99e8ad22d3d9169e61e7bedd4980ca184f15530d79dcc09c7531",
>>>>>>> 4820b213 (fix: updating more tests to run on Windows)
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
				dir: filepath.Join("testdata", "misconfig", "azurearm", "single-failure", "src"),
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
					PolicyPaths: []string{filepath.Join("testdata", "misconfig", "azurearm", "single-failure", "rego")},
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: 2, Digest: "", DiffID: "", CreatedBy: "", OpaqueDirs: []string(nil),
						WhiteoutFiles: []string(nil), OS: (*types.OS)(nil), Repository: (*types.Repository)(nil),
						PackageInfos: []types.PackageInfo(nil), Applications: []types.Application(nil),
						Misconfigurations: []types.Misconfiguration{
							types.Misconfiguration{
								FileType: "azure-arm", FilePath: "deploy.json", Successes: types.MisconfResults{
									types.MisconfResult{
										Namespace: "builtin.aws.rds.aws0176",
										Query:     "data.builtin.aws.rds.aws0176.deny", Message: "",
										PolicyMetadata: types.PolicyMetadata{
											ID: "N/A", AVDID: "AVD-AWS-0176", Type: "Azure ARM Security Check",
											Title:              "RDS IAM Database Authentication Disabled",
											Description:        "Ensure IAM Database Authentication is enabled for RDS database instances to manage database access",
											Severity:           "MEDIUM",
											RecommendedActions: "Modify the PostgreSQL and MySQL type RDS instances to enable IAM database authentication.",
											References:         []string{"https://docs.aws.amazon.com/neptune/latest/userguide/iam-auth.html"},
										}, CauseMetadata: types.CauseMetadata{
											Resource: "", Provider: "AWS", Service: "rds", StartLine: 0, EndLine: 0,
											Code: types.Code{Lines: []types.Line(nil)},
										}, Traces: []string(nil),
									}, types.MisconfResult{
										Namespace: "builtin.aws.rds.aws0177",
										Query:     "data.builtin.aws.rds.aws0177.deny", Message: "",
										PolicyMetadata: types.PolicyMetadata{
											ID: "N/A", AVDID: "AVD-AWS-0177", Type: "Azure ARM Security Check",
											Title:              "RDS Deletion Protection Disabled",
											Description:        "Ensure deletion protection is enabled for RDS database instances.",
											Severity:           "MEDIUM",
											RecommendedActions: "Modify the RDS instances to enable deletion protection.",
											References:         []string{"https://aws.amazon.com/about-aws/whats-new/2018/09/amazon-rds-now-provides-database-deletion-protection/"},
										}, CauseMetadata: types.CauseMetadata{
											Resource: "", Provider: "AWS", Service: "rds", StartLine: 0, EndLine: 0,
											Code: types.Code{Lines: []types.Line(nil)},
										}, Traces: []string(nil),
									},
								}, Warnings: types.MisconfResults(nil), Failures: types.MisconfResults{
									types.MisconfResult{
										Namespace: "user.something", Query: "data.user.something.deny",
										Message: "No account allowed!", PolicyMetadata: types.PolicyMetadata{
											ID: "TEST001", AVDID: "AVD-TEST-0001", Type: "Azure ARM Security Check",
											Title: "Test policy", Description: "This is a test policy.",
											Severity: "LOW", RecommendedActions: "Have a cup of tea.",
											References: []string{"https://trivy.dev/"},
										}, CauseMetadata: types.CauseMetadata{
											Resource: "resources[0]", Provider: "Generic", Service: "general",
											StartLine: 29, EndLine: 39, Code: types.Code{Lines: []types.Line(nil)},
										}, Traces: []string(nil),
									},
								}, Exceptions: types.MisconfResults(nil),
								Layer:         types.Layer{Digest: "", DiffID: "", CreatedBy: ""},
							},
						}, Secrets: []types.Secret(nil), Licenses: []types.LicenseFile(nil),
						BuildInfo: (*types.BuildInfo)(nil), CustomResources: []types.CustomResource(nil),
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: filepath.Join("testdata", "misconfig", "azurearm", "single-failure", "src"),
				Type: types.ArtifactFilesystem,
<<<<<<< HEAD
				ID:   "sha256:1113fd88abfa3727496c9a5e2e47c522d0197fa0c58d9b0472ff5715aa5dbe79",
				BlobIDs: []string{
					"sha256:1113fd88abfa3727496c9a5e2e47c522d0197fa0c58d9b0472ff5715aa5dbe79",
=======
				ID:   "sha256:f53b0f81067dcff95ef63e0c07573d3277638ba737dd31afbdc0854eebfee6f1",
				BlobIDs: []string{
					"sha256:f53b0f81067dcff95ef63e0c07573d3277638ba737dd31afbdc0854eebfee6f1",
>>>>>>> 4820b213 (fix: updating more tests to run on Windows)
				},
			},
		},
		{
			name: "multiple failures",
			fields: fields{
				dir: filepath.Join("testdata", "misconfig", "azurearm", "multiple-failures", "src"),
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
					PolicyPaths: []string{filepath.Join("testdata", "misconfig", "azurearm", "multiple-failures", "rego")},
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: 2, Digest: "", DiffID: "", CreatedBy: "", OpaqueDirs: []string(nil),
						WhiteoutFiles: []string(nil), OS: (*types.OS)(nil), Repository: (*types.Repository)(nil),
						PackageInfos: []types.PackageInfo(nil), Applications: []types.Application(nil),
						Misconfigurations: []types.Misconfiguration{
							types.Misconfiguration{
								FileType: "azure-arm", FilePath: "deploy.json", Successes: types.MisconfResults{
									types.MisconfResult{
										Namespace: "builtin.aws.rds.aws0176",
										Query:     "data.builtin.aws.rds.aws0176.deny", Message: "",
										PolicyMetadata: types.PolicyMetadata{
											ID: "N/A", AVDID: "AVD-AWS-0176", Type: "Azure ARM Security Check",
											Title:              "RDS IAM Database Authentication Disabled",
											Description:        "Ensure IAM Database Authentication is enabled for RDS database instances to manage database access",
											Severity:           "MEDIUM",
											RecommendedActions: "Modify the PostgreSQL and MySQL type RDS instances to enable IAM database authentication.",
											References:         []string{"https://docs.aws.amazon.com/neptune/latest/userguide/iam-auth.html"},
										}, CauseMetadata: types.CauseMetadata{
											Resource: "", Provider: "AWS", Service: "rds", StartLine: 0, EndLine: 0,
											Code: types.Code{Lines: []types.Line(nil)},
										}, Traces: []string(nil),
									}, types.MisconfResult{
										Namespace: "builtin.aws.rds.aws0177",
										Query:     "data.builtin.aws.rds.aws0177.deny", Message: "",
										PolicyMetadata: types.PolicyMetadata{
											ID: "N/A", AVDID: "AVD-AWS-0177", Type: "Azure ARM Security Check",
											Title:              "RDS Deletion Protection Disabled",
											Description:        "Ensure deletion protection is enabled for RDS database instances.",
											Severity:           "MEDIUM",
											RecommendedActions: "Modify the RDS instances to enable deletion protection.",
											References:         []string{"https://aws.amazon.com/about-aws/whats-new/2018/09/amazon-rds-now-provides-database-deletion-protection/"},
										}, CauseMetadata: types.CauseMetadata{
											Resource: "", Provider: "AWS", Service: "rds", StartLine: 0, EndLine: 0,
											Code: types.Code{Lines: []types.Line(nil)},
										}, Traces: []string(nil),
									},
								}, Warnings: types.MisconfResults(nil), Failures: types.MisconfResults{
									types.MisconfResult{
										Namespace: "user.something", Query: "data.user.something.deny",
										Message: "No account allowed!", PolicyMetadata: types.PolicyMetadata{
											ID: "TEST001", AVDID: "AVD-TEST-0001", Type: "Azure ARM Security Check",
											Title: "Test policy", Description: "This is a test policy.",
											Severity: "LOW", RecommendedActions: "Have a cup of tea.",
											References: []string{"https://trivy.dev/"},
										}, CauseMetadata: types.CauseMetadata{
											Resource: "resources[0]", Provider: "Generic", Service: "general",
											StartLine: 29, EndLine: 39, Code: types.Code{Lines: []types.Line(nil)},
										}, Traces: []string(nil),
									}, types.MisconfResult{
										Namespace: "user.something", Query: "data.user.something.deny",
										Message: "No account allowed!", PolicyMetadata: types.PolicyMetadata{
											ID: "TEST001", AVDID: "AVD-TEST-0001", Type: "Azure ARM Security Check",
											Title: "Test policy", Description: "This is a test policy.",
											Severity: "LOW", RecommendedActions: "Have a cup of tea.",
											References: []string{"https://trivy.dev/"},
										}, CauseMetadata: types.CauseMetadata{
											Resource: "resources[1]", Provider: "Generic", Service: "general",
											StartLine: 40, EndLine: 50, Code: types.Code{Lines: []types.Line(nil)},
										}, Traces: []string(nil),
									},
								}, Exceptions: types.MisconfResults(nil),
								Layer:         types.Layer{Digest: "", DiffID: "", CreatedBy: ""},
							},
						}, Secrets: []types.Secret(nil), Licenses: []types.LicenseFile(nil),
						BuildInfo: (*types.BuildInfo)(nil), CustomResources: []types.CustomResource(nil),
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: filepath.Join("testdata", "misconfig", "azurearm", "multiple-failures", "src"),
				Type: types.ArtifactFilesystem,
<<<<<<< HEAD
				ID:   "sha256:f75d8c2df3cd95fa0972ad064ca7c4c4bfc614b69a1220bb1b0e31b0c97cf2aa",
				BlobIDs: []string{
					"sha256:f75d8c2df3cd95fa0972ad064ca7c4c4bfc614b69a1220bb1b0e31b0c97cf2aa",
=======
				ID:   "sha256:784ba59afa68c8c55b2c572f9ae3e4880df7f816527b06f9e429b5205909560b",
				BlobIDs: []string{
					"sha256:784ba59afa68c8c55b2c572f9ae3e4880df7f816527b06f9e429b5205909560b",
>>>>>>> 4820b213 (fix: updating more tests to run on Windows)
				},
			},
		},
		{
			name: "no results",
			fields: fields{
				dir: filepath.Join("testdata", "misconfig", "azurearm", "no-results", "src"),
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
					PolicyPaths: []string{filepath.Join("testdata", "misconfig", "azurearm", "no-results", "rego")},
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
				Name: filepath.Join("testdata", "misconfig", "azurearm", "no-results", "src"),
				Type: types.ArtifactFilesystem,
<<<<<<< HEAD
				ID:   "sha256:cd80d8148f9b4cbc026f71a73d8dc1e35f79f6f39e4e52fe5e9a7821e9d09693",
				BlobIDs: []string{
					"sha256:cd80d8148f9b4cbc026f71a73d8dc1e35f79f6f39e4e52fe5e9a7821e9d09693",
=======
				ID:   "sha256:38ef4b416369d0cab47fdbae129940f97ac30ab2cf3d4fd7416f89312dae1033",
				BlobIDs: []string{
					"sha256:38ef4b416369d0cab47fdbae129940f97ac30ab2cf3d4fd7416f89312dae1033",
>>>>>>> 4820b213 (fix: updating more tests to run on Windows)
				},
			},
		},
		{
			name: "passed",
			fields: fields{
				dir: filepath.Join("testdata", "misconfig", "azurearm", "passed", "src"),
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
					PolicyPaths: []string{filepath.Join("testdata", "misconfig", "azurearm", "passed", "rego")},
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: 2, Digest: "", DiffID: "", CreatedBy: "", OpaqueDirs: []string(nil),
						WhiteoutFiles: []string(nil), OS: (*types.OS)(nil), Repository: (*types.Repository)(nil),
						PackageInfos: []types.PackageInfo(nil), Applications: []types.Application(nil),
						Misconfigurations: []types.Misconfiguration{
							types.Misconfiguration{
								FileType: "azure-arm", FilePath: "deploy.json", Successes: types.MisconfResults{
									types.MisconfResult{
										Namespace: "builtin.aws.rds.aws0176",
										Query:     "data.builtin.aws.rds.aws0176.deny", Message: "",
										PolicyMetadata: types.PolicyMetadata{
											ID: "N/A", AVDID: "AVD-AWS-0176", Type: "Azure ARM Security Check",
											Title:              "RDS IAM Database Authentication Disabled",
											Description:        "Ensure IAM Database Authentication is enabled for RDS database instances to manage database access",
											Severity:           "MEDIUM",
											RecommendedActions: "Modify the PostgreSQL and MySQL type RDS instances to enable IAM database authentication.",
											References:         []string{"https://docs.aws.amazon.com/neptune/latest/userguide/iam-auth.html"},
										}, CauseMetadata: types.CauseMetadata{
											Resource: "", Provider: "AWS", Service: "rds", StartLine: 0, EndLine: 0,
											Code: types.Code{Lines: []types.Line(nil)},
										}, Traces: []string(nil),
									}, types.MisconfResult{
										Namespace: "builtin.aws.rds.aws0177",
										Query:     "data.builtin.aws.rds.aws0177.deny", Message: "",
										PolicyMetadata: types.PolicyMetadata{
											ID: "N/A", AVDID: "AVD-AWS-0177", Type: "Azure ARM Security Check",
											Title:              "RDS Deletion Protection Disabled",
											Description:        "Ensure deletion protection is enabled for RDS database instances.",
											Severity:           "MEDIUM",
											RecommendedActions: "Modify the RDS instances to enable deletion protection.",
											References:         []string{"https://aws.amazon.com/about-aws/whats-new/2018/09/amazon-rds-now-provides-database-deletion-protection/"},
										}, CauseMetadata: types.CauseMetadata{
											Resource: "", Provider: "AWS", Service: "rds", StartLine: 0, EndLine: 0,
											Code: types.Code{Lines: []types.Line(nil)},
										}, Traces: []string(nil),
									}, types.MisconfResult{
										Namespace: "user.something", Query: "data.user.something.deny", Message: "",
										PolicyMetadata: types.PolicyMetadata{
											ID: "TEST001", AVDID: "AVD-TEST-0001", Type: "Azure ARM Security Check",
											Title: "Test policy", Description: "This is a test policy.",
											Severity: "LOW", RecommendedActions: "Have a cup of tea.",
											References: []string{"https://trivy.dev/"},
										}, CauseMetadata: types.CauseMetadata{
											Resource: "", Provider: "Generic", Service: "general", StartLine: 0,
											EndLine: 0, Code: types.Code{Lines: []types.Line(nil)},
										}, Traces: []string(nil),
									},
								}, Warnings: types.MisconfResults(nil), Failures: types.MisconfResults(nil),
								Exceptions: types.MisconfResults(nil),
								Layer:      types.Layer{Digest: "", DiffID: "", CreatedBy: ""},
							},
						}, Secrets: []types.Secret(nil), Licenses: []types.LicenseFile(nil),
						BuildInfo: (*types.BuildInfo)(nil), CustomResources: []types.CustomResource(nil),
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: filepath.Join("testdata", "misconfig", "azurearm", "passed", "src"),
				Type: types.ArtifactFilesystem,
<<<<<<< HEAD
				ID:   "sha256:1776289fa9295540d5d38fe219a7e565b1d60d7eab2e33331209d9eee88528bb",
				BlobIDs: []string{
					"sha256:1776289fa9295540d5d38fe219a7e565b1d60d7eab2e33331209d9eee88528bb",
=======
				ID:   "sha256:91bef90dbeb1577d834d7feeac60af3a935ed2465788022146a0ca9c5b38c445",
				BlobIDs: []string{
					"sha256:91bef90dbeb1577d834d7feeac60af3a935ed2465788022146a0ca9c5b38c445",
>>>>>>> 4820b213 (fix: updating more tests to run on Windows)
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
