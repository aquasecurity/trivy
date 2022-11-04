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
	// if runtime.GOOS == "windows" {
	// 	t.Skip("skipping test on Windows")
	// }
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
					BlobID: "sha256:fa644cab37290cb0be1f690cef170f2b54b939722a6d5f3d7306fa8035abdd0e",
					BlobInfo: types.BlobInfo{
						SchemaVersion: 2, Digest: "", DiffID: "", CreatedBy: "", OpaqueDirs: []string(nil),
						WhiteoutFiles: []string(nil), OS: (*types.OS)(nil), Repository: (*types.Repository)(nil),
						PackageInfos: []types.PackageInfo(nil), Applications: []types.Application(nil),
						Misconfigurations: []types.Misconfiguration(nil), Secrets: []types.Secret(nil),
						Licenses: []types.LicenseFile(nil), BuildInfo: (*types.BuildInfo)(nil),
						CustomResources: []types.CustomResource(nil),
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "host",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:fa644cab37290cb0be1f690cef170f2b54b939722a6d5f3d7306fa8035abdd0e",
				BlobIDs: []string{
					"sha256:fa644cab37290cb0be1f690cef170f2b54b939722a6d5f3d7306fa8035abdd0e",
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
					BlobID: "sha256:fa644cab37290cb0be1f690cef170f2b54b939722a6d5f3d7306fa8035abdd0e",
					BlobInfo: types.BlobInfo{
						SchemaVersion: 2, Digest: "", DiffID: "", CreatedBy: "", OpaqueDirs: []string(nil),
						WhiteoutFiles: []string(nil), OS: (*types.OS)(nil), Repository: (*types.Repository)(nil),
						PackageInfos: []types.PackageInfo(nil), Applications: []types.Application(nil),
						Misconfigurations: []types.Misconfiguration(nil), Secrets: []types.Secret(nil),
						Licenses: []types.LicenseFile(nil), BuildInfo: (*types.BuildInfo)(nil),
						CustomResources: []types.CustomResource(nil),
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
			wantErr: osSpecificFileNotFoundError(),
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
						SchemaVersion: 2, Digest: "", DiffID: "", CreatedBy: "", OpaqueDirs: []string(nil),
						WhiteoutFiles: []string(nil), OS: (*types.OS)(nil), Repository: (*types.Repository)(nil),
						PackageInfos: []types.PackageInfo(nil), Applications: []types.Application{
							types.Application{
								Type: "pip", FilePath: "requirements.txt", Libraries: []types.Package{
									types.Package{
										ID: "", Name: "Flask", Version: "2.0.0", Release: "", Epoch: 0, Arch: "",
										SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0,
										Licenses: []string(nil), Modularitylabel: "",
										BuildInfo: (*types.BuildInfo)(nil), Ref: "", Indirect: false,
										DependsOn: []string(nil),
										Layer:     types.Layer{Digest: "", DiffID: "", CreatedBy: ""}, FilePath: "",
										Locations: []types.Location(nil),
									},
								},
							},
						}, Misconfigurations: []types.Misconfiguration(nil), Secrets: []types.Secret(nil),
						Licenses: []types.LicenseFile(nil), BuildInfo: (*types.BuildInfo)(nil),
						CustomResources: []types.CustomResource(nil),
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
						SchemaVersion: 2, Digest: "", DiffID: "", CreatedBy: "", OpaqueDirs: []string(nil),
						WhiteoutFiles: []string(nil), OS: (*types.OS)(nil), Repository: (*types.Repository)(nil),
						PackageInfos: []types.PackageInfo(nil), Applications: []types.Application{
							types.Application{
								Type: "pip", FilePath: "requirements.txt", Libraries: []types.Package{
									types.Package{
										ID: "", Name: "Flask", Version: "2.0.0", Release: "", Epoch: 0, Arch: "",
										SrcName: "", SrcVersion: "", SrcRelease: "", SrcEpoch: 0,
										Licenses: []string(nil), Modularitylabel: "",
										BuildInfo: (*types.BuildInfo)(nil), Ref: "", Indirect: false,
										DependsOn: []string(nil),
										Layer:     types.Layer{Digest: "", DiffID: "", CreatedBy: ""}, FilePath: "",
										Locations: []types.Location(nil),
									},
								},
							},
						}, Misconfigurations: []types.Misconfiguration(nil), Secrets: []types.Secret(nil),
						Licenses: []types.LicenseFile(nil), BuildInfo: (*types.BuildInfo)(nil),
						CustomResources: []types.CustomResource(nil),
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
			[]string{"testPath"},
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

type artifactReferenceDetails struct {
	blobID        string
	windowsBlobID string
	filepath      string
	artifactType  types.ArtifactType
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
		want               artifactReferenceDetails
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
							{
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
							}, {
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
								Layer: types.Layer{Digest: "", DiffID: "", CreatedBy: ""},
							},
						}, Secrets: []types.Secret(nil), Licenses: []types.LicenseFile(nil),
						BuildInfo: (*types.BuildInfo)(nil), CustomResources: []types.CustomResource(nil),
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifactReferenceDetails{
				blobID:        "sha256:054ca717161e9042642323fce30d558ea4188280770f3a97f08878732182e2f5",
				windowsBlobID: "sha256:00839ff1b9db6cb4898dab4ba56d2cb982d5433737fbb06ef3393ee7531f8550",
				filepath:      filepath.Join("testdata", "misconfig", "terraform", "single-failure", "src"),
				artifactType:  types.ArtifactFilesystem,
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
							{
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
							}, {
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
								Layer: types.Layer{Digest: "", DiffID: "", CreatedBy: ""},
							}, {
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
								Layer: types.Layer{Digest: "", DiffID: "", CreatedBy: ""},
							},
						}, Secrets: []types.Secret(nil), Licenses: []types.LicenseFile(nil),
						BuildInfo: (*types.BuildInfo)(nil), CustomResources: []types.CustomResource(nil),
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifactReferenceDetails{
				blobID:        "sha256:539a82c7c394c9b4d64580feec160c9422f7d1aa2c7328d43c919e737bffdd70",
				windowsBlobID: "sha256:a667230715ab98155874066a6c07bc42b5318bb6ac4023498fff839328463de1",
				filepath:      filepath.Join("testdata", "misconfig", "terraform", "multiple-failures", "src"),
				artifactType:  types.ArtifactFilesystem,
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
			want: artifactReferenceDetails{
				blobID:        "sha256:58371119b88104d4a643bda59a6957e5777174d62a09e179bbad7744e9632128",
				windowsBlobID: "sha256:e4b7ab19dd670011336c6c538403abb6a24f77c41a45d749a05e2dfd89c5a580",
				filepath:      filepath.Join("testdata", "misconfig", "terraform", "no-results", "src"),
				artifactType:  types.ArtifactFilesystem,
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
							{
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
			want: artifactReferenceDetails{
				blobID:        "sha256:e21f36991ba1f6b15de2a109d2515faaf97452df74955f143766a6c4f4c9ad98",
				windowsBlobID: "sha256:9ddca8d09f3fe3c865964eef97c579fe6c6ce5f379c62d6b7fc0077d7ca156fa",
				filepath:      filepath.Join("testdata", "misconfig", "terraform", "passed", "src"),
				artifactType:  types.ArtifactFilesystem,
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

			var blobID string
			switch runtime.GOOS {
			case "windows":
				blobID = tt.want.windowsBlobID
			default:
				blobID = tt.want.blobID
			}
			want := types.ArtifactReference{
				Name: tt.want.filepath,
				Type: tt.want.artifactType,
				ID:   blobID,
				BlobIDs: []string{
					blobID,
				},
			}
			assert.Equal(t, want, got)
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
		want               artifactReferenceDetails
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
											Resource: "main.yaml:3-6", Provider: "Generic", Service: "general",
											StartLine: 3, EndLine: 6, Code: types.Code{Lines: []types.Line(nil)},
										}, Traces: []string(nil),
									},
								}, Exceptions: types.MisconfResults(nil),
								Layer: types.Layer{Digest: "", DiffID: "", CreatedBy: ""},
							},
						}, Secrets: []types.Secret(nil), Licenses: []types.LicenseFile(nil),
						BuildInfo: (*types.BuildInfo)(nil), CustomResources: []types.CustomResource(nil),
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifactReferenceDetails{
				filepath:      filepath.Join("testdata", "misconfig", "cloudformation", "single-failure", "src"),
				artifactType:  types.ArtifactFilesystem,
				blobID:        "sha256:4ae00d7180bbf9dcc3d2b4e9f48d7ee39830f1e86cd6069a0dc5c9cf9d2b003f",
				windowsBlobID: "sha256:01616db3395461a6dd41de15c7a885f3d185ea5b10db55ef97bfddcbab57770e",
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
								Layer: types.Layer{Digest: "", DiffID: "", CreatedBy: ""},
							},
						}, Secrets: []types.Secret(nil), Licenses: []types.LicenseFile(nil),
						BuildInfo: (*types.BuildInfo)(nil), CustomResources: []types.CustomResource(nil),
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifactReferenceDetails{
				filepath:      filepath.Join("testdata", "misconfig", "cloudformation", "multiple-failures", "src"),
				artifactType:  types.ArtifactFilesystem,
				blobID:        "sha256:4a3a9c97808bc837c4c0ba4fef933b0b637f5d3c48cecc996b347e1a80f05ec4",
				windowsBlobID: "sha256:10d074d262e53c85f430d708cdb4689f5792736984abec04047f2b5acf6df5f2",
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
			want: artifactReferenceDetails{
				filepath:      filepath.Join("testdata", "misconfig", "cloudformation", "no-results", "src"),
				artifactType:  types.ArtifactFilesystem,
				blobID:        "sha256:58371119b88104d4a643bda59a6957e5777174d62a09e179bbad7744e9632128",
				windowsBlobID: "sha256:e4b7ab19dd670011336c6c538403abb6a24f77c41a45d749a05e2dfd89c5a580",
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
			want: artifactReferenceDetails{
				filepath:      filepath.Join("testdata", "misconfig", "cloudformation", "passed", "src"),
				artifactType:  types.ArtifactFilesystem,
				blobID:        "sha256:734733115e3bcda02dd2079cdf30280244260c28744e4a3f2eb5a98e37353573",
				windowsBlobID: "sha256:befe6a41f1de990064c8ea2427d7bb424ef9267ffbe481804a8a5191536390e5",
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

			var blobID string
			switch runtime.GOOS {
			case "windows":
				blobID = tt.want.windowsBlobID
			default:
				blobID = tt.want.blobID
			}
			want := types.ArtifactReference{
				Name: tt.want.filepath,
				Type: tt.want.artifactType,
				ID:   blobID,
				BlobIDs: []string{
					blobID,
				},
			}
			assert.Equal(t, want, got)
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
		want               artifactReferenceDetails
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
						}, Secrets: []types.Secret(nil),
						OpaqueDirs:      []string(nil),
						WhiteoutFiles:   []string(nil),
						BuildInfo:       (*types.BuildInfo)(nil),
						CustomResources: []types.CustomResource(nil),
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifactReferenceDetails{
				filepath:      filepath.Join("testdata", "misconfig", "dockerfile", "single-failure", "src"),
				artifactType:  types.ArtifactFilesystem,
				blobID:        "sha256:4b0783905a99a1e645fc00945a008c0d42424a87366dbf99833d8efeafe70361",
				windowsBlobID: "sha256:0a721023a4d3fd523af4c329643dfef529b475d8df1b98696d780f7635680db6",
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
						}, Secrets: []types.Secret(nil),
						OpaqueDirs:      []string(nil),
						WhiteoutFiles:   []string(nil),
						BuildInfo:       (*types.BuildInfo)(nil),
						CustomResources: []types.CustomResource(nil),
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifactReferenceDetails{
				filepath:      filepath.Join("testdata", "misconfig", "dockerfile", "multiple-failures", "src"),
				artifactType:  types.ArtifactFilesystem,
				blobID:        "sha256:4b0783905a99a1e645fc00945a008c0d42424a87366dbf99833d8efeafe70361",
				windowsBlobID: "sha256:0a721023a4d3fd523af4c329643dfef529b475d8df1b98696d780f7635680db6",
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
			want: artifactReferenceDetails{
				filepath:      filepath.Join("testdata", "misconfig", "dockerfile", "no-results", "src"),
				artifactType:  types.ArtifactFilesystem,
				blobID:        "sha256:58371119b88104d4a643bda59a6957e5777174d62a09e179bbad7744e9632128",
				windowsBlobID: "sha256:e4b7ab19dd670011336c6c538403abb6a24f77c41a45d749a05e2dfd89c5a580",
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
			want: artifactReferenceDetails{
				filepath:      filepath.Join("testdata", "misconfig", "dockerfile", "passed", "src"),
				artifactType:  types.ArtifactFilesystem,
				blobID:        "sha256:92a2a8fb73136f4f1d5ec38bf66d9b38fd5db288869e727aed5f7516f60633db",
				windowsBlobID: "sha256:11169ed2403e648416dffd370aa0de6101c9ace0297524de1d40e1a9e8391d99",
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

			var blobID string
			switch runtime.GOOS {
			case "windows":
				blobID = tt.want.windowsBlobID
			default:
				blobID = tt.want.blobID
			}
			want := types.ArtifactReference{
				Name: tt.want.filepath,
				Type: tt.want.artifactType,
				ID:   blobID,
				BlobIDs: []string{
					blobID,
				},
			}
			assert.Equal(t, want, got)
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
		want               artifactReferenceDetails
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
			want: artifactReferenceDetails{
				filepath:      filepath.Join("testdata", "misconfig", "kubernetes", "single-failure", "src"),
				artifactType:  types.ArtifactFilesystem,
				blobID:        "sha256:af6a4b3a5906ea8495a21a315bc4accd97effb249ccb3e0c75d8720c386e5bfb",
				windowsBlobID: "sha256:bd3f7f92af9d18b898c615b55a93d783223f73c5b8c76da14cb8879185364fc1",
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
			want: artifactReferenceDetails{
				filepath:      filepath.Join("testdata", "misconfig", "kubernetes", "multiple-failures", "src"),
				artifactType:  types.ArtifactFilesystem,
				blobID:        "sha256:e681637468d8a07c867602047c84b2acceb7da1b36dbc96b6edb3df3fa711788",
				windowsBlobID: "sha256:f32e9c2da77b5bfd5a0568ed14baa43b8490cf835c97c816ed18cdf298990a96",
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
			want: artifactReferenceDetails{
				filepath:      filepath.Join("testdata", "misconfig", "kubernetes", "no-results", "src"),
				artifactType:  types.ArtifactFilesystem,
				blobID:        "sha256:63ee9fc1ce356a810234d884f9056432df7048485565a15bf3448644f4d97abe",
				windowsBlobID: "sha256:91ff7105811fde3a94cd0c46d764d14315783bc506b4fcae712b690045e32d09",
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
			want: artifactReferenceDetails{
				filepath:      filepath.Join("testdata", "misconfig", "kubernetes", "passed", "src"),
				artifactType:  types.ArtifactFilesystem,
				blobID:        "sha256:0e2a1bd08e49eba4ba3f829b87ab9021b949d4c3983d8c494cd0febfa7adc0cb",
				windowsBlobID: "sha256:4722f0c46d3a06f8aab5f49f85b4f2161691e3c9bffc6193d55c6c46ebcd5c71",
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

			var blobID string
			switch runtime.GOOS {
			case "windows":
				blobID = tt.want.windowsBlobID
			default:
				blobID = tt.want.blobID
			}
			want := types.ArtifactReference{
				Name: tt.want.filepath,
				Type: tt.want.artifactType,
				ID:   blobID,
				BlobIDs: []string{
					blobID,
				},
			}
			assert.Equal(t, want, got)
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
		want               artifactReferenceDetails
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
							{
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
								Layer: types.Layer{Digest: "", DiffID: "", CreatedBy: ""},
							},
						}, Secrets: []types.Secret(nil), Licenses: []types.LicenseFile(nil),
						BuildInfo: (*types.BuildInfo)(nil), CustomResources: []types.CustomResource(nil),
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifactReferenceDetails{
				filepath:      filepath.Join("testdata", "misconfig", "azurearm", "single-failure", "src"),
				artifactType:  types.ArtifactFilesystem,
				blobID:        "sha256:4a2b0992144ad47985149073e8807ea38a248da82a36342f78db16cf97254b68",
				windowsBlobID: "sha256:2705472fa17208a67523dc450016ccdae5b3bb3dbfb4e10c59b076411bf97b7d",
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
							{
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
								Layer: types.Layer{Digest: "", DiffID: "", CreatedBy: ""},
							},
						}, Secrets: []types.Secret(nil), Licenses: []types.LicenseFile(nil),
						BuildInfo: (*types.BuildInfo)(nil), CustomResources: []types.CustomResource(nil),
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifactReferenceDetails{
				filepath:      filepath.Join("testdata", "misconfig", "azurearm", "multiple-failures", "src"),
				artifactType:  types.ArtifactFilesystem,
				blobID:        "sha256:8859b0de1cb155a38e27ecf9f26dd662f2e809fdce48f201f4c1e94d299c0f96",
				windowsBlobID: "sha256:574827a1c9ca846b514084814e221190d319cd5560a3478eb0ce6117f5f38abb",
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
			want: artifactReferenceDetails{
				filepath:      filepath.Join("testdata", "misconfig", "azurearm", "no-results", "src"),
				artifactType:  types.ArtifactFilesystem,
				blobID:        "sha256:58371119b88104d4a643bda59a6957e5777174d62a09e179bbad7744e9632128",
				windowsBlobID: "sha256:e4b7ab19dd670011336c6c538403abb6a24f77c41a45d749a05e2dfd89c5a580",
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
							{
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
			want: artifactReferenceDetails{
				filepath:      filepath.Join("testdata", "misconfig", "azurearm", "passed", "src"),
				artifactType:  types.ArtifactFilesystem,
				blobID:        "sha256:11bfbe426d39efcefa0bd0ac16a1386967720e1efd00e92012d637b80330821c",
				windowsBlobID: "sha256:61a1869ae33125065c5ee48859a337cab11d228c6538801e942e3e687a3e7ed0",
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

			var blobID string
			switch runtime.GOOS {
			case "windows":
				blobID = tt.want.windowsBlobID
			default:
				blobID = tt.want.blobID
			}
			want := types.ArtifactReference{
				Name: tt.want.filepath,
				Type: tt.want.artifactType,
				ID:   blobID,
				BlobIDs: []string{
					blobID,
				},
			}
			assert.Equal(t, want, got)
		})
	}
}

func osSpecificFileNotFoundError() string {
	switch runtime.GOOS {
	case "windows":
		return "The system cannot find the file"
	default:
		return "no such file or directory"
	}
}
