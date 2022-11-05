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
					BlobID: "sha256:7177f27ce94e21305ba8efe2ced3533ba9be66bd251aaa217615469a29ed86a9",
					BlobInfo: types.BlobInfo{
						SchemaVersion: 2, Digest: "", DiffID: "", CreatedBy: "", OpaqueDirs: []string(nil),
						WhiteoutFiles: []string(nil), OS: &types.OS{Family: "alpine", Name: "3.11.6"},
						Repository: (*types.Repository)(nil), PackageInfos: []types.PackageInfo{
							types.PackageInfo{
								FilePath: "lib/apk/db/installed", Packages: []types.Package{
									types.Package{
										ID: "musl@1.1.24-r2", Name: "musl", Version: "1.1.24-r2", Release: "", Epoch: 0,
										Arch: "", SrcName: "musl", SrcVersion: "1.1.24-r2", SrcRelease: "", SrcEpoch: 0,
										Licenses: []string{"MIT"}, Modularitylabel: "",
										BuildInfo: (*types.BuildInfo)(nil), Ref: "", Indirect: false,
										DependsOn: []string(nil),
										Layer:     types.Layer{Digest: "", DiffID: "", CreatedBy: ""}, FilePath: "",
										Locations: []types.Location(nil),
									},
								},
							},
						}, Applications: []types.Application(nil), Misconfigurations: []types.Misconfiguration(nil),
						Secrets: []types.Secret(nil), Licenses: []types.LicenseFile(nil),
						BuildInfo: (*types.BuildInfo)(nil), CustomResources: []types.CustomResource(nil),
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "host",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:7177f27ce94e21305ba8efe2ced3533ba9be66bd251aaa217615469a29ed86a9",
				BlobIDs: []string{
					"sha256:7177f27ce94e21305ba8efe2ced3533ba9be66bd251aaa217615469a29ed86a9",
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
						SchemaVersion: 2, Digest: "", DiffID: "", CreatedBy: "", OpaqueDirs: []string(nil),
						WhiteoutFiles: []string(nil), OS: &types.OS{Family: "alpine", Name: "3.11.6"},
						Repository: (*types.Repository)(nil), PackageInfos: []types.PackageInfo{
							types.PackageInfo{
								FilePath: "lib/apk/db/installed", Packages: []types.Package{
									types.Package{
										ID: "musl@1.1.24-r2", Name: "musl", Version: "1.1.24-r2", Release: "", Epoch: 0,
										Arch: "", SrcName: "musl", SrcVersion: "1.1.24-r2", SrcRelease: "", SrcEpoch: 0,
										Licenses: []string{"MIT"}, Modularitylabel: "",
										BuildInfo: (*types.BuildInfo)(nil), Ref: "", Indirect: false,
										DependsOn: []string(nil),
										Layer:     types.Layer{Digest: "", DiffID: "", CreatedBy: ""}, FilePath: "",
										Locations: []types.Location(nil),
									},
								},
							},
						}, Applications: []types.Application(nil), Misconfigurations: []types.Misconfiguration(nil),
						Secrets: []types.Secret(nil), Licenses: []types.LicenseFile(nil),
						BuildInfo: (*types.BuildInfo)(nil), CustomResources: []types.CustomResource(nil),
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
				blobID:        "sha256:9827e4b06d1efa0853e8d75bafb4f95c4c778012b60cee114ce96042ea7c1b7b",
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
				blobID:        "sha256:5280d5ed00b245d916357a365dde2a87430bdef58bf8d3c26a4e9b7e67481f6b",
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
				blobID:        "sha256:cd80d8148f9b4cbc026f71a73d8dc1e35f79f6f39e4e52fe5e9a7821e9d09693",
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
				blobID:        "sha256:a765d67b40d8dafad114c8b57d817b3d2f03fce2b0d6cecbf057ac13a2d52662",
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
				blobID:        "sha256:16af3ef12417f03bab139674ad17636f5fb032a9f4e20f2092aeaa9ff0e3bc38",
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
				blobID:        "sha256:10801795d3e822d09f0810255a82deeb572f4e298f91af3abe5fc358c10ba68c",
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
				blobID:        "sha256:cd80d8148f9b4cbc026f71a73d8dc1e35f79f6f39e4e52fe5e9a7821e9d09693",
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
				blobID:        "sha256:30bc323c6eb7af47b561df826948fe3981ddd63c27c8a1f5bb516eeb0d361fef",
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
				blobID:        "sha256:d93b33f51c455c07767196c2b2eb3312e2b055b0e0db40704092d258fc0ed6ec",
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
				blobID:        "sha256:d93b33f51c455c07767196c2b2eb3312e2b055b0e0db40704092d258fc0ed6ec",
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
				blobID:        "sha256:cd80d8148f9b4cbc026f71a73d8dc1e35f79f6f39e4e52fe5e9a7821e9d09693",
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
				blobID:        "sha256:7218a8e53d2e3eb08efe9f9864767eb0fe6084eaaaef1480064096bbdc2c3f71",
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
				blobID:        "sha256:599ae82c0d032acbe75e24379b4320fb7f0a9818da50b4635c4f0645504d5a72",
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
				blobID:        "sha256:fd62e7fdfeffa3df4653c100cc87fe0bc83ddbca918c41b73c7a5724a64619df",
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
				blobID:        "sha256:b46953af7375260e0bf264328c8b156ee3341ff46794c0f09c65bce78b0eddb9",
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
				blobID:        "sha256:5b110611834af3e26a4c7aa5623f9e20098c46b394a29a0881a1a3852a114578",
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
				blobID:        "sha256:1113fd88abfa3727496c9a5e2e47c522d0197fa0c58d9b0472ff5715aa5dbe79",
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
				blobID:        "sha256:f75d8c2df3cd95fa0972ad064ca7c4c4bfc614b69a1220bb1b0e31b0c97cf2aa",
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
				blobID:        "sha256:cd80d8148f9b4cbc026f71a73d8dc1e35f79f6f39e4e52fe5e9a7821e9d09693",
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
				blobID:        "sha256:1776289fa9295540d5d38fe219a7e565b1d60d7eab2e33331209d9eee88528bb",
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
