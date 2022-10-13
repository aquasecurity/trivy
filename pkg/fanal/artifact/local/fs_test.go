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
					BlobID: "sha256:f7c8f14888e2908b613769b9e98816fa40d84980872f3777b656d11b8fb544fb",
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
				ID:   "sha256:f7c8f14888e2908b613769b9e98816fa40d84980872f3777b656d11b8fb544fb",
				BlobIDs: []string{
					"sha256:f7c8f14888e2908b613769b9e98816fa40d84980872f3777b656d11b8fb544fb",
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
					BlobID: "sha256:f7c8f14888e2908b613769b9e98816fa40d84980872f3777b656d11b8fb544fb",
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
				ID:   "sha256:f7c8f14888e2908b613769b9e98816fa40d84980872f3777b656d11b8fb544fb",
				BlobIDs: []string{
					"sha256:f7c8f14888e2908b613769b9e98816fa40d84980872f3777b656d11b8fb544fb",
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
								Layer: types.Layer{Digest: "", DiffID: "", CreatedBy: ""},
							},
						}, Secrets: []types.Secret(nil), Licenses: []types.LicenseFile(nil),
						BuildInfo: (*types.BuildInfo)(nil), CustomResources: []types.CustomResource(nil),
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/terraform/single-failure/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:054ca717161e9042642323fce30d558ea4188280770f3a97f08878732182e2f5",
				BlobIDs: []string{
					"sha256:054ca717161e9042642323fce30d558ea4188280770f3a97f08878732182e2f5",
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
								Layer: types.Layer{Digest: "", DiffID: "", CreatedBy: ""},
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
								Layer: types.Layer{Digest: "", DiffID: "", CreatedBy: ""},
							},
						}, Secrets: []types.Secret(nil), Licenses: []types.LicenseFile(nil),
						BuildInfo: (*types.BuildInfo)(nil), CustomResources: []types.CustomResource(nil),
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/terraform/multiple-failures/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:539a82c7c394c9b4d64580feec160c9422f7d1aa2c7328d43c919e737bffdd70",
				BlobIDs: []string{
					"sha256:539a82c7c394c9b4d64580feec160c9422f7d1aa2c7328d43c919e737bffdd70",
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
				ID:   "sha256:58371119b88104d4a643bda59a6957e5777174d62a09e179bbad7744e9632128",
				BlobIDs: []string{
					"sha256:58371119b88104d4a643bda59a6957e5777174d62a09e179bbad7744e9632128",
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
				Name: "testdata/misconfig/terraform/passed/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:e21f36991ba1f6b15de2a109d2515faaf97452df74955f143766a6c4f4c9ad98",
				BlobIDs: []string{
					"sha256:e21f36991ba1f6b15de2a109d2515faaf97452df74955f143766a6c4f4c9ad98",
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
								Layer: types.Layer{Digest: "", DiffID: "", CreatedBy: ""},
							},
						}, Secrets: []types.Secret(nil), Licenses: []types.LicenseFile(nil),
						BuildInfo: (*types.BuildInfo)(nil), CustomResources: []types.CustomResource(nil),
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/cloudformation/single-failure/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:4ae00d7180bbf9dcc3d2b4e9f48d7ee39830f1e86cd6069a0dc5c9cf9d2b003f",
				BlobIDs: []string{
					"sha256:4ae00d7180bbf9dcc3d2b4e9f48d7ee39830f1e86cd6069a0dc5c9cf9d2b003f",
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
			want: types.ArtifactReference{
				Name: "testdata/misconfig/cloudformation/multiple-failures/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:4a3a9c97808bc837c4c0ba4fef933b0b637f5d3c48cecc996b347e1a80f05ec4",
				BlobIDs: []string{
					"sha256:4a3a9c97808bc837c4c0ba4fef933b0b637f5d3c48cecc996b347e1a80f05ec4",
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
				ID:   "sha256:58371119b88104d4a643bda59a6957e5777174d62a09e179bbad7744e9632128",
				BlobIDs: []string{
					"sha256:58371119b88104d4a643bda59a6957e5777174d62a09e179bbad7744e9632128",
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
				Name: "testdata/misconfig/cloudformation/passed/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:734733115e3bcda02dd2079cdf30280244260c28744e4a3f2eb5a98e37353573",
				BlobIDs: []string{
					"sha256:734733115e3bcda02dd2079cdf30280244260c28744e4a3f2eb5a98e37353573",
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
			want: types.ArtifactReference{
				Name: "testdata/misconfig/dockerfile/single-failure/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:4b0783905a99a1e645fc00945a008c0d42424a87366dbf99833d8efeafe70361",
				BlobIDs: []string{
					"sha256:4b0783905a99a1e645fc00945a008c0d42424a87366dbf99833d8efeafe70361",
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
			want: types.ArtifactReference{
				Name: "testdata/misconfig/dockerfile/multiple-failures/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:4b0783905a99a1e645fc00945a008c0d42424a87366dbf99833d8efeafe70361",
				BlobIDs: []string{
					"sha256:4b0783905a99a1e645fc00945a008c0d42424a87366dbf99833d8efeafe70361",
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
				ID:   "sha256:58371119b88104d4a643bda59a6957e5777174d62a09e179bbad7744e9632128",
				BlobIDs: []string{
					"sha256:58371119b88104d4a643bda59a6957e5777174d62a09e179bbad7744e9632128",
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
				Name: "testdata/misconfig/dockerfile/passed/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:92a2a8fb73136f4f1d5ec38bf66d9b38fd5db288869e727aed5f7516f60633db",
				BlobIDs: []string{
					"sha256:92a2a8fb73136f4f1d5ec38bf66d9b38fd5db288869e727aed5f7516f60633db",
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
				Name: "testdata/misconfig/kubernetes/single-failure/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:af6a4b3a5906ea8495a21a315bc4accd97effb249ccb3e0c75d8720c386e5bfb",
				BlobIDs: []string{
					"sha256:af6a4b3a5906ea8495a21a315bc4accd97effb249ccb3e0c75d8720c386e5bfb",
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
				Name: "testdata/misconfig/kubernetes/multiple-failures/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:e681637468d8a07c867602047c84b2acceb7da1b36dbc96b6edb3df3fa711788",
				BlobIDs: []string{
					"sha256:e681637468d8a07c867602047c84b2acceb7da1b36dbc96b6edb3df3fa711788",
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
				ID:   "sha256:63ee9fc1ce356a810234d884f9056432df7048485565a15bf3448644f4d97abe",
				BlobIDs: []string{
					"sha256:63ee9fc1ce356a810234d884f9056432df7048485565a15bf3448644f4d97abe",
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
				Name: "testdata/misconfig/kubernetes/passed/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:0e2a1bd08e49eba4ba3f829b87ab9021b949d4c3983d8c494cd0febfa7adc0cb",
				BlobIDs: []string{
					"sha256:0e2a1bd08e49eba4ba3f829b87ab9021b949d4c3983d8c494cd0febfa7adc0cb",
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
				dir: "./testdata/misconfig/azurearm/single-failure/src",
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
					PolicyPaths: []string{"./testdata/misconfig/azurearm/single-failure/rego"},
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
								FileType: "Azure ARM", FilePath: "deploy.json", Successes: types.MisconfResults{
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
			want: types.ArtifactReference{
				Name: "testdata/misconfig/azurearm/single-failure/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:e5ddfd4e4cb3e8870bb38ab40caf67106d5fc7f298c497676c9a465600a35048",
				BlobIDs: []string{
					"sha256:e5ddfd4e4cb3e8870bb38ab40caf67106d5fc7f298c497676c9a465600a35048",
				},
			},
		},
		{
			name: "multiple failures",
			fields: fields{
				dir: "./testdata/misconfig/azurearm/multiple-failures/src",
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
					PolicyPaths: []string{"./testdata/misconfig/azurearm/multiple-failures/rego"},
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
								FileType: "Azure ARM", FilePath: "deploy.json", Successes: types.MisconfResults{
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
			want: types.ArtifactReference{
				Name: "testdata/misconfig/azurearm/multiple-failures/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:4699742ef0d934c25f6e9486fe5a00ebb632bbfeb5c9aede44ed5ad4e7afad47",
				BlobIDs: []string{
					"sha256:4699742ef0d934c25f6e9486fe5a00ebb632bbfeb5c9aede44ed5ad4e7afad47",
				},
			},
		},
		{
			name: "no results",
			fields: fields{
				dir: "./testdata/misconfig/azurearm/no-results/src",
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
				ID:   "sha256:58371119b88104d4a643bda59a6957e5777174d62a09e179bbad7744e9632128",
				BlobIDs: []string{
					"sha256:58371119b88104d4a643bda59a6957e5777174d62a09e179bbad7744e9632128",
				},
			},
		},
		{
			name: "passed",
			fields: fields{
				dir: "./testdata/misconfig/azurearm/passed/src",
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
					PolicyPaths: []string{"./testdata/misconfig/azurearm/passed/rego"},
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
								FileType: "Azure ARM", FilePath: "deploy.json", Successes: types.MisconfResults{
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
				Name: "testdata/misconfig/azurearm/passed/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:7e7df3fe10f93dcf1f025cd912f3659b75f2cffaa56a4c277d0f5880d9a6a9cf",
				BlobIDs: []string{
					"sha256:7e7df3fe10f93dcf1f025cd912f3659b75f2cffaa56a4c277d0f5880d9a6a9cf",
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
