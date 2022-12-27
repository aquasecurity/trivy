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
					BlobID: "sha256:7177f27ce94e21305ba8efe2ced3533ba9be66bd251aaa217615469a29ed86a9",
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
					BlobID: "sha256:25af809c209a60d5c852a9cd0fe0ea853f12876b693b7e3a90ba36236976f16a",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "host",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:25af809c209a60d5c852a9cd0fe0ea853f12876b693b7e3a90ba36236976f16a",
				BlobIDs: []string{
					"sha256:25af809c209a60d5c852a9cd0fe0ea853f12876b693b7e3a90ba36236976f16a",
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
						OS: types.OS{
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
			wantErr: "walk error",
		},
		{
			name: "happy path with single file",
			fields: fields{
				dir: "testdata/requirements.txt",
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobID: "sha256:5733e6d01251440e3ce19f0171a43360c50d32205051b2889187b8dd00e8d515",
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
				ID:   "sha256:5733e6d01251440e3ce19f0171a43360c50d32205051b2889187b8dd00e8d515",
				BlobIDs: []string{
					"sha256:5733e6d01251440e3ce19f0171a43360c50d32205051b2889187b8dd00e8d515",
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
					BlobID: "sha256:5733e6d01251440e3ce19f0171a43360c50d32205051b2889187b8dd00e8d515",
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
				ID:   "sha256:5733e6d01251440e3ce19f0171a43360c50d32205051b2889187b8dd00e8d515",
				BlobIDs: []string{
					"sha256:5733e6d01251440e3ce19f0171a43360c50d32205051b2889187b8dd00e8d515",
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
			name:  "path - abs, base - abs, not joining paths",
			oses:  []string{"linux", "darwin"},
			base:  "/foo",
			paths: []string{"/foo/bar"},
			want:  []string{"bar"},
		},
		{
			name: "path - abs, base - rel",
			oses: []string{"linux", "darwin"},
			base: "foo",
			paths: func() []string {
				abs, err := filepath.Abs("foo/bar")
				require.NoError(t, err)
				return []string{abs}
			}(),
			want: []string{"bar"},
		},
		{
			name:  "path - rel, base - rel, joining paths",
			oses:  []string{"linux", "darwin"},
			base:  "foo",
			paths: []string{"bar"},
			want:  []string{"bar"},
		},
		{
			name:  "path - rel, base - rel, not joining paths",
			oses:  []string{"linux", "darwin"},
			base:  "foo",
			paths: []string{"foo/bar/bar"},
			want:  []string{"bar/bar"},
		},
		{
			name:  "path - rel with dot, base - rel, removing the leading dot and not joining paths",
			oses:  []string{"linux", "darwin"},
			base:  "foo",
			paths: []string{"./foo/bar"},
			want:  []string{"bar"},
		},
		{
			name:  "path - rel, base - dot",
			oses:  []string{"linux", "darwin"},
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
						SchemaVersion: 2,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "terraform",
								FilePath: ".",
								Successes: types.MisconfResults{
									{
										Namespace: "builtin.aws.rds.aws0176",
										Query:     "data.builtin.aws.rds.aws0176.deny", Message: "",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "N/A",
											AVDID:              "AVD-AWS-0176",
											Type:               "Terraform Security Check",
											Title:              "RDS IAM Database Authentication Disabled",
											Description:        "Ensure IAM Database Authentication is enabled for RDS database instances to manage database access",
											Severity:           "MEDIUM",
											RecommendedActions: "Modify the PostgreSQL and MySQL type RDS instances to enable IAM database authentication.",
											References:         []string{"https://docs.aws.amazon.com/neptune/latest/userguide/iam-auth.html"},
										},
										CauseMetadata: types.CauseMetadata{
											Resource: "", Provider: "AWS", Service: "rds", StartLine: 0, EndLine: 0,
											Code: types.Code{Lines: []types.Line(nil)},
										}, Traces: []string(nil),
									},
									{
										Namespace: "builtin.aws.rds.aws0177",
										Query:     "data.builtin.aws.rds.aws0177.deny",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "N/A",
											AVDID:              "AVD-AWS-0177",
											Type:               "Terraform Security Check",
											Title:              "RDS Deletion Protection Disabled",
											Description:        "Ensure deletion protection is enabled for RDS database instances.",
											Severity:           "MEDIUM",
											RecommendedActions: "Modify the RDS instances to enable deletion protection.",
											References:         []string{"https://aws.amazon.com/about-aws/whats-new/2018/09/amazon-rds-now-provides-database-deletion-protection/"},
										},
										CauseMetadata: types.CauseMetadata{
											Resource: "", Provider: "AWS", Service: "rds", StartLine: 0, EndLine: 0,
											Code: types.Code{Lines: []types.Line(nil)},
										}, Traces: []string(nil),
									},
									{
										Namespace: "builtin.aws.rds.aws0180",
										Query:     "data.builtin.aws.rds.aws0180.deny",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "N/A",
											AVDID:              "AVD-AWS-0180",
											Type:               "Terraform Security Check",
											Title:              "RDS Publicly Accessible",
											Description:        "Ensures RDS instances are not launched into the public cloud.",
											Severity:           "HIGH",
											RecommendedActions: "Remove the public endpoint from the RDS instance'",
											References:         []string{"http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.html"},
										},
										CauseMetadata: types.CauseMetadata{
											Resource: "", Provider: "AWS", Service: "rds", StartLine: 0, EndLine: 0,
											Code: types.Code{Lines: []types.Line(nil)},
										}, Traces: []string(nil),
									},
								},
							},
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
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: types.ArtifactReference{
				Name: "testdata/misconfig/terraform/single-failure/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:50ac4117e0b0d075e9ce20726f3bd43f570955f3914ab3547bcbcfcdd0c2f063",
				BlobIDs: []string{
					"sha256:50ac4117e0b0d075e9ce20726f3bd43f570955f3914ab3547bcbcfcdd0c2f063",
				},
			},
		},
		{
			name: "multiple failures",
			fields: fields{
				dir: "./testdata/misconfig/terraform/multiple-failures/src",
			},
			artifactOpt: artifact.Option{
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
						SchemaVersion: 2,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "terraform",
								FilePath: ".",
								Successes: types.MisconfResults{
									{
										Namespace: "builtin.aws.rds.aws0176",
										Query:     "data.builtin.aws.rds.aws0176.deny",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "N/A",
											AVDID:              "AVD-AWS-0176",
											Type:               "Terraform Security Check",
											Title:              "RDS IAM Database Authentication Disabled",
											Description:        "Ensure IAM Database Authentication is enabled for RDS database instances to manage database access",
											Severity:           "MEDIUM",
											RecommendedActions: "Modify the PostgreSQL and MySQL type RDS instances to enable IAM database authentication.",
											References:         []string{"https://docs.aws.amazon.com/neptune/latest/userguide/iam-auth.html"},
										},
										CauseMetadata: types.CauseMetadata{
											Provider: "AWS",
											Service:  "rds",
										},
									},
									{
										Namespace: "builtin.aws.rds.aws0177",
										Query:     "data.builtin.aws.rds.aws0177.deny",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "N/A",
											AVDID:              "AVD-AWS-0177",
											Type:               "Terraform Security Check",
											Title:              "RDS Deletion Protection Disabled",
											Description:        "Ensure deletion protection is enabled for RDS database instances.",
											Severity:           "MEDIUM",
											RecommendedActions: "Modify the RDS instances to enable deletion protection.",
											References:         []string{"https://aws.amazon.com/about-aws/whats-new/2018/09/amazon-rds-now-provides-database-deletion-protection/"},
										},
										CauseMetadata: types.CauseMetadata{
											Provider: "AWS",
											Service:  "rds",
										},
									},
									{
										Namespace: "builtin.aws.rds.aws0180",
										Query:     "data.builtin.aws.rds.aws0180.deny",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "N/A",
											AVDID:              "AVD-AWS-0180",
											Type:               "Terraform Security Check",
											Title:              "RDS Publicly Accessible",
											Description:        "Ensures RDS instances are not launched into the public cloud.",
											Severity:           "HIGH",
											RecommendedActions: "Remove the public endpoint from the RDS instance'",
											References:         []string{"http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.html"},
										},
										CauseMetadata: types.CauseMetadata{
											Resource: "", Provider: "AWS", Service: "rds", StartLine: 0, EndLine: 0,
											Code: types.Code{Lines: []types.Line(nil)},
										}, Traces: []string(nil),
									},
								},
							},
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
											Resource:  "aws_s3_bucket.one",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 1,
											EndLine:   3,
										},
									},
									{
										Namespace: "user.something", Query: "data.user.something.deny",
										Message: "No buckets allowed!",
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
				Name: "testdata/misconfig/terraform/multiple-failures/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:99517dc844bb08a112ad5c418b87e179cebee917a7d4cf1406bdcfe1429eeabb",
				BlobIDs: []string{
					"sha256:99517dc844bb08a112ad5c418b87e179cebee917a7d4cf1406bdcfe1429eeabb",
				},
			},
		},
		{
			name: "no results",
			fields: fields{
				dir: "./testdata/misconfig/terraform/no-results/src",
			},
			artifactOpt: artifact.Option{
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
				ID:   "sha256:6612c1db6d6c52c11de53447264b552ee96bf9cc317de37b3374687a8fc4c4ac",
				BlobIDs: []string{
					"sha256:6612c1db6d6c52c11de53447264b552ee96bf9cc317de37b3374687a8fc4c4ac",
				},
			},
		},
		{
			name: "passed",
			fields: fields{
				dir: "./testdata/misconfig/terraform/passed/src",
			},
			artifactOpt: artifact.Option{
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
						SchemaVersion: 2,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "terraform",
								FilePath: ".",
								Successes: types.MisconfResults{
									{
										Namespace: "builtin.aws.rds.aws0176",
										Query:     "data.builtin.aws.rds.aws0176.deny",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "N/A",
											AVDID:              "AVD-AWS-0176",
											Type:               "Terraform Security Check",
											Title:              "RDS IAM Database Authentication Disabled",
											Description:        "Ensure IAM Database Authentication is enabled for RDS database instances to manage database access",
											Severity:           "MEDIUM",
											RecommendedActions: "Modify the PostgreSQL and MySQL type RDS instances to enable IAM database authentication.",
											References:         []string{"https://docs.aws.amazon.com/neptune/latest/userguide/iam-auth.html"},
										},
										CauseMetadata: types.CauseMetadata{
											Provider: "AWS",
											Service:  "rds",
										},
									},
									{
										Namespace: "builtin.aws.rds.aws0177",
										Query:     "data.builtin.aws.rds.aws0177.deny",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "N/A",
											AVDID:              "AVD-AWS-0177",
											Type:               "Terraform Security Check",
											Title:              "RDS Deletion Protection Disabled",
											Description:        "Ensure deletion protection is enabled for RDS database instances.",
											Severity:           "MEDIUM",
											RecommendedActions: "Modify the RDS instances to enable deletion protection.",
											References:         []string{"https://aws.amazon.com/about-aws/whats-new/2018/09/amazon-rds-now-provides-database-deletion-protection/"},
										},
										CauseMetadata: types.CauseMetadata{
											Provider: "AWS",
											Service:  "rds",
										},
									},
									{
										Namespace: "builtin.aws.rds.aws0180",
										Query:     "data.builtin.aws.rds.aws0180.deny",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "N/A",
											AVDID:              "AVD-AWS-0180",
											Type:               "Terraform Security Check",
											Title:              "RDS Publicly Accessible",
											Description:        "Ensures RDS instances are not launched into the public cloud.",
											Severity:           "HIGH",
											RecommendedActions: "Remove the public endpoint from the RDS instance'",
											References:         []string{"http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.html"},
										},
										CauseMetadata: types.CauseMetadata{
											Resource: "", Provider: "AWS", Service: "rds", StartLine: 0, EndLine: 0,
											Code: types.Code{Lines: []types.Line(nil)},
										}, Traces: []string(nil),
									},
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
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
				Name: "testdata/misconfig/terraform/passed/src",
				Type: types.ArtifactFilesystem,
				ID:   "sha256:3b10f21212504dafd8b4e5656b1cb590a6cb88f6a9e20e05b1a773e1b2951714",
				BlobIDs: []string{
					"sha256:3b10f21212504dafd8b4e5656b1cb590a6cb88f6a9e20e05b1a773e1b2951714",
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
            SchemaVersion: 2,
            Misconfigurations: []types.Misconfiguration{
              {
                FileType: "cloudformation",
                FilePath: "main.yaml",
                Successes: types.MisconfResults{
                  {
                    Namespace: "builtin.aws.rds.aws0176",
                    Query:     "data.builtin.aws.rds.aws0176.deny",
                    PolicyMetadata: types.PolicyMetadata{
                      ID:                 "N/A",
                      AVDID:              "AVD-AWS-0176",
                      Type:               "CloudFormation Security Check",
                      Title:              "RDS IAM Database Authentication Disabled",
                      Description:        "Ensure IAM Database Authentication is enabled for RDS database instances to manage database access",
                      Severity:           "MEDIUM",
                      RecommendedActions: "Modify the PostgreSQL and MySQL type RDS instances to enable IAM database authentication.",
                      References:         []string{"https://docs.aws.amazon.com/neptune/latest/userguide/iam-auth.html"},
                    },
                    CauseMetadata: types.CauseMetadata{
                      Provider: "AWS",
                      Service:  "rds",
                    },
                  },
                  {
                    Namespace: "builtin.aws.rds.aws0177",
                    Query:     "data.builtin.aws.rds.aws0177.deny",
                    PolicyMetadata: types.PolicyMetadata{
                      ID:                 "N/A",
                      AVDID:              "AVD-AWS-0177",
                      Type:               "CloudFormation Security Check",
                      Title:              "RDS Deletion Protection Disabled",
                      Description:        "Ensure deletion protection is enabled for RDS database instances.",
                      Severity:           "MEDIUM",
                      RecommendedActions: "Modify the RDS instances to enable deletion protection.",
                      References:         []string{"https://aws.amazon.com/about-aws/whats-new/2018/09/amazon-rds-now-provides-database-deletion-protection/"},
                    },
                    CauseMetadata: types.CauseMetadata{
                      Provider: "AWS",
                      Service:  "rds",
                    },
                  },
                  {
                    Namespace: "builtin.aws.rds.aws0180",
                    Query:     "data.builtin.aws.rds.aws0180.deny",
                    PolicyMetadata: types.PolicyMetadata{
                      ID:                 "N/A",
                      AVDID:              "AVD-AWS-0180",
                      Type:               "CloudFormation Security Check",
                      Title:              "RDS Publicly Accessible",
                      Description:        "Ensures RDS instances are not launched into the public cloud.",
                      Severity:           "HIGH",
                      RecommendedActions: "Remove the public endpoint from the RDS instance'",
                      References:         []string{"http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.html"},
                    },
                    CauseMetadata: types.CauseMetadata{
                      Resource: "", Provider: "AWS", Service: "rds", StartLine: 0, EndLine: 0,
                      Code: types.Code{Lines: []types.Line(nil)},
                    }, Traces: []string(nil),
                  },
                },
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
        ID:   "sha256:fc9006e68fd8e3306ec2e7fb4868c273223e133208bcf920d75cdd393a5cb155",
        BlobIDs: []string{
          "sha256:fc9006e68fd8e3306ec2e7fb4868c273223e133208bcf920d75cdd393a5cb155",
        },
      },
    },
    {
      name: "multiple failures",
      fields: fields{
        dir: "./testdata/misconfig/cloudformation/multiple-failures/src",
      },
      artifactOpt: artifact.Option{
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
            SchemaVersion: 2,
            Misconfigurations: []types.Misconfiguration{
              {
                FileType: "cloudformation",
                FilePath: "main.yaml",
                Successes: types.MisconfResults{
                  {
                    Namespace: "builtin.aws.rds.aws0176",
                    Query:     "data.builtin.aws.rds.aws0176.deny",
                    PolicyMetadata: types.PolicyMetadata{
                      ID:                 "N/A",
                      AVDID:              "AVD-AWS-0176",
                      Type:               "CloudFormation Security Check",
                      Title:              "RDS IAM Database Authentication Disabled",
                      Description:        "Ensure IAM Database Authentication is enabled for RDS database instances to manage database access",
                      Severity:           "MEDIUM",
                      RecommendedActions: "Modify the PostgreSQL and MySQL type RDS instances to enable IAM database authentication.",
                      References:         []string{"https://docs.aws.amazon.com/neptune/latest/userguide/iam-auth.html"},
                    },
                    CauseMetadata: types.CauseMetadata{
                      Provider: "AWS",
                      Service:  "rds",
                    },
                  },
                  {
                    Namespace: "builtin.aws.rds.aws0177",
                    Query:     "data.builtin.aws.rds.aws0177.deny",
                    PolicyMetadata: types.PolicyMetadata{
                      ID:                 "N/A",
                      AVDID:              "AVD-AWS-0177",
                      Type:               "CloudFormation Security Check",
                      Title:              "RDS Deletion Protection Disabled",
                      Description:        "Ensure deletion protection is enabled for RDS database instances.",
                      Severity:           "MEDIUM",
                      RecommendedActions: "Modify the RDS instances to enable deletion protection.",
                      References:         []string{"https://aws.amazon.com/about-aws/whats-new/2018/09/amazon-rds-now-provides-database-deletion-protection/"},
                    },
                    CauseMetadata: types.CauseMetadata{
                      Provider: "AWS",
                      Service:  "rds",
                    },
                  },
                  {
                    Namespace: "builtin.aws.rds.aws0180",
                    Query:     "data.builtin.aws.rds.aws0180.deny",
                    PolicyMetadata: types.PolicyMetadata{
                      ID:                 "N/A",
                      AVDID:              "AVD-AWS-0180",
                      Type:               "CloudFormation Security Check",
                      Title:              "RDS Publicly Accessible",
                      Description:        "Ensures RDS instances are not launched into the public cloud.",
                      Severity:           "HIGH",
                      RecommendedActions: "Remove the public endpoint from the RDS instance'",
                      References:         []string{"http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.html"},
                    },
                    CauseMetadata: types.CauseMetadata{
                      Resource: "", Provider: "AWS", Service: "rds", StartLine: 0, EndLine: 0,
                      Code: types.Code{Lines: []types.Line(nil)},
                    }, Traces: []string(nil),
                  },
                },
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
        ID:   "sha256:d007d48e2a07a76462768fa561e6f4f72c93f5835465522cda7a2fb5056c60b6",
        BlobIDs: []string{
          "sha256:d007d48e2a07a76462768fa561e6f4f72c93f5835465522cda7a2fb5056c60b6",
        },
      },
    },
    {
      name: "no results",
      fields: fields{
        dir: "./testdata/misconfig/cloudformation/no-results/src",
      },
      artifactOpt: artifact.Option{
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
        ID:   "sha256:cd80d8148f9b4cbc026f71a73d8dc1e35f79f6f39e4e52fe5e9a7821e9d09693",
        BlobIDs: []string{
          "sha256:cd80d8148f9b4cbc026f71a73d8dc1e35f79f6f39e4e52fe5e9a7821e9d09693",
        },
      },
    },
		{
			name: "passed",
			fields: fields{
				dir: "./testdata/misconfig/cloudformation/passed/src",
			},
			artifactOpt: artifact.Option{
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
						SchemaVersion: 2,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "cloudformation",
								FilePath: "main.yaml",
								Successes: types.MisconfResults{
									{
										Namespace: "builtin.aws.rds.aws0176",
										Query:     "data.builtin.aws.rds.aws0176.deny",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "N/A",
											AVDID:              "AVD-AWS-0176",
											Type:               "CloudFormation Security Check",
											Title:              "RDS IAM Database Authentication Disabled",
											Description:        "Ensure IAM Database Authentication is enabled for RDS database instances to manage database access",
											Severity:           "MEDIUM",
											RecommendedActions: "Modify the PostgreSQL and MySQL type RDS instances to enable IAM database authentication.",
											References:         []string{"https://docs.aws.amazon.com/neptune/latest/userguide/iam-auth.html"},
										},
										CauseMetadata: types.CauseMetadata{
											Provider: "AWS",
											Service:  "rds",
										},
									},
									{
										Namespace: "builtin.aws.rds.aws0177",
										Query:     "data.builtin.aws.rds.aws0177.deny",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "N/A",
											AVDID:              "AVD-AWS-0177",
											Type:               "CloudFormation Security Check",
											Title:              "RDS Deletion Protection Disabled",
											Description:        "Ensure deletion protection is enabled for RDS database instances.",
											Severity:           "MEDIUM",
											RecommendedActions: "Modify the RDS instances to enable deletion protection.",
											References:         []string{"https://aws.amazon.com/about-aws/whats-new/2018/09/amazon-rds-now-provides-database-deletion-protection/"},
										},
										CauseMetadata: types.CauseMetadata{
											Provider: "AWS",
											Service:  "rds",
										},
									},
									{
										Namespace: "builtin.aws.rds.aws0180",
										Query:     "data.builtin.aws.rds.aws0180.deny",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "N/A",
											AVDID:              "AVD-AWS-0180",
											Type:               "CloudFormation Security Check",
											Title:              "RDS Publicly Accessible",
											Description:        "Ensures RDS instances are not launched into the public cloud.",
											Severity:           "HIGH",
											RecommendedActions: "Remove the public endpoint from the RDS instance'",
											References:         []string{"http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.html"},
										},
										CauseMetadata: types.CauseMetadata{
											Resource: "", Provider: "AWS", Service: "rds", StartLine: 0, EndLine: 0,
											Code: types.Code{Lines: []types.Line(nil)},
										}, Traces: []string(nil),
									},
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
				ID:   "sha256:0c3ba0cb0ff2d77ed46e57ea8e6d7961844f68947599732d95e9596e314efbcd",
				BlobIDs: []string{
					"sha256:0c3ba0cb0ff2d77ed46e57ea8e6d7961844f68947599732d95e9596e314efbcd",
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
				ID:   "sha256:acf53660fed1eb7961e3c47f85c8f41a117f7df7a0c09221f6d84fc64737e361",
				BlobIDs: []string{
					"sha256:acf53660fed1eb7961e3c47f85c8f41a117f7df7a0c09221f6d84fc64737e361",
				},
			},
		},
		{
			name: "multiple failures",
			fields: fields{
				dir: "./testdata/misconfig/dockerfile/multiple-failures/src",
			},
			artifactOpt: artifact.Option{
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
				ID:   "sha256:acf53660fed1eb7961e3c47f85c8f41a117f7df7a0c09221f6d84fc64737e361",
				BlobIDs: []string{
					"sha256:acf53660fed1eb7961e3c47f85c8f41a117f7df7a0c09221f6d84fc64737e361",
				},
			},
		},
		{
			name: "no results",
			fields: fields{
				dir: "./testdata/misconfig/dockerfile/no-results/src",
			},
			artifactOpt: artifact.Option{
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
				ID:   "sha256:6612c1db6d6c52c11de53447264b552ee96bf9cc317de37b3374687a8fc4c4ac",
				BlobIDs: []string{
					"sha256:6612c1db6d6c52c11de53447264b552ee96bf9cc317de37b3374687a8fc4c4ac",
				},
			},
		},
		{
			name: "passed",
			fields: fields{
				dir: "./testdata/misconfig/dockerfile/passed/src",
			},
			artifactOpt: artifact.Option{
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
				ID:   "sha256:78a5071a951a980a53a0df7818384eda36fedd2a0237529a43e12979d3bf36f9",
				BlobIDs: []string{
					"sha256:78a5071a951a980a53a0df7818384eda36fedd2a0237529a43e12979d3bf36f9",
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
				ID:   "sha256:2a60e6a9b9cf1ab3c083f4e52a38d3c70026ab331b771d449b06f4ffd4b6f2dd",
				BlobIDs: []string{
					"sha256:2a60e6a9b9cf1ab3c083f4e52a38d3c70026ab331b771d449b06f4ffd4b6f2dd",
				},
			},
		},
		{
			name: "multiple failures",
			fields: fields{
				dir: "./testdata/misconfig/kubernetes/multiple-failures/src",
			},
			artifactOpt: artifact.Option{
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
				ID:   "sha256:56675c845f72190c9a6277d51a0c8248768d5322ea0d92650d1cc179f20d920e",
				BlobIDs: []string{
					"sha256:56675c845f72190c9a6277d51a0c8248768d5322ea0d92650d1cc179f20d920e",
				},
			},
		},
		{
			name: "no results",
			fields: fields{
				dir: "./testdata/misconfig/kubernetes/no-results/src",
			},
			artifactOpt: artifact.Option{
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
				ID:   "sha256:f1bc1b154a70ae2e1d94297ffcf721348d1975037ccd4a32f4f1157738cbe54d",
				BlobIDs: []string{
					"sha256:f1bc1b154a70ae2e1d94297ffcf721348d1975037ccd4a32f4f1157738cbe54d",
				},
			},
		},
		{
			name: "passed",
			fields: fields{
				dir: "./testdata/misconfig/kubernetes/passed/src",
			},
			artifactOpt: artifact.Option{
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
				ID:   "sha256:64fd37028d8cb4aefa49d6fa8438fa3a7e08ca331bfdfad22faf91e31ca0ff29",
				BlobIDs: []string{
					"sha256:64fd37028d8cb4aefa49d6fa8438fa3a7e08ca331bfdfad22faf91e31ca0ff29",
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
						SchemaVersion: 2,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "azure-arm",
								FilePath: "deploy.json",
								Successes: types.MisconfResults{
									{
										Namespace: "builtin.aws.rds.aws0176",
										Query:     "data.builtin.aws.rds.aws0176.deny",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "N/A",
											AVDID:              "AVD-AWS-0176",
											Type:               "Azure ARM Security Check",
											Title:              "RDS IAM Database Authentication Disabled",
											Description:        "Ensure IAM Database Authentication is enabled for RDS database instances to manage database access",
											Severity:           "MEDIUM",
											RecommendedActions: "Modify the PostgreSQL and MySQL type RDS instances to enable IAM database authentication.",
											References:         []string{"https://docs.aws.amazon.com/neptune/latest/userguide/iam-auth.html"},
										},
										CauseMetadata: types.CauseMetadata{
											Provider: "AWS",
											Service:  "rds",
										},
									},
									{
										Namespace: "builtin.aws.rds.aws0177",
										Query:     "data.builtin.aws.rds.aws0177.deny",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "N/A",
											AVDID:              "AVD-AWS-0177",
											Type:               "Azure ARM Security Check",
											Title:              "RDS Deletion Protection Disabled",
											Description:        "Ensure deletion protection is enabled for RDS database instances.",
											Severity:           "MEDIUM",
											RecommendedActions: "Modify the RDS instances to enable deletion protection.",
											References:         []string{"https://aws.amazon.com/about-aws/whats-new/2018/09/amazon-rds-now-provides-database-deletion-protection/"},
										},
										CauseMetadata: types.CauseMetadata{
											Provider: "AWS",
											Service:  "rds",
										},
									},
										{
										Namespace: "builtin.aws.rds.aws0180",
										Query:     "data.builtin.aws.rds.aws0180.deny",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "N/A",
											AVDID:              "AVD-AWS-0180",
											Type:               "Azure ARM Security Check",
											Title:              "RDS Publicly Accessible",
											Description:        "Ensures RDS instances are not launched into the public cloud.",
											Severity:           "HIGH",
											RecommendedActions: "Remove the public endpoint from the RDS instance'",
											References:         []string{"http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.html"},
										},
										CauseMetadata: types.CauseMetadata{
											Resource: "", Provider: "AWS", Service: "rds", StartLine: 0, EndLine: 0,
											Code: types.Code{Lines: []types.Line(nil)},
										}, Traces: []string(nil),
									},
								},
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
				ID:   "sha256:2d7ddb4a4f5e05278903bfa020a95756682ffcc8b168a79c9f9363806151803c",
				BlobIDs: []string{
					"sha256:2d7ddb4a4f5e05278903bfa020a95756682ffcc8b168a79c9f9363806151803c",
				},
			},
		},
		{
			name: "multiple failures",
			fields: fields{
				dir: "./testdata/misconfig/azurearm/multiple-failures/src",
			},
			artifactOpt: artifact.Option{
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
						SchemaVersion: 2,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "azure-arm",
								FilePath: "deploy.json",
								Successes: types.MisconfResults{
									{
										Namespace: "builtin.aws.rds.aws0176",
										Query:     "data.builtin.aws.rds.aws0176.deny",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "N/A",
											AVDID:              "AVD-AWS-0176",
											Type:               "Azure ARM Security Check",
											Title:              "RDS IAM Database Authentication Disabled",
											Description:        "Ensure IAM Database Authentication is enabled for RDS database instances to manage database access",
											Severity:           "MEDIUM",
											RecommendedActions: "Modify the PostgreSQL and MySQL type RDS instances to enable IAM database authentication.",
											References:         []string{"https://docs.aws.amazon.com/neptune/latest/userguide/iam-auth.html"},
										},
										CauseMetadata: types.CauseMetadata{
											Provider: "AWS",
											Service:  "rds",
										},
									},
									{
										Namespace: "builtin.aws.rds.aws0177",
										Query:     "data.builtin.aws.rds.aws0177.deny",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "N/A",
											AVDID:              "AVD-AWS-0177",
											Type:               "Azure ARM Security Check",
											Title:              "RDS Deletion Protection Disabled",
											Description:        "Ensure deletion protection is enabled for RDS database instances.",
											Severity:           "MEDIUM",
											RecommendedActions: "Modify the RDS instances to enable deletion protection.",
											References:         []string{"https://aws.amazon.com/about-aws/whats-new/2018/09/amazon-rds-now-provides-database-deletion-protection/"},
										},
										CauseMetadata: types.CauseMetadata{
											Provider: "AWS",
											Service:  "rds",
										},
									},
									{
										Namespace: "builtin.aws.rds.aws0180",
										Query:     "data.builtin.aws.rds.aws0180.deny",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "N/A",
											AVDID:              "AVD-AWS-0180",
											Type:               "Azure ARM Security Check",
											Title:              "RDS Publicly Accessible",
											Description:        "Ensures RDS instances are not launched into the public cloud.",
											Severity:           "HIGH",
											RecommendedActions: "Remove the public endpoint from the RDS instance'",
											References:         []string{"http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.html"},
										},
										CauseMetadata: types.CauseMetadata{
											Resource: "", Provider: "AWS", Service: "rds", StartLine: 0, EndLine: 0,
											Code: types.Code{Lines: []types.Line(nil)},
										}, Traces: []string(nil),
									},
								},
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
				ID:   "sha256:101d413693da46fc1f5e3465c1ac9c00e12cd802a475dd348b470ae9e20bbc8d",
				BlobIDs: []string{
					"sha256:101d413693da46fc1f5e3465c1ac9c00e12cd802a475dd348b470ae9e20bbc8d",
				},
			},
		},
		{
			name: "no results",
			fields: fields{
				dir: "./testdata/misconfig/azurearm/no-results/src",
			},
			artifactOpt: artifact.Option{
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
				ID:   "sha256:6612c1db6d6c52c11de53447264b552ee96bf9cc317de37b3374687a8fc4c4ac",
				BlobIDs: []string{
					"sha256:6612c1db6d6c52c11de53447264b552ee96bf9cc317de37b3374687a8fc4c4ac",
				},
			},
		},
		{
			name: "passed",
			fields: fields{
				dir: "./testdata/misconfig/azurearm/passed/src",
			},
			artifactOpt: artifact.Option{
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
						SchemaVersion: 2,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "azure-arm",
								FilePath: "deploy.json",
								Successes: types.MisconfResults{
									{
										Namespace: "builtin.aws.rds.aws0176",
										Query:     "data.builtin.aws.rds.aws0176.deny",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "N/A",
											AVDID:              "AVD-AWS-0176",
											Type:               "Azure ARM Security Check",
											Title:              "RDS IAM Database Authentication Disabled",
											Description:        "Ensure IAM Database Authentication is enabled for RDS database instances to manage database access",
											Severity:           "MEDIUM",
											RecommendedActions: "Modify the PostgreSQL and MySQL type RDS instances to enable IAM database authentication.",
											References:         []string{"https://docs.aws.amazon.com/neptune/latest/userguide/iam-auth.html"},
										},
										CauseMetadata: types.CauseMetadata{
											Provider: "AWS",
											Service:  "rds",
										},
									},
									{
										Namespace: "builtin.aws.rds.aws0177",
										Query:     "data.builtin.aws.rds.aws0177.deny",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "N/A",
											AVDID:              "AVD-AWS-0177",
											Type:               "Azure ARM Security Check",
											Title:              "RDS Deletion Protection Disabled",
											Description:        "Ensure deletion protection is enabled for RDS database instances.",
											Severity:           "MEDIUM",
											RecommendedActions: "Modify the RDS instances to enable deletion protection.",
											References:         []string{"https://aws.amazon.com/about-aws/whats-new/2018/09/amazon-rds-now-provides-database-deletion-protection/"},
										}, CauseMetadata: types.CauseMetadata{
											Provider: "AWS",
											Service:  "rds",
										},
									},
									{
										Namespace: "builtin.aws.rds.aws0180",
										Query:     "data.builtin.aws.rds.aws0180.deny",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "N/A",
											AVDID:              "AVD-AWS-0180",
											Type:               "Azure ARM Security Check",
											Title:              "RDS Publicly Accessible",
											Description:        "Ensures RDS instances are not launched into the public cloud.",
											Severity:           "HIGH",
											RecommendedActions: "Remove the public endpoint from the RDS instance'",
											References:         []string{"http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.html"},
										},
										CauseMetadata: types.CauseMetadata{
											Resource: "", Provider: "AWS", Service: "rds", StartLine: 0, EndLine: 0,
											Code: types.Code{Lines: []types.Line(nil)},
										}, Traces: []string(nil),
									},
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
				ID:   "sha256:9a45fcaed342f1778b1221f97c5cdad91a06cd24345e16be81315c1ae8ef1d23",
				BlobIDs: []string{
					"sha256:9a45fcaed342f1778b1221f97c5cdad91a06cd24345e16be81315c1ae8ef1d23",
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
