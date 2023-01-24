package commands

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Run(t *testing.T) {

	regoDir := t.TempDir()

	tests := []struct {
		name         string
		options      flag.Options
		want         string
		expectErr    bool
		cacheContent string
		regoPolicy   string
	}{
		{
			name: "fail without region",
			options: flag.Options{
				RegoOptions: flag.RegoOptions{SkipPolicyUpdate: true},
			},
			want:      "",
			expectErr: true,
		},
		{
			name: "fail without creds",
			options: flag.Options{
				RegoOptions: flag.RegoOptions{SkipPolicyUpdate: true},
				AWSOptions: flag.AWSOptions{
					Region: "us-east-1",
				},
			},
			want:      "",
			expectErr: true,
		},
		{
			name: "try to call aws if cache is expired",
			options: flag.Options{
				RegoOptions: flag.RegoOptions{SkipPolicyUpdate: true},
				AWSOptions: flag.AWSOptions{
					Region:   "us-east-1",
					Services: []string{"s3"},
					Account:  "12345678",
				},
				CloudOptions: flag.CloudOptions{
					MaxCacheAge: time.Minute,
				},
			},
			cacheContent: exampleS3Cache,
			expectErr:    true,
		},
		{
			name: "succeed with cached infra",
			options: flag.Options{
				RegoOptions: flag.RegoOptions{SkipPolicyUpdate: true},
				AWSOptions: flag.AWSOptions{
					Region:   "us-east-1",
					Services: []string{"s3"},
					Account:  "12345678",
				},
				CloudOptions: flag.CloudOptions{
					MaxCacheAge: time.Hour * 24 * 365 * 100,
				},
			},
			cacheContent: exampleS3Cache,
			want: `{
  "ArtifactName": "12345678",
  "ArtifactType": "aws_account",
  "Metadata": {
    "ImageConfig": {
      "architecture": "",
      "created": "0001-01-01T00:00:00Z",
      "os": "",
      "rootfs": {
        "type": "",
        "diff_ids": null
      },
      "config": {}
    }
  },
  "Results": [
    {
      "Target": "arn:aws:s3:::examplebucket",
      "Class": "config",
      "Type": "cloud",
      "MisconfSummary": {
        "Successes": 0,
        "Failures": 9,
        "Exceptions": 0
      },
      "Misconfigurations": [
        {
          "Type": "AWS",
          "ID": "AVD-AWS-0086",
          "AVDID": "AVD-AWS-0086",
          "Title": "S3 Access block should block public ACL",
          "Description": "S3 buckets should block public ACLs on buckets and any objects they contain. By blocking, PUTs with fail if the object has any public ACL a.",
          "Message": "No public access block so not blocking public acls",
          "Resolution": "Enable blocking any PUT calls with a public ACL specified",
          "Severity": "HIGH",
          "PrimaryURL": "https://avd.aquasec.com/misconfig/avd-aws-0086",
          "References": [
            "https://avd.aquasec.com/misconfig/avd-aws-0086"
          ],
          "Status": "FAIL",
          "Layer": {},
          "CauseMetadata": {
            "Resource": "arn:aws:s3:::examplebucket",
            "Provider": "aws",
            "Service": "s3",
            "Code": {
              "Lines": null
            }
          }
        },
        {
          "Type": "AWS",
          "ID": "AVD-AWS-0087",
          "AVDID": "AVD-AWS-0087",
          "Title": "S3 Access block should block public policy",
          "Description": "S3 bucket policy should have block public policy to prevent users from putting a policy that enable public access.",
          "Message": "No public access block so not blocking public policies",
          "Resolution": "Prevent policies that allow public access being PUT",
          "Severity": "HIGH",
          "PrimaryURL": "https://avd.aquasec.com/misconfig/avd-aws-0087",
          "References": [
            "https://avd.aquasec.com/misconfig/avd-aws-0087"
          ],
          "Status": "FAIL",
          "Layer": {},
          "CauseMetadata": {
            "Resource": "arn:aws:s3:::examplebucket",
            "Provider": "aws",
            "Service": "s3",
            "Code": {
              "Lines": null
            }
          }
        },
        {
          "Type": "AWS",
          "ID": "AVD-AWS-0088",
          "AVDID": "AVD-AWS-0088",
          "Title": "Unencrypted S3 bucket.",
          "Description": "S3 Buckets should be encrypted to protect the data that is stored within them if access is compromised.",
          "Message": "Bucket does not have encryption enabled",
          "Resolution": "Configure bucket encryption",
          "Severity": "HIGH",
          "PrimaryURL": "https://avd.aquasec.com/misconfig/avd-aws-0088",
          "References": [
            "https://avd.aquasec.com/misconfig/avd-aws-0088"
          ],
          "Status": "FAIL",
          "Layer": {},
          "CauseMetadata": {
            "Resource": "arn:aws:s3:::examplebucket",
            "Provider": "aws",
            "Service": "s3",
            "Code": {
              "Lines": null
            }
          }
        },
        {
          "Type": "AWS",
          "ID": "AVD-AWS-0089",
          "AVDID": "AVD-AWS-0089",
          "Title": "S3 Bucket does not have logging enabled.",
          "Description": "Buckets should have logging enabled so that access can be audited.",
          "Message": "Bucket does not have logging enabled",
          "Resolution": "Add a logging block to the resource to enable access logging",
          "Severity": "MEDIUM",
          "PrimaryURL": "https://avd.aquasec.com/misconfig/avd-aws-0089",
          "References": [
            "https://avd.aquasec.com/misconfig/avd-aws-0089"
          ],
          "Status": "FAIL",
          "Layer": {},
          "CauseMetadata": {
            "Resource": "arn:aws:s3:::examplebucket",
            "Provider": "aws",
            "Service": "s3",
            "Code": {
              "Lines": null
            }
          }
        },
        {
          "Type": "AWS",
          "ID": "AVD-AWS-0090",
          "AVDID": "AVD-AWS-0090",
          "Title": "S3 Data should be versioned",
          "Description": "Versioning in Amazon S3 is a means of keeping multiple variants of an object in the same bucket. \nYou can use the S3 Versioning feature to preserve, retrieve, and restore every version of every object stored in your buckets. \nWith versioning you can recover more easily from both unintended user actions and application failures.",
          "Message": "Bucket does not have versioning enabled",
          "Resolution": "Enable versioning to protect against accidental/malicious removal or modification",
          "Severity": "MEDIUM",
          "PrimaryURL": "https://avd.aquasec.com/misconfig/avd-aws-0090",
          "References": [
            "https://avd.aquasec.com/misconfig/avd-aws-0090"
          ],
          "Status": "FAIL",
          "Layer": {},
          "CauseMetadata": {
            "Resource": "arn:aws:s3:::examplebucket",
            "Provider": "aws",
            "Service": "s3",
            "Code": {
              "Lines": null
            }
          }
        },
        {
          "Type": "AWS",
          "ID": "AVD-AWS-0132",
          "AVDID": "AVD-AWS-0132",
          "Title": "S3 encryption should use Customer Managed Keys",
          "Description": "Encryption using AWS keys provides protection for your S3 buckets. To increase control of the encryption and manage factors like rotation use customer managed keys.",
          "Message": "Bucket does not encrypt data with a customer managed key.",
          "Resolution": "Enable encryption using customer managed keys",
          "Severity": "HIGH",
          "PrimaryURL": "https://avd.aquasec.com/misconfig/avd-aws-0132",
          "References": [
            "https://avd.aquasec.com/misconfig/avd-aws-0132"
          ],
          "Status": "FAIL",
          "Layer": {},
          "CauseMetadata": {
            "Resource": "arn:aws:s3:::examplebucket",
            "Provider": "aws",
            "Service": "s3",
            "Code": {
              "Lines": null
            }
          }
        },
        {
          "Type": "AWS",
          "ID": "AVD-AWS-0091",
          "AVDID": "AVD-AWS-0091",
          "Title": "S3 Access Block should Ignore Public Acl",
          "Description": "S3 buckets should ignore public ACLs on buckets and any objects they contain. By ignoring rather than blocking, PUT calls with public ACLs will still be applied but the ACL will be ignored.",
          "Message": "No public access block so not ignoring public acls",
          "Resolution": "Enable ignoring the application of public ACLs in PUT calls",
          "Severity": "HIGH",
          "PrimaryURL": "https://avd.aquasec.com/misconfig/avd-aws-0091",
          "References": [
            "https://avd.aquasec.com/misconfig/avd-aws-0091"
          ],
          "Status": "FAIL",
          "Layer": {},
          "CauseMetadata": {
            "Resource": "arn:aws:s3:::examplebucket",
            "Provider": "aws",
            "Service": "s3",
            "Code": {
              "Lines": null
            }
          }
        },
        {
          "Type": "AWS",
          "ID": "AVD-AWS-0093",
          "AVDID": "AVD-AWS-0093",
          "Title": "S3 Access block should restrict public bucket to limit access",
          "Description": "S3 buckets should restrict public policies for the bucket. By enabling, the restrict_public_buckets, only the bucket owner and AWS Services can access if it has a public policy.",
          "Message": "No public access block so not restricting public buckets",
          "Resolution": "Limit the access to public buckets to only the owner or AWS Services (eg; CloudFront)",
          "Severity": "HIGH",
          "PrimaryURL": "https://avd.aquasec.com/misconfig/avd-aws-0093",
          "References": [
            "https://avd.aquasec.com/misconfig/avd-aws-0093"
          ],
          "Status": "FAIL",
          "Layer": {},
          "CauseMetadata": {
            "Resource": "arn:aws:s3:::examplebucket",
            "Provider": "aws",
            "Service": "s3",
            "Code": {
              "Lines": null
            }
          }
        },
        {
          "Type": "AWS",
          "ID": "AVD-AWS-0094",
          "AVDID": "AVD-AWS-0094",
          "Title": "S3 buckets should each define an aws_s3_bucket_public_access_block",
          "Description": "The \"block public access\" settings in S3 override individual policies that apply to a given bucket, meaning that all public access can be controlled in one central types for that bucket. It is therefore good practice to define these settings for each bucket in order to clearly define the public access that can be allowed for it.",
          "Message": "Bucket does not have a corresponding public access block.",
          "Resolution": "Define a aws_s3_bucket_public_access_block for the given bucket to control public access policies",
          "Severity": "LOW",
          "PrimaryURL": "https://avd.aquasec.com/misconfig/avd-aws-0094",
          "References": [
            "https://avd.aquasec.com/misconfig/avd-aws-0094"
          ],
          "Status": "FAIL",
          "Layer": {},
          "CauseMetadata": {
            "Resource": "arn:aws:s3:::examplebucket",
            "Provider": "aws",
            "Service": "s3",
            "Code": {
              "Lines": null
            }
          }
        }
      ]
    }
  ]
}
`,
		},
		{
			name: "custom rego rule",
			options: flag.Options{
				AWSOptions: flag.AWSOptions{
					Region:   "us-east-1",
					Services: []string{"s3"},
					Account:  "12345678",
				},
				CloudOptions: flag.CloudOptions{
					MaxCacheAge: time.Hour * 24 * 365 * 100,
				},
				RegoOptions: flag.RegoOptions{
					Trace: true,
					PolicyPaths: []string{
						filepath.Join(regoDir, "policies"),
					},
					PolicyNamespaces: []string{
						"user",
					},
				},
			},
			regoPolicy: `# METADATA
# title: No example buckets
# description: Buckets should not be named with "example" in the name
# scope: package
# schemas:
# - input: schema["input"]
# custom:
#   severity: LOW
#   service: s3
#   input:
#     selector:
#     - type: cloud
package user.whatever

deny[res] {
	bucket := input.aws.s3.buckets[_]
	contains(bucket.name.value, "example")
	res := result.new("example bucket detected", bucket.name)
}
`,
			cacheContent: exampleS3Cache,
			want: `{
  "ArtifactName": "12345678",
  "ArtifactType": "aws_account",
  "Metadata": {
    "ImageConfig": {
      "architecture": "",
      "created": "0001-01-01T00:00:00Z",
      "os": "",
      "rootfs": {
        "type": "",
        "diff_ids": null
      },
      "config": {}
    }
  },
  "Results": [
    {
      "Target": "arn:aws:s3:::examplebucket",
      "Class": "config",
      "Type": "cloud",
      "MisconfSummary": {
        "Successes": 0,
        "Failures": 10,
        "Exceptions": 0
      },
      "Misconfigurations": [
        {
          "Type": "AWS",
          "ID": "AVD-AWS-0086",
          "AVDID": "AVD-AWS-0086",
          "Title": "S3 Access block should block public ACL",
          "Description": "S3 buckets should block public ACLs on buckets and any objects they contain. By blocking, PUTs with fail if the object has any public ACL a.",
          "Message": "No public access block so not blocking public acls",
          "Resolution": "Enable blocking any PUT calls with a public ACL specified",
          "Severity": "HIGH",
          "PrimaryURL": "https://avd.aquasec.com/misconfig/avd-aws-0086",
          "References": [
            "https://avd.aquasec.com/misconfig/avd-aws-0086"
          ],
          "Status": "FAIL",
          "Layer": {},
          "CauseMetadata": {
            "Resource": "arn:aws:s3:::examplebucket",
            "Provider": "aws",
            "Service": "s3",
            "Code": {
              "Lines": null
            }
          }
        },
        {
          "Type": "AWS",
          "ID": "AVD-AWS-0087",
          "AVDID": "AVD-AWS-0087",
          "Title": "S3 Access block should block public policy",
          "Description": "S3 bucket policy should have block public policy to prevent users from putting a policy that enable public access.",
          "Message": "No public access block so not blocking public policies",
          "Resolution": "Prevent policies that allow public access being PUT",
          "Severity": "HIGH",
          "PrimaryURL": "https://avd.aquasec.com/misconfig/avd-aws-0087",
          "References": [
            "https://avd.aquasec.com/misconfig/avd-aws-0087"
          ],
          "Status": "FAIL",
          "Layer": {},
          "CauseMetadata": {
            "Resource": "arn:aws:s3:::examplebucket",
            "Provider": "aws",
            "Service": "s3",
            "Code": {
              "Lines": null
            }
          }
        },
        {
          "Type": "AWS",
          "ID": "AVD-AWS-0088",
          "AVDID": "AVD-AWS-0088",
          "Title": "Unencrypted S3 bucket.",
          "Description": "S3 Buckets should be encrypted to protect the data that is stored within them if access is compromised.",
          "Message": "Bucket does not have encryption enabled",
          "Resolution": "Configure bucket encryption",
          "Severity": "HIGH",
          "PrimaryURL": "https://avd.aquasec.com/misconfig/avd-aws-0088",
          "References": [
            "https://avd.aquasec.com/misconfig/avd-aws-0088"
          ],
          "Status": "FAIL",
          "Layer": {},
          "CauseMetadata": {
            "Resource": "arn:aws:s3:::examplebucket",
            "Provider": "aws",
            "Service": "s3",
            "Code": {
              "Lines": null
            }
          }
        },
        {
          "Type": "AWS",
          "ID": "AVD-AWS-0089",
          "AVDID": "AVD-AWS-0089",
          "Title": "S3 Bucket does not have logging enabled.",
          "Description": "Buckets should have logging enabled so that access can be audited.",
          "Message": "Bucket does not have logging enabled",
          "Resolution": "Add a logging block to the resource to enable access logging",
          "Severity": "MEDIUM",
          "PrimaryURL": "https://avd.aquasec.com/misconfig/avd-aws-0089",
          "References": [
            "https://avd.aquasec.com/misconfig/avd-aws-0089"
          ],
          "Status": "FAIL",
          "Layer": {},
          "CauseMetadata": {
            "Resource": "arn:aws:s3:::examplebucket",
            "Provider": "aws",
            "Service": "s3",
            "Code": {
              "Lines": null
            }
          }
        },
        {
          "Type": "AWS",
          "ID": "AVD-AWS-0090",
          "AVDID": "AVD-AWS-0090",
          "Title": "S3 Data should be versioned",
          "Description": "Versioning in Amazon S3 is a means of keeping multiple variants of an object in the same bucket. \nYou can use the S3 Versioning feature to preserve, retrieve, and restore every version of every object stored in your buckets. \nWith versioning you can recover more easily from both unintended user actions and application failures.",
          "Message": "Bucket does not have versioning enabled",
          "Resolution": "Enable versioning to protect against accidental/malicious removal or modification",
          "Severity": "MEDIUM",
          "PrimaryURL": "https://avd.aquasec.com/misconfig/avd-aws-0090",
          "References": [
            "https://avd.aquasec.com/misconfig/avd-aws-0090"
          ],
          "Status": "FAIL",
          "Layer": {},
          "CauseMetadata": {
            "Resource": "arn:aws:s3:::examplebucket",
            "Provider": "aws",
            "Service": "s3",
            "Code": {
              "Lines": null
            }
          }
        },
        {
          "Type": "AWS",
          "ID": "AVD-AWS-0132",
          "AVDID": "AVD-AWS-0132",
          "Title": "S3 encryption should use Customer Managed Keys",
          "Description": "Encryption using AWS keys provides protection for your S3 buckets. To increase control of the encryption and manage factors like rotation use customer managed keys.",
          "Message": "Bucket does not encrypt data with a customer managed key.",
          "Resolution": "Enable encryption using customer managed keys",
          "Severity": "HIGH",
          "PrimaryURL": "https://avd.aquasec.com/misconfig/avd-aws-0132",
          "References": [
            "https://avd.aquasec.com/misconfig/avd-aws-0132"
          ],
          "Status": "FAIL",
          "Layer": {},
          "CauseMetadata": {
            "Resource": "arn:aws:s3:::examplebucket",
            "Provider": "aws",
            "Service": "s3",
            "Code": {
              "Lines": null
            }
          }
        },
        {
          "Type": "AWS",
          "ID": "AVD-AWS-0091",
          "AVDID": "AVD-AWS-0091",
          "Title": "S3 Access Block should Ignore Public Acl",
          "Description": "S3 buckets should ignore public ACLs on buckets and any objects they contain. By ignoring rather than blocking, PUT calls with public ACLs will still be applied but the ACL will be ignored.",
          "Message": "No public access block so not ignoring public acls",
          "Resolution": "Enable ignoring the application of public ACLs in PUT calls",
          "Severity": "HIGH",
          "PrimaryURL": "https://avd.aquasec.com/misconfig/avd-aws-0091",
          "References": [
            "https://avd.aquasec.com/misconfig/avd-aws-0091"
          ],
          "Status": "FAIL",
          "Layer": {},
          "CauseMetadata": {
            "Resource": "arn:aws:s3:::examplebucket",
            "Provider": "aws",
            "Service": "s3",
            "Code": {
              "Lines": null
            }
          }
        },
        {
          "Type": "AWS",
          "ID": "AVD-AWS-0093",
          "AVDID": "AVD-AWS-0093",
          "Title": "S3 Access block should restrict public bucket to limit access",
          "Description": "S3 buckets should restrict public policies for the bucket. By enabling, the restrict_public_buckets, only the bucket owner and AWS Services can access if it has a public policy.",
          "Message": "No public access block so not restricting public buckets",
          "Resolution": "Limit the access to public buckets to only the owner or AWS Services (eg; CloudFront)",
          "Severity": "HIGH",
          "PrimaryURL": "https://avd.aquasec.com/misconfig/avd-aws-0093",
          "References": [
            "https://avd.aquasec.com/misconfig/avd-aws-0093"
          ],
          "Status": "FAIL",
          "Layer": {},
          "CauseMetadata": {
            "Resource": "arn:aws:s3:::examplebucket",
            "Provider": "aws",
            "Service": "s3",
            "Code": {
              "Lines": null
            }
          }
        },
        {
          "Type": "AWS",
          "ID": "AVD-AWS-0094",
          "AVDID": "AVD-AWS-0094",
          "Title": "S3 buckets should each define an aws_s3_bucket_public_access_block",
          "Description": "The \"block public access\" settings in S3 override individual policies that apply to a given bucket, meaning that all public access can be controlled in one central types for that bucket. It is therefore good practice to define these settings for each bucket in order to clearly define the public access that can be allowed for it.",
          "Message": "Bucket does not have a corresponding public access block.",
          "Resolution": "Define a aws_s3_bucket_public_access_block for the given bucket to control public access policies",
          "Severity": "LOW",
          "PrimaryURL": "https://avd.aquasec.com/misconfig/avd-aws-0094",
          "References": [
            "https://avd.aquasec.com/misconfig/avd-aws-0094"
          ],
          "Status": "FAIL",
          "Layer": {},
          "CauseMetadata": {
            "Resource": "arn:aws:s3:::examplebucket",
            "Provider": "aws",
            "Service": "s3",
            "Code": {
              "Lines": null
            }
          }
        },
        {
          "Type": "AWS",
          "Title": "No example buckets",
          "Description": "Buckets should not be named with \"example\" in the name",
          "Message": "example bucket detected",
          "Namespace": "user.whatever",
          "Query": "deny",
          "Severity": "LOW",
          "References": [
            ""
          ],
          "Status": "FAIL",
          "Layer": {},
          "CauseMetadata": {
            "Resource": "arn:aws:s3:::examplebucket",
            "Provider": "cloud",
            "Service": "s3",
            "Code": {
              "Lines": null
            }
          }
        }
      ]
    }
  ]
}
`,
		},
		{
			name: "compliance report summary",
			options: flag.Options{
				AWSOptions: flag.AWSOptions{
					Region:   "us-east-1",
					Services: []string{"s3"},
					Account:  "12345678",
				},
				CloudOptions: flag.CloudOptions{
					MaxCacheAge: time.Hour * 24 * 365 * 100,
				},
				ReportOptions: flag.ReportOptions{Compliance: "@./testdata/example-spec.yaml", Format: "table", ReportFormat: "summary"},
			},
			cacheContent: exampleS3Cache,
			want: `
Summary Report for compliance: my-custom-spec
┌─────┬──────────┬───────────────────────┬────────┬────────┐
│ ID  │ Severity │     Control Name      │ Status │ Issues │
├─────┼──────────┼───────────────────────┼────────┼────────┤
│ 1.1 │ HIGH     │ Unencrypted S3 bucket │  FAIL  │   1    │
└─────┴──────────┴───────────────────────┴────────┴────────┘


`,
		},
		{
			name:      "error loading compliance report",
			expectErr: true,
			options: flag.Options{
				AWSOptions: flag.AWSOptions{
					Region:   "us-east-1",
					Services: []string{"s3"},
					Account:  "12345678",
				},
				CloudOptions: flag.CloudOptions{
					MaxCacheAge: time.Hour * 24 * 365 * 100,
				},
				ReportOptions: flag.ReportOptions{Compliance: "@./testdata/nosuchspec.yaml", Format: "table", ReportFormat: "summary"},
			},
			cacheContent: exampleS3Cache,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			buffer := new(bytes.Buffer)
			test.options.Output = buffer
			test.options.Debug = true
			test.options.GlobalOptions.Timeout = time.Minute
			if test.options.Format == "" {
				test.options.Format = "json"
			}
			test.options.Severities = []dbTypes.Severity{
				dbTypes.SeverityUnknown,
				dbTypes.SeverityLow,
				dbTypes.SeverityMedium,
				dbTypes.SeverityHigh,
				dbTypes.SeverityCritical,
			}

			if test.regoPolicy != "" {
				require.NoError(t, os.MkdirAll(filepath.Join(regoDir, "policies"), 0755))
				require.NoError(t, os.WriteFile(filepath.Join(regoDir, "policies", "user.rego"), []byte(test.regoPolicy), 0644))
			}

			if test.cacheContent != "" {
				cacheRoot := t.TempDir()
				test.options.CacheDir = cacheRoot
				cacheFile := filepath.Join(cacheRoot, "cloud", "aws", test.options.Account, test.options.Region, "data.json")
				require.NoError(t, os.MkdirAll(filepath.Dir(cacheFile), 0700))
				require.NoError(t, os.WriteFile(cacheFile, []byte(test.cacheContent), 0600))
			}

			err := Run(context.Background(), test.options)
			if test.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.want, buffer.String())
			}
		})
	}
}

const exampleS3Cache = `{
   "schema_version":2,
   "state":{
      "AWS":{
         "S3":{
            "Buckets":[
               {
                  "Metadata":{
                     "default":false,
                     "explicit":false,
                     "managed":true,
                     "parent":null,
                     "range":{
                        "endLine":0,
                        "filename":"arn:aws:s3:::examplebucket",
                        "fsKey":"",
                        "isLogicalSource":false,
                        "sourcePrefix":"remote",
                        "startLine":0
                     },
                     "ref":"arn:aws:s3:::examplebucket",
                     "unresolvable":false
                  },
                  "Name":{
                     "metadata":{
                        "default":false,
                        "explicit":false,
                        "managed":true,
                        "parent":null,
                        "range":{
                           "endLine":0,
                           "filename":"arn:aws:s3:::examplebucket",
                           "fsKey":"",
                           "isLogicalSource":false,
                           "sourcePrefix":"remote",
                           "startLine":0
                        },
                        "ref":"arn:aws:s3:::examplebucket",
                        "unresolvable":false
                     },
                     "value":"examplebucket"
                  },
                  "PublicAccessBlock":null,
                  "BucketPolicies":null,
                  "Encryption":{
                     "Metadata":{
                        "default":false,
                        "explicit":false,
                        "managed":true,
                        "parent":null,
                        "range":{
                           "endLine":0,
                           "filename":"arn:aws:s3:::examplebucket",
                           "fsKey":"",
                           "isLogicalSource":false,
                           "sourcePrefix":"remote",
                           "startLine":0
                        },
                        "ref":"arn:aws:s3:::examplebucket",
                        "unresolvable":false
                     },
                     "Enabled":{
                        "metadata":{
                           "default":true,
                           "explicit":false,
                           "managed":true,
                           "parent":null,
                           "range":{
                              "endLine":0,
                              "filename":"arn:aws:s3:::examplebucket",
                              "fsKey":"",
                              "isLogicalSource":false,
                              "sourcePrefix":"remote",
                              "startLine":0
                           },
                           "ref":"arn:aws:s3:::examplebucket",
                           "unresolvable":false
                        },
                        "value":false
                     },
                     "Algorithm":{
                        "metadata":{
                           "default":true,
                           "explicit":false,
                           "managed":true,
                           "parent":null,
                           "range":{
                              "endLine":0,
                              "filename":"arn:aws:s3:::examplebucket",
                              "fsKey":"",
                              "isLogicalSource":false,
                              "sourcePrefix":"remote",
                              "startLine":0
                           },
                           "ref":"arn:aws:s3:::examplebucket",
                           "unresolvable":false
                        },
                        "value":""
                     },
                     "KMSKeyId":{
                        "metadata":{
                           "default":true,
                           "explicit":false,
                           "managed":true,
                           "parent":null,
                           "range":{
                              "endLine":0,
                              "filename":"arn:aws:s3:::examplebucket",
                              "fsKey":"",
                              "isLogicalSource":false,
                              "sourcePrefix":"remote",
                              "startLine":0
                           },
                           "ref":"arn:aws:s3:::examplebucket",
                           "unresolvable":false
                        },
                        "value":""
                     }
                  },
                  "Versioning":{
                     "Metadata":{
                        "default":false,
                        "explicit":false,
                        "managed":true,
                        "parent":null,
                        "range":{
                           "endLine":0,
                           "filename":"arn:aws:s3:::examplebucket",
                           "fsKey":"",
                           "isLogicalSource":false,
                           "sourcePrefix":"remote",
                           "startLine":0
                        },
                        "ref":"arn:aws:s3:::examplebucket",
                        "unresolvable":false
                     },
                     "Enabled":{
                        "metadata":{
                           "default":true,
                           "explicit":false,
                           "managed":true,
                           "parent":null,
                           "range":{
                              "endLine":0,
                              "filename":"arn:aws:s3:::examplebucket",
                              "fsKey":"",
                              "isLogicalSource":false,
                              "sourcePrefix":"remote",
                              "startLine":0
                           },
                           "ref":"arn:aws:s3:::examplebucket",
                           "unresolvable":false
                        },
                        "value":false
                     },
                     "MFADelete":{
                        "metadata":{
                           "default":false,
                           "explicit":false,
                           "managed":true,
                           "parent":null,
                           "range":{
                              "endLine":0,
                              "filename":"arn:aws:s3:::examplebucket",
                              "fsKey":"",
                              "isLogicalSource":false,
                              "sourcePrefix":"remote",
                              "startLine":0
                           },
                           "ref":"arn:aws:s3:::examplebucket",
                           "unresolvable":false
                        },
                        "value":false
                     }
                  },
                  "Logging":{
                     "Metadata":{
                        "default":false,
                        "explicit":false,
                        "managed":true,
                        "parent":null,
                        "range":{
                           "endLine":0,
                           "filename":"arn:aws:s3:::examplebucket",
                           "fsKey":"",
                           "isLogicalSource":false,
                           "sourcePrefix":"remote",
                           "startLine":0
                        },
                        "ref":"arn:aws:s3:::examplebucket",
                        "unresolvable":false
                     },
                     "Enabled":{
                        "metadata":{
                           "default":true,
                           "explicit":false,
                           "managed":true,
                           "parent":null,
                           "range":{
                              "endLine":0,
                              "filename":"arn:aws:s3:::examplebucket",
                              "fsKey":"",
                              "isLogicalSource":false,
                              "sourcePrefix":"remote",
                              "startLine":0
                           },
                           "ref":"arn:aws:s3:::examplebucket",
                           "unresolvable":false
                        },
                        "value":false
                     },
                     "TargetBucket":{
                        "metadata":{
                           "default":true,
                           "explicit":false,
                           "managed":true,
                           "parent":null,
                           "range":{
                              "endLine":0,
                              "filename":"arn:aws:s3:::examplebucket",
                              "fsKey":"",
                              "isLogicalSource":false,
                              "sourcePrefix":"remote",
                              "startLine":0
                           },
                           "ref":"arn:aws:s3:::examplebucket",
                           "unresolvable":false
                        },
                        "value":""
                     }
                  },
                  "ACL":{
                     "metadata":{
                        "default":false,
                        "explicit":false,
                        "managed":true,
                        "parent":null,
                        "range":{
                           "endLine":0,
                           "filename":"arn:aws:s3:::examplebucket",
                           "fsKey":"",
                           "isLogicalSource":false,
                           "sourcePrefix":"remote",
                           "startLine":0
                        },
                        "ref":"arn:aws:s3:::examplebucket",
                        "unresolvable":false
                     },
                     "value":"private"
                  }
               }
            ]
         }
      }
   },
   "service_metadata":{
      "s3":{
         "name":"s3",
         "updated": "2022-10-04T14:08:36.659817426+01:00"
      }
   },
   "updated": "2022-10-04T14:08:36.659817426+01:00"
}`
