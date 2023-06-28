package commands

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/compliance/spec"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const expectedS3ScanResult = `{
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
        "Successes": 1,
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
          "ID": "AVD-AWS-0092",
          "AVDID": "AVD-AWS-0092",
          "Title": "S3 Buckets not publicly accessible through ACL.",
          "Description": "Buckets should not have ACLs that allow public access",
          "Resolution": "Don't use canned ACLs or switch to private acl",
          "Severity": "HIGH",
          "PrimaryURL": "https://avd.aquasec.com/misconfig/avd-aws-0092",
          "References": [
            "https://avd.aquasec.com/misconfig/avd-aws-0092"
          ],
          "Status": "PASS",
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
`
const expectedCustomScanResult = `{
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
        "Successes": 1,
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
          "ID": "AVD-AWS-0092",
          "AVDID": "AVD-AWS-0092",
          "Title": "S3 Buckets not publicly accessible through ACL.",
          "Description": "Buckets should not have ACLs that allow public access",
          "Resolution": "Don't use canned ACLs or switch to private acl",
          "Severity": "HIGH",
          "PrimaryURL": "https://avd.aquasec.com/misconfig/avd-aws-0092",
          "References": [
            "https://avd.aquasec.com/misconfig/avd-aws-0092"
          ],
          "Status": "PASS",
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
`
const expectedS3AndCloudTrailResult = `{
  "ArtifactName": "123456789",
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
      "Target": "arn:aws:cloudtrail:us-east-1:12345678:trail/management-events",
      "Class": "config",
      "Type": "cloud",
      "MisconfSummary": {
        "Successes": 1,
        "Failures": 3,
        "Exceptions": 0
      },
      "Misconfigurations": [
        {
          "Type": "AWS",
          "ID": "AVD-AWS-0014",
          "AVDID": "AVD-AWS-0014",
          "Title": "Cloudtrail should be enabled in all regions regardless of where your AWS resources are generally homed",
          "Description": "When creating Cloudtrail in the AWS Management Console the trail is configured by default to be multi-region, this isn't the case with the Terraform resource. Cloudtrail should cover the full AWS account to ensure you can track changes in regions you are not actively operting in.",
          "Resolution": "Enable Cloudtrail in all regions",
          "Severity": "MEDIUM",
          "PrimaryURL": "https://avd.aquasec.com/misconfig/avd-aws-0014",
          "References": [
            "https://avd.aquasec.com/misconfig/avd-aws-0014"
          ],
          "Status": "PASS",
          "Layer": {},
          "CauseMetadata": {
            "Resource": "arn:aws:cloudtrail:us-east-1:12345678:trail/management-events",
            "Provider": "aws",
            "Service": "cloudtrail",
            "Code": {
              "Lines": null
            }
          }
        },
        {
          "Type": "AWS",
          "ID": "AVD-AWS-0015",
          "AVDID": "AVD-AWS-0015",
          "Title": "Cloudtrail should be encrypted at rest to secure access to sensitive trail data",
          "Description": "Cloudtrail logs should be encrypted at rest to secure the sensitive data. Cloudtrail logs record all activity that occurs in the the account through API calls and would be one of the first places to look when reacting to a breach.",
          "Message": "Trail is not encrypted.",
          "Resolution": "Enable encryption at rest",
          "Severity": "HIGH",
          "PrimaryURL": "https://avd.aquasec.com/misconfig/avd-aws-0015",
          "References": [
            "https://avd.aquasec.com/misconfig/avd-aws-0015"
          ],
          "Status": "FAIL",
          "Layer": {},
          "CauseMetadata": {
            "Resource": "arn:aws:cloudtrail:us-east-1:12345678:trail/management-events",
            "Provider": "aws",
            "Service": "cloudtrail",
            "Code": {
              "Lines": null
            }
          }
        },
        {
          "Type": "AWS",
          "ID": "AVD-AWS-0016",
          "AVDID": "AVD-AWS-0016",
          "Title": "Cloudtrail log validation should be enabled to prevent tampering of log data",
          "Description": "Log validation should be activated on Cloudtrail logs to prevent the tampering of the underlying data in the S3 bucket. It is feasible that a rogue actor compromising an AWS account might want to modify the log data to remove trace of their actions.",
          "Message": "Trail does not have log validation enabled.",
          "Resolution": "Turn on log validation for Cloudtrail",
          "Severity": "HIGH",
          "PrimaryURL": "https://avd.aquasec.com/misconfig/avd-aws-0016",
          "References": [
            "https://avd.aquasec.com/misconfig/avd-aws-0016"
          ],
          "Status": "FAIL",
          "Layer": {},
          "CauseMetadata": {
            "Resource": "arn:aws:cloudtrail:us-east-1:12345678:trail/management-events",
            "Provider": "aws",
            "Service": "cloudtrail",
            "Code": {
              "Lines": null
            }
          }
        },
        {
          "Type": "AWS",
          "ID": "AVD-AWS-0162",
          "AVDID": "AVD-AWS-0162",
          "Title": "CloudTrail logs should be stored in S3 and also sent to CloudWatch Logs",
          "Description": "CloudTrail is a web service that records AWS API calls made in a given account. The recorded information includes the identity of the API caller, the time of the API call, the source IP address of the API caller, the request parameters, and the response elements returned by the AWS service.\n\nCloudTrail uses Amazon S3 for log file storage and delivery, so log files are stored durably. In addition to capturing CloudTrail logs in a specified Amazon S3 bucket for long-term analysis, you can perform real-time analysis by configuring CloudTrail to send logs to CloudWatch Logs.\n\nFor a trail that is enabled in all Regions in an account, CloudTrail sends log files from all those Regions to a CloudWatch Logs log group.",
          "Message": "Trail does not have CloudWatch logging configured",
          "Resolution": "Enable logging to CloudWatch",
          "Severity": "LOW",
          "PrimaryURL": "https://avd.aquasec.com/misconfig/avd-aws-0162",
          "References": [
            "https://avd.aquasec.com/misconfig/avd-aws-0162"
          ],
          "Status": "FAIL",
          "Layer": {},
          "CauseMetadata": {
            "Resource": "arn:aws:cloudtrail:us-east-1:12345678:trail/management-events",
            "Provider": "aws",
            "Service": "cloudtrail",
            "Code": {
              "Lines": null
            }
          }
        }
      ]
    },
    {
      "Target": "arn:aws:s3:::examplebucket",
      "Class": "config",
      "Type": "cloud",
      "MisconfSummary": {
        "Successes": 1,
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
          "ID": "AVD-AWS-0092",
          "AVDID": "AVD-AWS-0092",
          "Title": "S3 Buckets not publicly accessible through ACL.",
          "Description": "Buckets should not have ACLs that allow public access",
          "Resolution": "Don't use canned ACLs or switch to private acl",
          "Severity": "HIGH",
          "PrimaryURL": "https://avd.aquasec.com/misconfig/avd-aws-0092",
          "References": [
            "https://avd.aquasec.com/misconfig/avd-aws-0092"
          ],
          "Status": "PASS",
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
`

func Test_Run(t *testing.T) {

	regoDir := t.TempDir()

	tests := []struct {
		name         string
		options      flag.Options
		want         string
		expectErr    bool
		cacheContent string
		regoPolicy   string
		allServices  []string
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
			cacheContent: "testdata/s3onlycache.json",
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
				MisconfOptions: flag.MisconfOptions{IncludeNonFailures: true},
			},
			cacheContent: "testdata/s3onlycache.json",
			allServices:  []string{"s3"},
			want:         expectedS3ScanResult,
		},
		{
			name: "custom rego rule with passed results",
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
					SkipPolicyUpdate: true,
				},
				MisconfOptions: flag.MisconfOptions{IncludeNonFailures: true},
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
			cacheContent: "testdata/s3onlycache.json",
			allServices:  []string{"s3"},
			want:         expectedCustomScanResult,
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
				ReportOptions: flag.ReportOptions{
					Compliance: spec.ComplianceSpec{
						Spec: defsecTypes.Spec{
							// TODO: refactor defsec so that the parsed spec can be passed
							ID:          "@testdata/example-spec.yaml",
							Title:       "my-custom-spec",
							Description: "My fancy spec",
							Version:     "1.2",
							Controls: []defsecTypes.Control{
								{
									ID:          "1.1",
									Name:        "Unencrypted S3 bucket",
									Description: "S3 Buckets should be encrypted to protect the data that is stored within them if access is compromised.",
									Checks: []defsecTypes.SpecCheck{
										{ID: "AVD-AWS-0088"},
									},
									Severity: "HIGH",
								},
							},
						},
					},
					Format:       "table",
					ReportFormat: "summary",
				},
				RegoOptions: flag.RegoOptions{SkipPolicyUpdate: true},
			},
			cacheContent: "testdata/s3onlycache.json",
			allServices:  []string{"s3"},
			want: `
Summary Report for compliance: my-custom-spec
┌─────┬──────────┬───────────────────────┬────────┬────────┐
│ ID  │ Severity │     Control Name      │ Status │ Issues │
├─────┼──────────┼───────────────────────┼────────┼────────┤
│ 1.1 │   HIGH   │ Unencrypted S3 bucket │  FAIL  │   1    │
└─────┴──────────┴───────────────────────┴────────┴────────┘
`,
		},
		{
			name: "scan an unsupported service",
			options: flag.Options{
				RegoOptions: flag.RegoOptions{SkipPolicyUpdate: true},
				AWSOptions: flag.AWSOptions{
					Region:   "us-east-1",
					Account:  "123456789",
					Services: []string{"theultimateservice"},
				},
				CloudOptions: flag.CloudOptions{
					MaxCacheAge: time.Hour * 24 * 365 * 100,
				},
				MisconfOptions: flag.MisconfOptions{IncludeNonFailures: true},
			},
			cacheContent: "testdata/s3onlycache.json",
			expectErr:    true,
		},
		{
			name: "scan every service",
			options: flag.Options{
				RegoOptions: flag.RegoOptions{SkipPolicyUpdate: true},
				AWSOptions: flag.AWSOptions{
					Region:  "us-east-1",
					Account: "123456789",
				},
				CloudOptions: flag.CloudOptions{
					MaxCacheAge: time.Hour * 24 * 365 * 100,
				},
				MisconfOptions: flag.MisconfOptions{IncludeNonFailures: true},
			},
			cacheContent: "testdata/s3andcloudtrailcache.json",
			allServices:  []string{"s3", "cloudtrail"},
			want:         expectedS3AndCloudTrailResult,
		},
		{
			name: "skip certain services and include specific services",
			options: flag.Options{
				RegoOptions: flag.RegoOptions{SkipPolicyUpdate: true},
				AWSOptions: flag.AWSOptions{
					Region:       "us-east-1",
					Services:     []string{"s3"},
					SkipServices: []string{"cloudtrail"},
					Account:      "123456789",
				},
				CloudOptions: flag.CloudOptions{
					MaxCacheAge: time.Hour * 24 * 365 * 100,
				},
				MisconfOptions: flag.MisconfOptions{IncludeNonFailures: true},
			},
			cacheContent: "testdata/s3andcloudtrailcache.json",
			allServices:  []string{"s3", "cloudtrail"},
			// we skip cloudtrail but still expect results from it as it is cached
			want: expectedS3AndCloudTrailResult,
		},
		{
			name: "only skip certain services but scan the rest",
			options: flag.Options{
				RegoOptions: flag.RegoOptions{SkipPolicyUpdate: true},
				AWSOptions: flag.AWSOptions{
					Region:       "us-east-1",
					SkipServices: []string{"cloudtrail", "iam"},
					Account:      "12345678",
				},
				CloudOptions: flag.CloudOptions{
					MaxCacheAge: time.Hour * 24 * 365 * 100,
				},
				MisconfOptions: flag.MisconfOptions{IncludeNonFailures: true},
			},
			allServices:  []string{"s3", "cloudtrail", "iam"},
			cacheContent: "testdata/s3onlycache.json",
			want:         expectedS3ScanResult,
		},
		{
			name: "fail - service specified to both include and exclude",
			options: flag.Options{
				RegoOptions: flag.RegoOptions{SkipPolicyUpdate: true},
				AWSOptions: flag.AWSOptions{
					Region:       "us-east-1",
					Services:     []string{"s3"},
					SkipServices: []string{"s3"},
					Account:      "123456789",
				},
				CloudOptions: flag.CloudOptions{
					MaxCacheAge: time.Hour * 24 * 365 * 100,
				},
				MisconfOptions: flag.MisconfOptions{IncludeNonFailures: true},
			},
			cacheContent: "testdata/s3andcloudtrailcache.json",
			expectErr:    true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.allServices != nil {
				oldAllSupportedServicesFunc := allSupportedServicesFunc
				allSupportedServicesFunc = func() []string {
					return test.allServices
				}
				defer func() {
					allSupportedServicesFunc = oldAllSupportedServicesFunc
				}()
			}

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

				cacheData, err := os.ReadFile(test.cacheContent)
				require.NoError(t, err, test.name)

				require.NoError(t, os.WriteFile(cacheFile, []byte(cacheData), 0600))
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
