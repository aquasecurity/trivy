package commands

import (
	"bytes"
	"context"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func Test_Run(t *testing.T) {
	tests := []struct {
		name         string
		options      flag.Options
		want         string
		expectErr    string
		cacheContent string
	}{
		{
			name:      "fail without region",
			options:   flag.Options{},
			want:      "",
			expectErr: "failed to discover AWS caller identity: operation error STS: GetCallerIdentity, failed to resolve service endpoint, an AWS region is required, but was not found",
		},
		{
			name: "fail without creds",
			options: flag.Options{
				AWSOptions: flag.AWSOptions{
					Region: "us-east-1",
				},
			},
			want:      "",
			expectErr: "failed to discover AWS caller identity: operation error STS: GetCallerIdentity, context deadline exceeded",
		},
		{
			name: "try to call aws if cache is expired",
			options: flag.Options{
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
			expectErr:    "aws scan error: failed to discover AWS caller identity: operation error STS: GetCallerIdentity, context deadline exceeded",
		},
		{
			name: "succeed with cached infra",
			options: flag.Options{
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
      "Type": "cloud"
    }
  ]
}
`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			buffer := new(bytes.Buffer)
			test.options.Output = buffer
			test.options.Debug = true
			test.options.GlobalOptions.Timeout = time.Minute
			test.options.Format = "json"

			if test.cacheContent != "" {
				cacheRoot := t.TempDir()
				test.options.CacheDir = cacheRoot
				cacheFile := filepath.Join(cacheRoot, "cloud", "aws", test.options.Account, test.options.Region, "data.json")
				require.NoError(t, os.MkdirAll(filepath.Dir(cacheFile), 0700))
				require.NoError(t, os.WriteFile(cacheFile, []byte(test.cacheContent), 0600))
			}

			err := Run(context.Background(), test.options)
			if test.expectErr != "" {
				assert.EqualError(t, err, test.expectErr)
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
