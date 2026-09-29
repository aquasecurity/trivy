package s3

import (
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/s3"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/parser"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func TestAdapt(t *testing.T) {
	fsys := fstest.MapFS{
		"playbook.yaml": {
			Data: []byte(`---
- name: Update web servers
  hosts: localhost

  tasks:
  - name: Ensure apache is at the latest version
    s3_bucket:
      name: mys3bucket
      encryption: "aws:kms"
      encryption_key_id: "arn:aws:kms:us-east-1:1234/5678example"
      public_access:
        block_public_acls: true
        block_public_policy: true
        ignore_public_acls: true
        restrict_public_buckets: true
`),
		},
	}

	project, err := parser.New(fsys, ".").Parse()
	require.NoError(t, err)

	tasks := project.ListTasks()

	got := Adapt(tasks)
	want := s3.S3{
		Buckets: []s3.Bucket{
			{
				Name: iacTypes.StringTest("mys3bucket"),
				Encryption: s3.Encryption{
					Algorithm: iacTypes.StringTest("aws:kms"),
					KMSKeyId:  iacTypes.StringTest("arn:aws:kms:us-east-1:1234/5678example"),
				},
				PublicAccessBlock: &s3.PublicAccessBlock{
					BlockPublicACLs:       iacTypes.BoolTest(true),
					BlockPublicPolicy:     iacTypes.BoolTest(true),
					IgnorePublicACLs:      iacTypes.BoolTest(true),
					RestrictPublicBuckets: iacTypes.BoolTest(true),
				},
				Website: &s3.Website{},
			},
		},
	}

	testutil.AssertDefsecEqual(t, want, got)
}
