package spaces

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/digitalocean/spaces"

	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/trivy/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_adaptBuckets(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []spaces.Bucket
	}{
		{
			name: "basic",
			terraform: `
			resource "digitalocean_spaces_bucket" "example" {
				name   = "public_space"
				region = "nyc3"
				acl    = "private"

				force_destroy = true

				versioning {
					enabled = true
				  }
			  }
			  
			  resource "digitalocean_spaces_bucket_object" "index" {
				bucket       = digitalocean_spaces_bucket.example.name
				acl          = "private"
			  }
`,
			expected: []spaces.Bucket{
				{
					Metadata: defsecTypes.NewTestMetadata(),
					Name:     defsecTypes.String("public_space", defsecTypes.NewTestMetadata()),
					Objects: []spaces.Object{
						{
							Metadata: defsecTypes.NewTestMetadata(),
							ACL:      defsecTypes.String("private", defsecTypes.NewTestMetadata()),
						},
					},
					ACL:          defsecTypes.String("private", defsecTypes.NewTestMetadata()),
					ForceDestroy: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
					Versioning: spaces.Versioning{
						Metadata: defsecTypes.NewTestMetadata(),
						Enabled:  defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
					},
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "digitalocean_spaces_bucket" "example" {
			  }
			
`,
			expected: []spaces.Bucket{
				{
					Metadata:     defsecTypes.NewTestMetadata(),
					Name:         defsecTypes.String("", defsecTypes.NewTestMetadata()),
					Objects:      nil,
					ACL:          defsecTypes.String("public-read", defsecTypes.NewTestMetadata()),
					ForceDestroy: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
					Versioning: spaces.Versioning{
						Metadata: defsecTypes.NewTestMetadata(),
						Enabled:  defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptBuckets(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "digitalocean_spaces_bucket" "example" {
		name   = "public_space"
		region = "nyc3"
		acl    = "private"

		force_destroy = true

		versioning {
			enabled = true
		  }
	  }
	  
	  resource "digitalocean_spaces_bucket_object" "index" {
		bucket       = digitalocean_spaces_bucket.example.name
		acl          = "public-read"
	  }
	`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Buckets, 1)
	bucket := adapted.Buckets[0]

	assert.Equal(t, 2, bucket.Metadata.Range().GetStartLine())
	assert.Equal(t, 12, bucket.Metadata.Range().GetEndLine())

	assert.Equal(t, 3, bucket.Name.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, bucket.Name.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 5, bucket.ACL.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 5, bucket.ACL.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 7, bucket.ForceDestroy.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 7, bucket.ForceDestroy.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 9, bucket.Versioning.Metadata.Range().GetStartLine())
	assert.Equal(t, 11, bucket.Versioning.Metadata.Range().GetEndLine())

	assert.Equal(t, 10, bucket.Versioning.Enabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, bucket.Versioning.Enabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 14, bucket.Objects[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 17, bucket.Objects[0].Metadata.Range().GetEndLine())

	assert.Equal(t, 16, bucket.Objects[0].ACL.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 16, bucket.Objects[0].ACL.GetMetadata().Range().GetEndLine())

}
