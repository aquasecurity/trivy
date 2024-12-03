package parser

import (
	"context"
	"path"
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
)

func TestFindRootModules(t *testing.T) {
	tests := []struct {
		name     string
		files    map[string]string
		expected []string
	}{
		{
			name: "multiple root modules",
			files: map[string]string{
				"code/main.tf": `
module "this" {
  count = 0
  source = "./modules/s3"
}`,
				"code/modules/s3/main.tf": `
module "this" {
  source = "./modules/logging"
}
resource "aws_s3_bucket" "this" {
  bucket = "test"
}`,
				"code/modules/s3/modules/logging/main.tf": `
resource "aws_s3_bucket" "this" {
  bucket = "test1"
}`,
				"code/example/main.tf": `
module "this" {
  source = "../modules/s3"
}`,
			},
			expected: []string{
				"code",
				"code/example",
			},
		},
		{
			name: "without module block",
			files: map[string]string{
				"code/infra1/main.tf": `resource "test" "this" {}`,
				"code/infra2/main.tf": `resource "test" "this" {}`,
			},
			expected: []string{
				"code/infra1",
				"code/infra2",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := testutil.CreateFS(t, tt.files)
			parser := New(fsys, "", OptionStopOnHCLError(true))

			modules := lo.Map(lo.Keys(tt.files), func(p string, _ int) string {
				return path.Dir(p)
			})

			got, err := parser.FindRootModules(context.TODO(), modules)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, got)
		})
	}
}
