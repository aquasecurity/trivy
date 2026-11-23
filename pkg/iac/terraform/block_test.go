package terraform

import (
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestBlock(t *testing.T, src string) *Block {
	t.Helper()
	file, diags := hclsyntax.ParseConfig([]byte(src), "main.tf", hcl.Pos{Line: 1, Column: 1})
	require.False(t, diags.HasErrors(), diags.Error())
	body, ok := file.Body.(*hclsyntax.Body)
	require.True(t, ok)
	require.Len(t, body.Blocks, 1)
	return NewBlock(body.Blocks[0].AsHCLBlock(), nil, nil, nil, "", nil)
}

func TestBlock_GetNestedAttribute(t *testing.T) {
	block := newTestBlock(t, `resource "aws_s3_bucket" "test" {
  rule {
    apply {
      algorithm = "AES256"
    }
    empty {}
  }
}
`)

	tests := []struct {
		name       string
		path       string
		wantValue  string
		wantParent int
	}{
		{
			name:       "attribute exists",
			path:       "rule.apply.algorithm",
			wantValue:  "AES256",
			wantParent: 3,
		},
		{
			name:       "attribute is missing",
			path:       "rule.empty.algorithm",
			wantParent: 6,
		},
		{
			name:       "block is missing",
			path:       "rule.missing.algorithm",
			wantParent: 2,
		},
		{
			name:       "first block is missing",
			path:       "missing.apply.algorithm",
			wantParent: 1,
		},
		{
			name:       "attribute of the block itself is missing",
			path:       "algorithm",
			wantParent: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attr, parent := block.GetNestedAttribute(tt.path)
			if tt.wantValue == "" {
				assert.Nil(t, attr)
			} else {
				require.NotNil(t, attr)
				assert.Equal(t, tt.wantValue, attr.Value().AsString())
			}
			require.NotNil(t, parent)
			assert.Equal(t, tt.wantParent, parent.GetMetadata().Range().GetStartLine())
		})
	}
}
