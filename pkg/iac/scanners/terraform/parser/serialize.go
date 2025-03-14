package parser

import (
	"bytes"

	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/hashicorp/hcl/v2/hclwrite"
)

// Serialize makes a best effort to serialize the blocks back to HCL.
// This is not guaranteed to be the same as the original HCL, and should
// only be used for debugging.
func Serialize(blocks terraform.Blocks) string {
	var buf bytes.Buffer

	f := hclwrite.NewFile()
	for _, b := range blocks {
		f.Body().AppendBlock(hclwriteBlock(b))
	}

	_, _ = f.WriteTo(&buf)
	return buf.String()
}

func hclwriteBlock(block *terraform.Block) *hclwrite.Block {
	b := hclwrite.NewBlock(block.TypeLabel(), block.Labels())
	for _, attr := range block.Attributes() {
		// If the value is "null", it would be better to write the
		// underlying expression. That gets a bit complicated with
		// hclwrite, so just keep them as null for now.
		b.Body().SetAttributeValue(attr.Name(), attr.Value())
	}

	for _, subBlock := range block.AllBlocks() {
		b.Body().AppendBlock(hclwriteBlock(subBlock))
	}

	return b
}
