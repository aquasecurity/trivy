package funcs

import (
	"bytes"
	"fmt"

	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/hashicorp/hcl/v2/hclwrite"
)

func Dump(blocks terraform.Blocks) {
	var buf bytes.Buffer

	f := hclwrite.NewFile()
	f.Body().AppendBlock(hclwrite.NewBlock("locals", nil))
	f.WriteTo(&buf)
	fmt.Println(buf.String())
}
