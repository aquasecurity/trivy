package dns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
)

func TestLines(t *testing.T) {
	src := `
resource "nifcloud_dns_record" "example" {
	type    = "A"
	record  = "example-record"
}
`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Records, 1)

	record := adapted.Records[0]

	assert.Equal(t, 3, record.Type.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, record.Type.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 4, record.Record.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, record.Record.GetMetadata().Range().GetEndLine())
}
