package sslcertificate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
)

func TestLines(t *testing.T) {
	src := `
resource "nifcloud_ssl_certificate" "example" {
	certificate  = "generated-certificate"
}
`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.ServerCertificates, 1)

	serverCertificate := adapted.ServerCertificates[0]

	assert.Equal(t, 3, serverCertificate.Expiration.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, serverCertificate.Expiration.GetMetadata().Range().GetEndLine())
}
