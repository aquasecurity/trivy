package rdb

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
)

func TestLines(t *testing.T) {
	src := `
resource "nifcloud_db_instance" "example" {
	publicly_accessible     = false
	engine                  = "MySQL"
  	engine_version          = "5.7.15"
	backup_retention_period = 2
	network_id              = "example-network"
}

resource "nifcloud_db_security_group" "example" {
	description = "memo"

	rule {
	  cidr_ip = "0.0.0.0/0"
	}
}
`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.DBInstances, 1)
	require.Len(t, adapted.DBSecurityGroups, 1)

	dbInstance := adapted.DBInstances[0]
	dbSecurityGroup := adapted.DBSecurityGroups[0]

	assert.Equal(t, 3, dbInstance.PublicAccess.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, dbInstance.PublicAccess.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 4, dbInstance.Engine.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, dbInstance.Engine.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 5, dbInstance.EngineVersion.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 5, dbInstance.EngineVersion.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 6, dbInstance.BackupRetentionPeriodDays.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 6, dbInstance.BackupRetentionPeriodDays.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 7, dbInstance.NetworkID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 7, dbInstance.NetworkID.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 11, dbSecurityGroup.Description.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 11, dbSecurityGroup.Description.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 14, dbSecurityGroup.CIDRs[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 14, dbSecurityGroup.CIDRs[0].GetMetadata().Range().GetEndLine())
}
