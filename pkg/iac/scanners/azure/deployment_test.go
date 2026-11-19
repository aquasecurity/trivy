package azure

import (
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func newTestResource(typ, name string, children ...Resource) Resource {
	meta := types.NewTestMetadata()
	return Resource{
		Metadata:  meta,
		Type:      NewValue(typ, meta),
		Name:      NewValue(name, meta),
		Resources: children,
	}
}

func TestDeployment_GetResourcesByType(t *testing.T) {
	deployment := Deployment{
		Resources: []Resource{
			newTestResource("Microsoft.Storage/storageAccounts", "exact"),
			newTestResource("Microsoft.Storage/StorageAccounts", "mixed"),
			newTestResource("microsoft.storage/storageaccounts", "lower"),
			newTestResource("Microsoft.Network/networkSecurityGroups", "other"),
		},
	}

	resources := deployment.GetResourcesByType("Microsoft.Storage/storageAccounts")
	names := lo.Map(resources, func(r Resource, _ int) string { return r.Name.AsString() })
	assert.ElementsMatch(t, []string{"exact", "mixed", "lower"}, names)
}

func TestResource_GetResourcesByType(t *testing.T) {
	parent := newTestResource("Microsoft.Sql/servers", "server",
		newTestResource("Microsoft.Sql/servers/firewallRules", "exact"),
		newTestResource("Microsoft.Sql/Servers/FirewallRules", "mixed"),
		newTestResource("Microsoft.Sql/servers/databases", "other"),
	)

	resources := parent.GetResourcesByType("Microsoft.Sql/servers/firewallRules")
	names := lo.Map(resources, func(r Resource, _ int) string { return r.Name.AsString() })
	assert.ElementsMatch(t, []string{"exact", "mixed"}, names)
}
