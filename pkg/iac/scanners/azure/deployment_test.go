package azure

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/iac/types"
)

const (
	accountType   = "Microsoft.Storage/storageAccounts"
	containerType = "Microsoft.Storage/storageAccounts/blobServices/containers"
)

func TestDeployment_GetChildResources(t *testing.T) {
	tests := []struct {
		name      string
		account   Resource
		topLevel  []Resource
		childType string
		expected  []string
	}{
		{
			name: "short types nested under the blob service",
			account: testResource(accountType, "sa",
				testResource("blobServices", "default",
					testResource("containers", "one"),
					testResource("queues", "other"),
				),
			),
			childType: "blobServices/containers",
			expected:  []string{"one"},
		},
		{
			name: "multi-segment and full types nested in the account",
			account: testResource(accountType, "sa",
				testResource("blobServices/containers", "default/one"),
				testResource(containerType, "default/two"),
			),
			childType: "blobServices/containers",
			expected:  []string{"default/one", "default/two"},
		},
		{
			name: "full type nested under the blob service",
			account: testResource(accountType, "sa",
				testResource("blobServices", "default",
					testResource(containerType, "one"),
				),
			),
			childType: containerType,
			expected:  []string{"one"},
		},
		{
			name: "types match case-insensitively",
			account: testResource(accountType, "sa",
				testResource("BlobServices", "default",
					testResource("Containers", "one"),
				),
			),
			childType: "blobservices/containers",
			expected:  []string{"one"},
		},
		{
			name:    "top-level children whose name starts with the parent name",
			account: testResource(accountType, "sa"),
			topLevel: []Resource{
				testResource(containerType, "sa/default/one"),
				testResource("microsoft.storage/storageaccounts/blobservices/containers", "SA/default/two"),
				testResource(containerType, "sab/default/three"),
				testResource(containerType, "sa"),
				testResource(accountType+"/queueServices/queues", "sa/default/four"),
			},
			childType: "blobServices/containers",
			expected:  []string{"sa/default/one", "SA/default/two"},
		},
		{
			name:    "children nested in a top-level child",
			account: testResource(accountType, "sa"),
			topLevel: []Resource{
				testResource(accountType+"/blobServices", "sa/default",
					testResource("containers", "one"),
				),
				testResource(accountType+"/blobServices", "other/default",
					testResource("containers", "two"),
				),
			},
			childType: "blobServices/containers",
			expected:  []string{"one"},
		},
		{
			name:      "top-level child with an expression name is skipped",
			account:   testResource(accountType, "sa"),
			topLevel:  []Resource{testExprResource(containerType, "format('{0}/default/one', 'sa')")},
			childType: "blobServices/containers",
		},
		{
			name:      "top-level child is skipped when the parent name is an expression",
			account:   testExprResource(accountType, "parameters('name')"),
			topLevel:  []Resource{testResource(containerType, "sa/default/one")},
			childType: "blobServices/containers",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deployment := Deployment{Resources: append([]Resource{tt.account}, tt.topLevel...)}
			assert.Equal(t, tt.expected, resourceNames(deployment.GetChildResources(tt.account, tt.childType)))
		})
	}
}

func TestDeployment_GetOrphanResources(t *testing.T) {
	deployment := Deployment{Resources: []Resource{
		testResource(accountType, "sa",
			testResource("blobServices", "default",
				testResource("containers", "nested"),
			),
		),
		testExprResource(accountType, "parameters('name')"),
		testResource(containerType, "sa/default/owned"),
		testResource(containerType, "other/default/unknown-parent"),
		testExprResource(containerType, "format('{0}/default/expr', 'sa')"),
		testResource(accountType+"/queueServices/queues", "other/default/queue"),
		testResource(accountType+"/blobServices", "sa/default",
			testResource("containers", "owned-nested"),
		),
		testExprResource(accountType+"/blobServices", "format('{0}/default', 'sa')",
			testResource("containers", "expr-parent-nested"),
		),
	}}

	assert.Equal(t,
		[]string{"other/default/unknown-parent", "format('{0}/default/expr', 'sa')", "expr-parent-nested"},
		resourceNames(deployment.GetOrphanResources(accountType, "blobServices/containers")),
	)
}

func testResource(typ, name string, children ...Resource) Resource {
	return Resource{
		Type:      NewValue(typ, types.NewTestMetadata()),
		Name:      NewValue(name, types.NewTestMetadata()),
		Resources: children,
	}
}

func testExprResource(typ, name string, children ...Resource) Resource {
	return Resource{
		Type:      NewValue(typ, types.NewTestMetadata()),
		Name:      NewExprValue(name, types.NewTestMetadata()),
		Resources: children,
	}
}

func resourceNames(resources []Resource) []string {
	var names []string
	for _, resource := range resources {
		if resource.Name.Kind == KindExpression {
			names = append(names, resource.Name.rLit.(string))
			continue
		}
		names = append(names, resource.Name.AsString())
	}
	return names
}
