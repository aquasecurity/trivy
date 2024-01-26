package openstack

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/openstack"

	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/trivy/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFields(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  openstack.OpenStack
	}{
		{
			name: "Plaintext password",
			terraform: `
			resource "openstack_compute_instance_v2" "my-instance" {
			  admin_pass      = "N0tSoS3cretP4ssw0rd"

			}`,
			expected: openstack.OpenStack{
				Compute: openstack.Compute{
					Instances: []openstack.Instance{
						{
							Metadata:      defsecTypes.NewTestMetadata(),
							AdminPassword: defsecTypes.String("N0tSoS3cretP4ssw0rd", defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
		},
		{
			name: "No plaintext password",
			terraform: `
			resource "openstack_compute_instance_v2" "my-instance" {
			}`,
			expected: openstack.OpenStack{
				Compute: openstack.Compute{
					Instances: []openstack.Instance{
						{
							Metadata:      defsecTypes.NewTestMetadata(),
							AdminPassword: defsecTypes.String("", defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
		},
		{
			name: "Firewall rule",
			terraform: `
			resource "openstack_fw_rule_v1" "rule_1" {
				action                 = "allow"
				protocol               = "tcp"
				destination_port       = "22"
				destination_ip_address = "10.10.10.1"
				source_ip_address      = "10.10.10.2"
				enabled                = "true"
			}`,
			expected: openstack.OpenStack{
				Compute: openstack.Compute{
					Firewall: openstack.Firewall{
						AllowRules: []openstack.FirewallRule{
							{
								Metadata:        defsecTypes.NewTestMetadata(),
								Enabled:         defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
								Destination:     defsecTypes.String("10.10.10.1", defsecTypes.NewTestMetadata()),
								Source:          defsecTypes.String("10.10.10.2", defsecTypes.NewTestMetadata()),
								DestinationPort: defsecTypes.String("22", defsecTypes.NewTestMetadata()),
								SourcePort:      defsecTypes.String("", defsecTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := Adapt(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "openstack_compute_instance_v2" "my-instance" {
		admin_pass      = "N0tSoS3cretP4ssw0rd"
	}

	resource "openstack_fw_rule_v1" "rule_1" {
		action                 = "allow"
		protocol               = "tcp"
		destination_port       = "22"
		destination_ip_address = "10.10.10.1"
		source_ip_address      = "10.10.10.2"
		enabled                = "true"
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Compute.Instances, 1)
	instance := adapted.Compute.Instances[0]

	require.Len(t, adapted.Compute.Firewall.AllowRules, 1)
	rule := adapted.Compute.Firewall.AllowRules[0]

	assert.Equal(t, 3, instance.AdminPassword.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, instance.AdminPassword.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 9, rule.DestinationPort.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 9, rule.DestinationPort.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 10, rule.Destination.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, rule.Destination.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 11, rule.Source.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 11, rule.Source.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 12, rule.Enabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 12, rule.Enabled.GetMetadata().Range().GetEndLine())
}
