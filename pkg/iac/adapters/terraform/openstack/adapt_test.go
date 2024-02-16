package openstack

import (
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/providers/openstack"

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
							Metadata:      iacTypes.NewTestMetadata(),
							AdminPassword: iacTypes.String("N0tSoS3cretP4ssw0rd", iacTypes.NewTestMetadata()),
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
							Metadata:      iacTypes.NewTestMetadata(),
							AdminPassword: iacTypes.String("", iacTypes.NewTestMetadata()),
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
								Metadata:        iacTypes.NewTestMetadata(),
								Enabled:         iacTypes.Bool(true, iacTypes.NewTestMetadata()),
								Destination:     iacTypes.String("10.10.10.1", iacTypes.NewTestMetadata()),
								Source:          iacTypes.String("10.10.10.2", iacTypes.NewTestMetadata()),
								DestinationPort: iacTypes.String("22", iacTypes.NewTestMetadata()),
								SourcePort:      iacTypes.String("", iacTypes.NewTestMetadata()),
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
