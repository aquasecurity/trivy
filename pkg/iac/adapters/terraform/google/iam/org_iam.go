package iam

import (
	"github.com/google/uuid"

	"github.com/aquasecurity/trivy/pkg/iac/providers/google/iam"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

// see https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_organization_iam

func (a *adapter) adaptOrganizationIAM() {
	a.adaptOrganizations()
	a.adaptOrganizationMembers()
	a.adaptOrganizationBindings()
}

func (a *adapter) adaptOrganizations() {
	for _, orgBlock := range a.modules.GetDatasByType("google_organization") {
		a.orgs[orgBlock.ID()] = &iam.Organization{
			Metadata: orgBlock.GetMetadata(),
		}
	}
}

func (a *adapter) adaptOrganizationMembers() {
	for _, iamBlock := range a.modules.GetResourcesByType("google_organization_iam_member") {

		member := a.adaptMember(iamBlock)

		if org := a.findOrganization(iamBlock); org != nil {
			org.Members = append(org.Members, member)
		} else {
			// we didn't find the org - add an unmanaged one
			a.orgs[uuid.NewString()] = &iam.Organization{
				Metadata: types.NewUnmanagedMetadata(),
				Members:  []iam.Member{member},
			}
		}
	}
}

func (a *adapter) adaptOrganizationBindings() {

	for _, iamBlock := range a.modules.GetResourcesByType("google_organization_iam_policy") {

		policyAttr := iamBlock.GetAttribute("policy_data")
		if policyAttr.IsNil() {
			continue
		}

		policyBlock, err := a.modules.GetReferencedBlock(policyAttr, iamBlock)
		if err != nil {
			continue
		}

		bindings := ParsePolicyBlock(policyBlock)

		if org := a.findOrganization(iamBlock); org != nil {
			org.Bindings = append(org.Bindings, bindings...)
		} else {
			// we didn't find the org - add an unmanaged one
			a.orgs[uuid.NewString()] = &iam.Organization{
				Metadata: types.NewUnmanagedMetadata(),
				Bindings: bindings,
			}
		}
	}

	for _, iamBlock := range a.modules.GetResourcesByType("google_organization_iam_binding") {

		binding := a.adaptBinding(iamBlock)

		if org := a.findOrganization(iamBlock); org != nil {
			org.Bindings = append(org.Bindings, binding)
		} else {
			// we didn't find the org - add an unmanaged one
			a.orgs[uuid.NewString()] = &iam.Organization{
				Metadata: types.NewUnmanagedMetadata(),
				Bindings: []iam.Binding{binding},
			}
		}
	}
}

func (a *adapter) findOrganization(iamBlock *terraform.Block) *iam.Organization {
	orgAttr := iamBlock.GetAttribute("organization")
	if orgAttr.IsNil() {
		orgAttr = iamBlock.GetAttribute("org_id")
	}
	refBlock, err := a.modules.GetReferencedBlock(orgAttr, iamBlock)
	if err != nil {
		return nil
	}

	if org, exists := a.orgs[refBlock.ID()]; exists {
		return org
	}

	return nil
}
