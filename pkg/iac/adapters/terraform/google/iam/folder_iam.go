package iam

import (
	"github.com/google/uuid"

	"github.com/aquasecurity/trivy/pkg/iac/providers/google/iam"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

// see https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_folder_iam

func (a *adapter) adaptFolderIAM() {
	a.adaptFolders()
	a.adaptFolderMembers()
	a.adaptFolderBindings()
}

const googleFolder = "google_folder"

func (a *adapter) adaptFolders() {
	for _, folderBlock := range a.modules.GetResourcesByType(googleFolder) {
		a.folders[folderBlock.ID()] = &iam.Folder{
			Metadata: folderBlock.GetMetadata(),
		}
	}
}

func (a *adapter) adaptFolderMembers() {
	for _, iamBlock := range a.modules.GetResourcesByType("google_folder_iam_member") {
		member := a.adaptMember(iamBlock)

		if folder := a.findFolder(iamBlock); folder != nil {
			folder.Members = append(folder.Members, member)
		} else {
			// we didn't find the folder - add an unmanaged one
			a.folders[uuid.NewString()] = &iam.Folder{
				Metadata: types.NewUnmanagedMetadata(),
				Members:  []iam.Member{member},
			}
		}
	}
}

func (a *adapter) adaptFolderBindings() {

	for _, iamBlock := range a.modules.GetResourcesByType("google_folder_iam_policy") {

		policyAttr := iamBlock.GetAttribute("policy_data")
		if policyAttr.IsNil() {
			continue
		}

		policyBlock, err := a.modules.GetReferencedBlock(policyAttr, iamBlock)
		if err != nil {
			continue
		}

		bindings := ParsePolicyBlock(policyBlock)

		if folder := a.findFolder(iamBlock); folder != nil {
			folder.Bindings = append(folder.Bindings, bindings...)
		} else {
			// we didn't find the folder - add an unmanaged one
			a.folders[uuid.NewString()] = &iam.Folder{
				Metadata: types.NewUnmanagedMetadata(),
				Bindings: bindings,
			}
		}
	}

	for _, iamBlock := range a.modules.GetResourcesByType("google_folder_iam_binding") {
		binding := a.adaptBinding(iamBlock)

		if folder := a.findFolder(iamBlock); folder != nil {
			folder.Bindings = append(folder.Bindings, binding)
		} else {
			// we didn't find the folder - add an unmanaged one
			a.folders[uuid.NewString()] = &iam.Folder{
				Metadata: types.NewUnmanagedMetadata(),
				Bindings: []iam.Binding{binding},
			}
		}
	}
}

func (a *adapter) findFolder(iamBlock *terraform.Block) *iam.Folder {
	folderAttr := iamBlock.GetAttribute("folder")
	refBlock, err := a.modules.GetReferencedBlock(folderAttr, iamBlock)
	if err != nil {
		return nil
	}

	if folder, exists := a.folders[refBlock.ID()]; exists {
		return folder
	}

	return nil
}
