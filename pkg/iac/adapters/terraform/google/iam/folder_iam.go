package iam

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/google/iam"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

// see https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_folder_iam

func (a *adapter) adaptFolderIAM() {
	a.adaptFolderMembers()
	a.adaptFolderBindings()
}

func (a *adapter) adaptFolderMembers() {
	for _, iamBlock := range a.modules.GetResourcesByType("google_folder_iam_member") {
		member := a.adaptMember(iamBlock)
		folderAttr := iamBlock.GetAttribute("folder")
		if refBlock, err := a.modules.GetReferencedBlock(folderAttr, iamBlock); err == nil {
			if refBlock.TypeLabel() == GoogleFolder {
				var foundFolder bool
				for i, folder := range a.folders {
					if folder.blockID == refBlock.ID() {
						folder.folder.Members = append(folder.folder.Members, member)
						a.folders[i] = folder
						foundFolder = true
						break
					}
				}
				if foundFolder {
					continue
				}
			}
		}

		// we didn't find the folder - add an unmanaged one
		a.folders = append(a.folders, parentedFolder{
			folder: iam.Folder{
				Metadata: types.NewUnmanagedMetadata(),
				Members:  []iam.Member{member},
			},
		})
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
		folderAttr := iamBlock.GetAttribute("folder")

		if refBlock, err := a.modules.GetReferencedBlock(folderAttr, iamBlock); err == nil {
			if refBlock.TypeLabel() == GoogleFolder {
				var foundFolder bool
				for i, folder := range a.folders {
					if folder.blockID == refBlock.ID() {
						folder.folder.Bindings = append(folder.folder.Bindings, bindings...)
						a.folders[i] = folder
						foundFolder = true
						break
					}
				}
				if foundFolder {
					continue
				}

			}
		}

		// we didn't find the project - add an unmanaged one
		a.folders = append(a.folders, parentedFolder{
			folder: iam.Folder{
				Metadata: types.NewUnmanagedMetadata(),
				Bindings: bindings,
			},
		})
	}

	for _, iamBlock := range a.modules.GetResourcesByType("google_folder_iam_binding") {
		binding := a.adaptBinding(iamBlock)
		folderAttr := iamBlock.GetAttribute("folder")
		if refBlock, err := a.modules.GetReferencedBlock(folderAttr, iamBlock); err == nil {
			if refBlock.TypeLabel() == GoogleFolder {
				var foundFolder bool
				for i, folder := range a.folders {
					if folder.blockID == refBlock.ID() {
						folder.folder.Bindings = append(folder.folder.Bindings, binding)
						a.folders[i] = folder
						foundFolder = true
						break
					}
				}
				if foundFolder {
					continue
				}

			}
		}

		// we didn't find the folder - add an unmanaged one
		a.folders = append(a.folders, parentedFolder{
			folder: iam.Folder{
				Metadata: types.NewUnmanagedMetadata(),
				Bindings: []iam.Binding{binding},
			},
		})
	}
}
