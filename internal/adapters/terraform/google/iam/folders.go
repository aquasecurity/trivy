package iam

import (
	"github.com/aquasecurity/defsec/pkg/providers/google/iam"
)

type parentedFolder struct {
	blockID       string
	parentBlockID string
	parentRef     string
	folder        iam.Folder
}

func (a *adapter) adaptFolders() {
	for _, folderBlock := range a.modules.GetResourcesByType("google_folder") {
		var folder parentedFolder
		parentAttr := folderBlock.GetAttribute("parent")
		if parentAttr.IsNil() {
			continue
		}

		folder.folder.Metadata = folderBlock.GetMetadata()
		folder.blockID = folderBlock.ID()
		if parentAttr.IsString() {
			folder.parentRef = parentAttr.Value().AsString()
		}

		if referencedBlock, err := a.modules.GetReferencedBlock(parentAttr, folderBlock); err == nil {
			if referencedBlock.TypeLabel() == "google_folder" {
				folder.parentBlockID = referencedBlock.ID()
			}
			if referencedBlock.TypeLabel() == "google_organization" {
				folder.parentBlockID = referencedBlock.ID()
				a.addOrg(folder.parentBlockID)
			}
		}

		a.folders = append(a.folders, folder)
	}
}
