// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

package saver2v1

import (
	"fmt"
	"io"
	"sort"

	"github.com/spdx/tools-golang/spdx"
)

func renderFile2_1(f *spdx.File2_1, w io.Writer) error {
	if f.FileName != "" {
		fmt.Fprintf(w, "FileName: %s\n", f.FileName)
	}
	if f.FileSPDXIdentifier != "" {
		fmt.Fprintf(w, "SPDXID: %s\n", spdx.RenderElementID(f.FileSPDXIdentifier))
	}
	for _, s := range f.FileType {
		fmt.Fprintf(w, "FileType: %s\n", s)
	}
	if f.FileChecksumSHA1 != "" {
		fmt.Fprintf(w, "FileChecksum: SHA1: %s\n", f.FileChecksumSHA1)
	}
	if f.FileChecksumSHA256 != "" {
		fmt.Fprintf(w, "FileChecksum: SHA256: %s\n", f.FileChecksumSHA256)
	}
	if f.FileChecksumMD5 != "" {
		fmt.Fprintf(w, "FileChecksum: MD5: %s\n", f.FileChecksumMD5)
	}
	if f.LicenseConcluded != "" {
		fmt.Fprintf(w, "LicenseConcluded: %s\n", f.LicenseConcluded)
	}
	for _, s := range f.LicenseInfoInFile {
		fmt.Fprintf(w, "LicenseInfoInFile: %s\n", s)
	}
	if f.LicenseComments != "" {
		fmt.Fprintf(w, "LicenseComments: %s\n", textify(f.LicenseComments))
	}
	if f.FileCopyrightText != "" {
		fmt.Fprintf(w, "FileCopyrightText: %s\n", textify(f.FileCopyrightText))
	}
	for _, aop := range f.ArtifactOfProjects {
		fmt.Fprintf(w, "ArtifactOfProjectName: %s\n", aop.Name)
		if aop.HomePage != "" {
			fmt.Fprintf(w, "ArtifactOfProjectHomePage: %s\n", aop.HomePage)
		}
		if aop.URI != "" {
			fmt.Fprintf(w, "ArtifactOfProjectURI: %s\n", aop.URI)
		}
	}
	if f.FileComment != "" {
		fmt.Fprintf(w, "FileComment: %s\n", textify(f.FileComment))
	}
	if f.FileNotice != "" {
		fmt.Fprintf(w, "FileNotice: %s\n", textify(f.FileNotice))
	}
	for _, s := range f.FileContributor {
		fmt.Fprintf(w, "FileContributor: %s\n", s)
	}
	for _, s := range f.FileDependencies {
		fmt.Fprintf(w, "FileDependency: %s\n", s)
	}

	fmt.Fprintf(w, "\n")

	// also render any snippets for this file
	// get slice of Snippet identifiers so we can sort them
	snippetKeys := []string{}
	for k := range f.Snippets {
		snippetKeys = append(snippetKeys, string(k))
	}
	sort.Strings(snippetKeys)
	for _, sID := range snippetKeys {
		s := f.Snippets[spdx.ElementID(sID)]
		renderSnippet2_1(s, w)
	}

	return nil
}
