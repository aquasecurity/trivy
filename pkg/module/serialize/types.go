package serialize

import (
	"github.com/aquasecurity/trivy/pkg/types"
)

type StringSlice []string

type AnalysisResult struct {
	// TODO: support other fields as well
	// OS                   *types.OS
	// Repository           *types.Repository
	// PackageInfos         []types.PackageInfo
	// Applications         []types.Application
	// Secrets              []types.Secret
	// SystemInstalledFiles []string // A list of files installed by OS package manager

	// Currently it supports custom resources only
	CustomResources []CustomResource
}

type CustomResource struct {
	Type     string
	FilePath string
	Data     interface{}
}

type PostScanAction string

type PostScanSpec struct {
	// What action the module will do in post scanning.
	// value: INSERT, UPDATE and DELETE
	Action PostScanAction

	// IDs represent which vulnerability and misconfiguration ID will be updated or deleted in post scanning.
	// When the action is UPDATE, the matched result will be passed to the module.
	IDs []string
}

type Results []Result

type Result types.Result
