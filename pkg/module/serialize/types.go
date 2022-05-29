package serialize

import (
	"github.com/aquasecurity/trivy/pkg/types"
)

//easyjson:json
type StringSlice []string

//easyjson:json
type AnalysisResult struct {
	// TODO: support other fields as well
	//OS                   *types.OS
	//Repository           *types.Repository
	//PackageInfos         []types.PackageInfo
	//Applications         []types.Application
	//Secrets              []types.Secret
	//SystemInstalledFiles []string // A list of files installed by OS package manager

	// Currently it supports custom resources only
	CustomResources []CustomResource
}

type CustomResource struct {
	Type     string
	FilePath string
	Data     interface{}
}

//easyjson:json
type Results []Result

//easyjson:json
type Result types.Result
