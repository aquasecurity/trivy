package serialize

import (
	"github.com/aquasecurity/trivy/pkg/types"
)

// TinyGo doesn't support encoding/json, but github.com/mailru/easyjson for now.
// We need to generate JSON-related methods like MarshalEasyJSON implementing easyjson.Marshaler.
//
// $ make easyjson

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

type PostScanAction string

//easyjson:json
type PostScanSpec struct {
	// What action the module will do in post scanning.
	// value: INSERT, UPDATE and DELETE
	Action PostScanAction

	// IDs represent which vulnerability and misconfiguration ID will be updated or deleted in post scanning.
	// When the action is UPDATE, the matched result will be passed to the module.
	IDs []string
}

//easyjson:json
type Results []Result

//easyjson:json
type Result types.Result
