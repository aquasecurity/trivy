package types

import (
	"time"

	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
)

type FilePath string

type OS struct {
	Family string
	Name   string
}

type Layer struct {
	Digest string `json:",omitempty"`
	DiffID string `json:",omitempty"`
}

type Package struct {
	Name       string `json:",omitempty"`
	Version    string `json:",omitempty"`
	Release    string `json:",omitempty"`
	Epoch      int    `json:",omitempty"`
	Arch       string `json:",omitempty"`
	SrcName    string `json:",omitempty"`
	SrcVersion string `json:",omitempty"`
	SrcRelease string `json:",omitempty"`
	SrcEpoch   int    `json:",omitempty"`
	Layer      Layer  `json:",omitempty"`
}

type SrcPackage struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	BinaryNames []string `json:"binaryNames"`
}

type PackageInfo struct {
	FilePath string
	Packages []Package
}

type LibraryInfo struct {
	Library godeptypes.Library `json:",omitempty"`
	Layer   Layer              `json:",omitempty"`
}

type Application struct {
	Type      string
	FilePath  string
	Libraries []LibraryInfo
}

type ImageReference struct {
	Name     string // image name or tar file name
	ID       string
	LayerIDs []string
}

type ImageDetail struct {
	OS           *OS           `json:",omitempty"`
	Packages     []Package     `json:",omitempty"`
	Applications []Application `json:",omitempty"`

	// HistoryPackages are packages extracted from RUN instructions
	HistoryPackages []Package `json:",omitempty"`
}

// ImageInfo is stored in cache
type ImageInfo struct {
	SchemaVersion int
	Architecture  string
	Created       time.Time
	DockerVersion string
	OS            string

	// HistoryPackages are packages extracted from RUN instructions
	HistoryPackages []Package
}

// LayerInfo is stored in cache
type LayerInfo struct {
	SchemaVersion int
	Digest        string        `json:",omitempty"`
	DiffID        string        `json:",omitempty"`
	OS            *OS           `json:",omitempty"`
	PackageInfos  []PackageInfo `json:",omitempty"`
	Applications  []Application `json:",omitempty"`
	OpaqueDirs    []string      `json:",omitempty"`
	WhiteoutFiles []string      `json:",omitempty"`
}
