package pom

type Metadata struct {
	GroupId    string `xml:"groupId"`
	ArtifactId string `xml:"artifactId"`
	Versioning struct {
		SnapshotVersions []SnapshotVersion `xml:"snapshotVersions>snapshotVersion"`
	} `xml:"versioning"`
	Version string `xml:"version"`
}

type SnapshotVersion struct {
	Extension string `xml:"extension"`
	Value     string `xml:"value"`
}
