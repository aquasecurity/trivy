package pom

type Metadata struct {
	GroupId    string     `xml:"groupId"`
	ArtifactId string     `xml:"artifactId"`
	Versioning Versioning `xml:"versioning"`
	Version    string     `xml:"version"`
}

type Versioning struct {
	SnapshotVersions []SnapshotVersion `xml:"snapshotVersions>snapshotVersion"`
}

type SnapshotVersion struct {
	Extension string `xml:"extension"`
	Value     string `xml:"value"`
}
