package sarif

import "time"

// VersionControlDetails ...
type VersionControlDetails struct {
	AsOfTimeUTC   *time.Time        `json:"asOfTimeUtc,omitempty"`
	Branch        *string           `json:"branch,omitempty"`
	MappedTo      *ArtifactLocation `json:"mappedTo,omitempty"`
	RepositoryURI *string           `json:"repositoryUri"`
	RevisionID    *string           `json:"revisionId,omitempty"`
	RevisionTag   *string           `json:"revisionTag,omitempty"`
	PropertyBag
}

// NewVersionControlDetails creates a new VersionControlDetails and returns a pointer to it
func NewVersionControlDetails() *VersionControlDetails {
	return &VersionControlDetails{}
}

// WithAsOfTimeUTC sets the AsOfTimeUTC
func (versionControlDetails *VersionControlDetails) WithAsOfTimeUTC(asOfTimeUTC *time.Time) *VersionControlDetails {
	versionControlDetails.AsOfTimeUTC = asOfTimeUTC
	return versionControlDetails
}

// WithBranch sets the Branch
func (versionControlDetails *VersionControlDetails) WithBranch(branch string) *VersionControlDetails {
	versionControlDetails.Branch = &branch
	return versionControlDetails
}

// WithMappedTo sets the MappedTo
func (versionControlDetails *VersionControlDetails) WithMappedTo(mappedTo *ArtifactLocation) *VersionControlDetails {
	versionControlDetails.MappedTo = mappedTo
	return versionControlDetails
}

// WithRepositoryURI sets the RepositoryURI
func (versionControlDetails *VersionControlDetails) WithRepositoryURI(repositoryURI string) *VersionControlDetails {
	versionControlDetails.RepositoryURI = &repositoryURI
	return versionControlDetails
}

// WithRevisionID sets the RevisionID
func (versionControlDetails *VersionControlDetails) WithRevisionID(revisionID string) *VersionControlDetails {
	versionControlDetails.RevisionID = &revisionID
	return versionControlDetails
}

// WithRevisionTag sets the RevisionTag
func (versionControlDetails *VersionControlDetails) WithRevisionTag(revisionTag string) *VersionControlDetails {
	versionControlDetails.RevisionTag = &revisionTag
	return versionControlDetails
}
