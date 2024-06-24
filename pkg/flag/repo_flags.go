package flag

var (
	FetchBranchFlag = Flag[string]{
		Name:       "branch",
		ConfigName: "repository.branch",
		Usage:      "pass the branch name to be scanned",
	}
	FetchCommitFlag = Flag[string]{
		Name:       "commit",
		ConfigName: "repository.commit",
		Usage:      "pass the commit hash to be scanned",
	}
	FetchTagFlag = Flag[string]{
		Name:       "tag",
		ConfigName: "repository.tag",
		Usage:      "pass the tag name to be scanned",
	}
)

type RepoFlagGroup struct {
	Branch *Flag[string]
	Commit *Flag[string]
	Tag    *Flag[string]
}

type RepoOptions struct {
	RepoBranch string
	RepoCommit string
	RepoTag    string
}

func NewRepoFlagGroup() *RepoFlagGroup {
	return &RepoFlagGroup{
		Branch: FetchBranchFlag.Clone(),
		Commit: FetchCommitFlag.Clone(),
		Tag:    FetchTagFlag.Clone(),
	}
}

func (f *RepoFlagGroup) Name() string {
	return "Repository"
}

func (f *RepoFlagGroup) Flags() []Flagger {
	return []Flagger{
		f.Branch,
		f.Commit,
		f.Tag,
	}
}

func (f *RepoFlagGroup) ToOptions() (RepoOptions, error) {
	if err := parseFlags(f); err != nil {
		return RepoOptions{}, err
	}

	return RepoOptions{
		RepoBranch: f.Branch.Value(),
		RepoCommit: f.Commit.Value(),
		RepoTag:    f.Tag.Value(),
	}, nil
}
