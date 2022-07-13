package flag

var (
	FetchBranchFlag = Flag{
		Name:       "branch",
		ConfigName: "repository.branch",
		Value:      "",
		Usage:      "pass the branch name to be scanned",
	}
	FetchCommitFlag = Flag{
		Name:       "commit",
		ConfigName: "repository.commit",
		Value:      "",
		Usage:      "pass the commit hash to be scanned",
	}
	FetchTagFlag = Flag{
		Name:       "tag",
		ConfigName: "repository.tag",
		Value:      "",
		Usage:      "pass the tag name to be scanned",
	}
)

type RepoFlagGroup struct {
	Branch *Flag
	Commit *Flag
	Tag    *Flag
}

type RepoOptions struct {
	RepoBranch string
	RepoCommit string
	RepoTag    string
}

func NewRepoFlagGroup() *RepoFlagGroup {
	return &RepoFlagGroup{
		Branch: &FetchBranchFlag,
		Commit: &FetchCommitFlag,
		Tag:    &FetchTagFlag,
	}
}

func (f *RepoFlagGroup) Name() string {
	return "Repository"
}

func (f *RepoFlagGroup) Flags() []*Flag {
	return []*Flag{f.Branch, f.Commit, f.Tag}
}

func (f *RepoFlagGroup) ToOptions() RepoOptions {
	return RepoOptions{
		RepoBranch: getString(f.Branch),
		RepoCommit: getString(f.Commit),
		RepoTag:    getString(f.Tag),
	}
}
