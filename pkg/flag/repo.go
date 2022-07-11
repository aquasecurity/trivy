package flag

var (
	FetchBranchFlag = Flag{
		Name:       "branch",
		ConfigName: "repo.branch",
		Value:      "",
		Usage:      "pass the branch name to be scanned",
	}
	FetchCommitFlag = Flag{
		Name:       "commit",
		ConfigName: "repo.commit",
		Value:      "",
		Usage:      "pass the commit hash to be scanned",
	}
	FetchTagFlag = Flag{
		Name:       "tag",
		ConfigName: "repo.tag",
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
	Branch string
	Commit string
	Tag    string
}

func NewRepoFlagGroup() *RepoFlagGroup {
	return &RepoFlagGroup{
		Branch: &FetchBranchFlag,
		Commit: &FetchCommitFlag,
		Tag:    &FetchTagFlag,
	}
}

func (f *RepoFlagGroup) Name() string {
	return "Repo"
}

func (f *RepoFlagGroup) Flags() []*Flag {
	return []*Flag{f.Branch, f.Commit, f.Tag}
}

func (f *RepoFlagGroup) ToOptions() RepoOptions {
	return RepoOptions{
		Branch: getString(f.Branch),
		Commit: getString(f.Commit),
		Tag:    getString(f.Tag),
	}
}
