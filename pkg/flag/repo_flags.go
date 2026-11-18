package flag

import "github.com/aquasecurity/trivy/pkg/log"

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
	GitUsernameFlag = Flag[string]{
		Name:       "git-username",
		ConfigName: "repository.username",
		Usage:      "username for cloning a remote git repository over HTTPS",
	}
	GitPasswordFlag = Flag[string]{
		Name:       "git-password",
		ConfigName: "repository.password",
		Usage:      "password or access token for cloning a remote git repository over HTTPS. TRIVY_GIT_PASSWORD should be used for security reasons.",
	}
)

type RepoFlagGroup struct {
	Branch      *Flag[string]
	Commit      *Flag[string]
	Tag         *Flag[string]
	GitUsername *Flag[string]
	GitPassword *Flag[string]
}

type RepoOptions struct {
	RepoBranch   string
	RepoCommit   string
	RepoTag      string
	RepoUsername string
	RepoPassword string
}

func NewRepoFlagGroup() *RepoFlagGroup {
	return &RepoFlagGroup{
		Branch:      FetchBranchFlag.Clone(),
		Commit:      FetchCommitFlag.Clone(),
		Tag:         FetchTagFlag.Clone(),
		GitUsername: GitUsernameFlag.Clone(),
		GitPassword: GitPasswordFlag.Clone(),
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
		f.GitUsername,
		f.GitPassword,
	}
}

func (f *RepoFlagGroup) ToOptions(opts *Options) error {
	if f.GitUsername.Value() != "" && f.GitPassword.Value() == "" {
		log.Warn(`"--git-username" is ignored because "--git-password" is not set`)
	}
	opts.RepoOptions = RepoOptions{
		RepoBranch:   f.Branch.Value(),
		RepoCommit:   f.Commit.Value(),
		RepoTag:      f.Tag.Value(),
		RepoUsername: f.GitUsername.Value(),
		RepoPassword: f.GitPassword.Value(),
	}
	return nil
}
