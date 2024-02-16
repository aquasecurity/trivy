package github

type GitHub struct {
	Repositories       []Repository
	EnvironmentSecrets []EnvironmentSecret
	BranchProtections  []BranchProtection
}
