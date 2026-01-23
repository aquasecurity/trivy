package binary

// Bridge to expose binary parser internals to tests in the binary_test package.

// ChooseMainVersion exports chooseMainVersion for testing.
func (p *Parser) ChooseMainVersion(version, ldflagsVersion string) string {
	return p.chooseMainVersion(version, ldflagsVersion)
}
