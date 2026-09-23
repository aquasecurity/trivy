package secret

// Bridge to expose secret scanner internals to tests in the secret_test package.

// Validate exports validate for testing.
func (r Rule) Validate() error {
	return r.validate()
}
