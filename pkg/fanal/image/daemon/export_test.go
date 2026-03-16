package daemon

// Bridge to expose daemon internals to tests in the daemon_test package.

// ResolveDockerHost exports resolveDockerHost for testing.
var ResolveDockerHost = resolveDockerHost
