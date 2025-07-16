package daemon

const (
	testContextHost = "npipe:////./pipe/test_docker_engine"
	
	// Test socket paths for Windows systems
	testFlagHost    = "npipe:////./pipe/flag_docker"
	testEnvHost     = "npipe:////./pipe/env_docker"
)