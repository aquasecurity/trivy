# Integration Tests

This directory contains integration tests for Trivy. These tests verify Trivy's behavior by running actual commands and comparing the output against golden files.

## Running Tests

### Run integration tests
```bash
# Run standard integration tests (excludes VM, K8s, and module tests)
mage test:integration

# Run all types of integration tests separately
mage test:integration  # Standard integration tests
mage test:module       # Wasm module tests
mage test:vm           # VM integration tests
mage test:k8s          # Kubernetes integration tests
```

### Run specific test
```bash
GOEXPERIMENT=jsonv2 go test -tags=integration -run TestRepository ./integration -v
```

## Golden Files

Golden files store the expected output for integration tests. They are located in `integration/testdata/*.golden`.

### Updating Golden Files

When you make changes that affect test output, you need to update the golden files:

```bash
# Update golden files for standard integration tests
mage test:updateGolden

# Update golden files for Wasm module tests
mage test:updateModuleGolden

# Update golden files for VM integration tests
mage test:updateVMGolden

# Update specific golden files manually
GOEXPERIMENT=jsonv2 go test -tags=integration -run TestRepository ./integration -v -update
```

**Important**:
- Only tests that generate golden files as the canonical source support the `-update` flag
- Tests that reuse golden files from other tests will be **skipped** during updates
- Look for `override: nil` comment in test code to identify canonical source tests

### Golden File Management Strategy

#### 1. Canonical Source Tests (Can Update Golden Files)

These tests generate golden files and should have:
- `override: nil` comment in the code
- No `t.Skipf()` for the `-update` flag

Example:
```go
func TestRepository(t *testing.T) {
    // ...
    runTest(t, osArgs, tt.golden, format, runOptions{
        fakeUUID: "3ff14136-e09f-4df9-80ea-%012d",
        override: nil, // Do not use overrides - golden files are generated from this test as the canonical source
    })
}
```

#### 2. Consumer Tests (Cannot Update Golden Files)

These tests reuse golden files from canonical source tests and should have:
- `if *update { t.Skipf(...) }` at the beginning of the test function
- `override` functions to adjust for differences (e.g., different artifact names, paths)
- Simplified comment: `Golden files are shared with TestXXX.`

Example:
```go
// TestClientServer tests the client-server mode of Trivy.
//
// Golden files are shared with TestTar or TestRepository.
func TestClientServer(t *testing.T) {
    if *update {
        t.Skipf("Skipping TestClientServer when -update flag is set. Golden files should be updated via TestTar or TestRepository.")
    }

    // ...
    runTest(t, osArgs, tt.golden, types.FormatJSON, runOptions{
        override: overrideFuncs(overrideUID, func(_ *testing.T, want, _ *types.Report) {
            want.ArtifactName = "https://github.com/knqyf263/trivy-ci-test"
        }),
        fakeUUID: "3ff14136-e09f-4df9-80ea-%012d",
    })
}
```

### Why Only One Test Updates Each Golden File

**Critical constraint**: Each golden file must be updated by exactly one test function.

If multiple tests update the same golden file, they may introduce subtle differences in the output. This causes the golden file to change every time tests are run, depending on which test executed last. This makes the golden files unstable and defeats their purpose.

**Solution**: Designate one test as the "canonical source" for each golden file. Other tests that want to verify equivalent results share the golden file in read-only mode (with `t.Skipf()` during updates).

### When to Share Golden Files

Share golden files between tests when you want to verify that different commands, flags, or configurations produce equivalent results with the **same output format**:

**Good reasons to share:**
- Testing different input methods that produce the same JSON output (local path vs remote URL vs client-server mode)
- Testing different ways to specify the same configuration (environment variables vs CLI flags vs config files)
- Testing different image sources that produce the same scan results (tar archive vs Docker Engine vs registry)

**Use override functions to handle:**
- Different artifact names or paths
- Different metadata (e.g., image config, repo info)
- Different ReportIDs or UUIDs
- Minor formatting differences in paths (e.g., Windows vs Unix separators)

**Example**: TestTar generates golden files for image scanning, and these are reused by:
- TestDockerEngine (different image source: Docker Engine API)
- TestRegistry (different image source: container registry)
- TestClientServer (different execution mode: client-server)

All of these produce the same JSON format with the same vulnerability data, but with different artifact names and metadata.

### Validation

The test framework automatically validates that:
- Tests updating golden files (`*update == true`) cannot use override functions
- This prevents accidentally updating golden files with modified data

If you try to update a golden file with an override function, the test will fail with:
```
invalid test configuration: cannot use override functions when update=true
```

## Test Organization

### Test Files

Tests are organized by functionality:

- `standalone_tar_test.go` - Container image scanning from tar archives
- `repo_test.go` - Repository and filesystem scanning
- `sbom_test.go` - SBOM scanning and generation
- `client_server_test.go` - Client-server mode
- `docker_engine_test.go` - Docker Engine API integration
- `registry_test.go` - Container registry integration
- `config_test.go` - Configuration handling (CLI flags, env vars, config files)
- `vm_test.go` - Virtual machine image scanning
- `module_test.go` - Wasm module integration

### Test Data Directory Structure

```
integration/testdata/
├── *.golden              # Golden files (expected test outputs)
└── fixtures/             # Test input files
    ├── images/           # Container images (auto-downloaded)
    ├── vm-images/        # VM images (auto-downloaded)
    ├── repo/             # Repository and filesystem test data
    ├── sbom/             # SBOM test files
    └── ...
```

**Important**: `testdata/fixtures/images/` and `testdata/fixtures/vm-images/` are automatically downloaded by mage commands:
- `mage test:integration` downloads container images
- `mage test:vm` downloads VM images

If you run tests directly with `go test` without using mage commands, these fixtures will not be present and tests will fail. Use mage commands to ensure fixtures are properly set up.

## Troubleshooting

### Golden file shared between tests shows unexpected differences

1. Identify which test is the canonical source (has `override: nil`)
2. Update golden file from the canonical source test only
3. Adjust override functions in consumer tests to handle differences

### Cannot update golden files for a specific test

1. Check if the test has `if *update { t.Skipf(...) }` - this prevents updates
2. Find the canonical source test mentioned in the skip message
3. Update golden files from the canonical source test instead

## Best Practices

1. **One golden file, one updater**: Each golden file should be updated by exactly one test function
2. **Use `mage test:updateGolden`**: This automatically updates all golden files from canonical source tests
3. **Minimize golden file duplication**: Share golden files when testing equivalent functionality
4. **Keep override functions simple**: Complex overrides may indicate tests shouldn't share golden files
5. **Add `override: nil` comments**: Clearly mark canonical source tests in the code
