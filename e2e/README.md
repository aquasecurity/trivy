# End-to-End (E2E) Tests

## Testing Philosophy

The E2E tests in this directory are designed to test Trivy's functionality in realistic environments with **external dependencies and network connectivity**. These tests complement unit tests and integration tests by focusing on scenarios that require real external resources.

### What E2E Tests Should Cover

E2E tests should focus on functionality that involves:
- **External network connections** (downloading container images, vulnerability databases)
- **External service dependencies** (Docker daemon, registry access, proxy servers)
- **Real-world scenarios** that cannot be easily mocked or simulated
- **Cross-component integration** involving external systems

### What E2E Tests Should NOT Cover

E2E tests should **avoid** detailed assertions and comprehensive validation:
- **Detailed JSON output validation** - this should be covered by integration tests
- **Comprehensive vulnerability detection** - this should be covered by unit tests
- **Complex result comparison** - basic functionality verification is sufficient
- **Edge cases and error conditions** - these should be covered by unit tests

### Testing Approach

- **Minimal assertions**: Focus on basic functionality rather than detailed output validation
- **External dependencies**: Use real registries, databases, and services where practical
- **Environment isolation**: Each test should use isolated cache and working directories
- **Golden files**: Use -update flag for maintainable output comparison
- **Conditional execution**: Tests should validate required dependencies during setup

### Dependencies

- **Docker**: Required for local image scanning tests
- **Internet access**: Required for downloading images and databases

### Test Execution

The E2E tests build and execute trivy in isolated temporary directories. When you run `mage test:e2e`, it automatically:
1. Builds trivy in a test-specific temporary directory (via `t.TempDir()`)
2. Adds the temporary directory to the PATH for test execution
3. Runs the E2E tests using the isolated binary

This approach ensures:
- No pollution of the global environment
- Each test run uses a freshly built binary
- Test isolation between different test runs
- Clean test environment without side effects

### Running Tests

```bash
# Run all E2E tests
mage test:e2e

# Run specific test
go test -v -tags=e2e ./e2e/ -run TestE2E/image_scan

# Update golden files when output changes
go test -v -tags=e2e ./e2e/ -update
```

### Adding New Tests

When adding new E2E tests:
1. Focus on external dependencies and real-world scenarios
2. Use minimal assertions - verify functionality, not detailed output
3. Use golden files with -update flag for output comparison
4. Validate required dependencies in test setup
5. Use fixed/pinned versions for reproducible results
6. Include clear test documentation explaining the scenario being tested