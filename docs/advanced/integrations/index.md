# Integrations
Scan your image automatically as part of your CI workflow, failing the workflow if a vulnerability is found. When you don't want to fail the test, specify `--exit-code 0`.

Since in automated scenarios such as CI/CD you are only interested in the end result, and not the full report, use the `--light` flag to optimize for this scenario and get fast results.
