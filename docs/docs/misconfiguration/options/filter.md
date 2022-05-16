# Filter Misconfigurations

## By Severity

Use `--severity` option.

```bash
trivy conf --severity HIGH,CRITICAL examples/misconf/mixed
```

<details>
<summary>Result</summary>

```shell
2022-05-16T13:50:42.718+0100	INFO	Detected config files: 3

Dockerfile (dockerfile)
=======================
Tests: 17 (SUCCESSES: 16, FAILURES: 1, EXCEPTIONS: 0)
Failures: 1 (HIGH: 1, CRITICAL: 0)

HIGH: Last USER command in Dockerfile should not be 'root'
═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Running containers with 'root' user can lead to a container escape situation. It is a best practice to run containers as non-root users, which can be done by adding a 'USER' statement to the Dockerfile.

See https://avd.aquasec.com/misconfig/ds002
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 Dockerfile:3
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   3 [ USER root
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────



deployment.yaml (kubernetes)
============================
Tests: 8 (SUCCESSES: 8, FAILURES: 0, EXCEPTIONS: 0)
Failures: 0 (HIGH: 0, CRITICAL: 0)


main.tf (terraform)
===================
Tests: 1 (SUCCESSES: 0, FAILURES: 1, EXCEPTIONS: 0)
Failures: 1 (HIGH: 0, CRITICAL: 1)

CRITICAL: Classic resources should not be used.
═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
AWS Classic resources run in a shared environment with infrastructure owned by other AWS customers. You should run
resources in a VPC instead.

See https://avd.aquasec.com/misconfig/avd-aws-0081
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 main.tf:2-4
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   2 ┌ resource "aws_db_security_group" "sg" {
   3 │
   4 └ }
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```
</details>
