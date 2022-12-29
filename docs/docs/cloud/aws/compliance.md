# AWS Compliance

!!! warning "EXPERIMENTAL"
    This feature might change without preserving backwards compatibility.

This page describes AWS specific compliance reports. For an overview of Trivy's Compliance feature, including working with custom compliance, check out the [Compliance documentation](../../compliance/compliance.md).

## Built in reports

the following reports are available out of the box:

| Compliance | Name for command | More info
--- | --- | ---
AWS CIS Foundations Benchmark v1.2 | `aws-cis-1.2` | [link](https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf)
AWS CIS Foundations Benchmark v1.4 | `aws-cis-1.4` | [link](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls-1.4.0.html)

## Examples

Scan a cloud account and generate a compliance summary report:

```
$ trivy aws --compliance=<compliance_id> --report=summary
```

***Note*** : The `Issues` column represent the total number of failed checks for this control.


Get all of the detailed output for checks:

```
$ trivy aws --compliance=<compliance_id> --report all
```

Report result in JSON format:

```
$ trivy aws --compliance=<compliance_id> --report all --format json
```

