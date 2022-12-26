# AWS Compliance

!!! warning "EXPERIMENTAL"
    This feature might change without preserving backwards compatibility.

This page describes AWS specific compliance reports. For an overview of Trivy's Compliance feature, including working with custom compliance, check out the [Compliance documentation](../../compliance/compliance.md).


## CLI Commands

Scan a cloud accoung and generate a compliance summary report:

```
$ trivy aws --compliance=awscis1.2 --report=summary
```

```
Summary Report for compliance: awscis1.2
┌──────┬──────────┬────────────────────────────────────────────┬────────┬────────┐
│  ID  │ Severity │                Control Name                │ Status │ Issues │
├──────┼──────────┼────────────────────────────────────────────┼────────┼────────┤
│ 1.1  │ LOW      │          limit-root-account-usage          │  PASS  │   0    │
│ 1.10 │ MEDIUM   │             no-password-reuse              │  PASS  │   0    │
│ 1.11 │ MEDIUM   │            set-max-password-age            │  PASS  │   0    │
│ 1.12 │ CRITICAL │            no-root-access-keys             │  PASS  │   0    │
│ 1.13 │ CRITICAL │              enforce-root-mfa              │  PASS  │   0    │
│ 1.16 │ LOW      │         no-user-attached-policies          │  FAIL  │   5    │
│ 1.2  │ MEDIUM   │              enforce-user-mfa              │  PASS  │   0    │
│ 1.3  │ MEDIUM   │         disable-unused-credentials         │  FAIL  │   2    │
│ 1.4  │ LOW      │             rotate-access-keys             │  FAIL  │   7    │
│ 1.5  │ MEDIUM   │       require-uppercase-in-passwords       │  PASS  │   0    │
│ 1.6  │ MEDIUM   │       require-lowercase-in-passwords       │  PASS  │   0    │
│ 1.7  │ MEDIUM   │        require-symbols-in-passwords        │  PASS  │   0    │
│ 1.8  │ MEDIUM   │        require-numbers-in-passwords        │  PASS  │   0    │
│ 1.9  │ MEDIUM   │        set-minimum-password-length         │  FAIL  │   1    │
│ 2.3  │ CRITICAL │            no-public-log-access            │  PASS  │   0    │
│ 2.4  │ LOW      │       ensure-cloudwatch-integration        │  PASS  │   0    │
│ 2.5  │ MEDIUM   │             enable-all-regions             │  PASS  │   0    │
│ 2.6  │ LOW      │       require-bucket-access-logging        │  PASS  │   0    │
│ 3.1  │ LOW      │    require-unauthorised-api-call-alarm     │  PASS  │   0    │
│ 3.10 │ LOW      │          require-sg-change-alarms          │  PASS  │   0    │
│ 3.11 │ LOW      │         require-nacl-changes-alarm         │  PASS  │   0    │
│ 3.12 │ LOW      │   require-network-gateway-changes-alarm    │  PASS  │   0    │
│ 3.13 │ LOW      │   require-network-gateway-changes-alarm    │  PASS  │   0    │
│ 3.14 │ LOW      │         require-vpc-changes-alarm          │  PASS  │   0    │
│ 3.2  │ LOW      │        require-non-mfa-login-alarm         │  PASS  │   0    │
│ 3.3  │ LOW      │       require-root-user-usage-alarm        │  PASS  │   0    │
│ 3.4  │ LOW      │      require-iam-policy-change-alarm       │  PASS  │   0    │
│ 3.5  │ LOW      │      require-cloud-trail-change-alarm      │  PASS  │   0    │
│ 3.6  │ LOW      │    require-console-login-failures-alarm    │  PASS  │   0    │
│ 3.7  │ LOW      │         require-cmk-disabled-alarm         │  PASS  │   0    │
│ 3.8  │ LOW      │   require-s3-bucket-policy-change-alarm    │  PASS  │   0    │
│ 3.9  │ LOW      │ require-config-configuration-changes-alarm │  PASS  │   0    │
│ 4.1  │ CRITICAL │           no-public-ingress-sgr            │  PASS  │   0    │
└──────┴──────────┴────────────────────────────────────────────┴────────┴────────┘
```

<<<<<<< HEAD

Furthermore, you can also get the report in a JSON format.
```shell
$ trivy aws --compliance=aws-cis-1.2 --report=summary --format=json
```

```json
{
  "ID": "aws-cis-1.2",
  "Title": "AWS CIS Foundations",
  "SummaryControls": [
    {
      "ID": "1.1",
      "Name": "limit-root-account-usage",
      "Severity": "LOW",
      "TotalFail": 5
    },
    {
      "ID": "1.10",
      "Name": "no-password-reuse",
      "Severity": "MEDIUM",
      "TotalFail": 1
    }
  ]
}
```


## Custom compliance report

The Trivy AWS CLI allows you to create a custom compliance specification and pass it to trivy for generating scan report.

The report is generated based on scanning result mapping between users define controls and trivy checks ID.
The supported checks are from two types and can be found at [Aqua vulnerability DB](https://avd.aquasec.com/):
- [misconfiguration](https://avd.aquasec.com/misconfig/)

### Compliance spec format
The compliance spec file format should be as follows:


```yaml
---
spec:
  id: aws-cis-1.2
  title: AWS CIS Foundations
  description: AWS CIS Foundations
  version: "1.2"
  relatedResources:
  - https://www.cisecurity.org/benchmark/amazon_web_services
  controls:
  - id: "1.1"
    name: limit-root-account-usage
    description: |-
      The "root" account has unrestricted access to all resources in the AWS account. It is highly
      recommended that the use of this account be avoided.
    checks:
    - id: AVD-AWS-0140
    severity: LOW
```

## Custom report CLI Commands

To use a custom spec, the file path should be passed to the `--compliance` flag with `@` prefix as follows:
=======
***Note*** : The `Issues` column represent the total number of failed checks for this control.


Get all of the detailed output for checks:
>>>>>>> 499209ca8 (docs: improve compliance docs)

```
$ trivy aws --compliance=awscis1.2 --report all
```

Report result in JSON format:

```
$ trivy aws --compliance=awscis1.2 --report all --format json
```

```
$ trivy k8s cluster --compliance=nsa --report all --format json
```

## Built in reports

the following reports out of the box:

| Compliance | Name for command | More info
--- | --- | ---
AWS CIS Foundations Benchmark v1.2 | `awscis1.2` | [link](https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf)
AWS CIS Foundations Benchmark v1.4 | `awscis1.4` | [link](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls-1.4.0.html)
