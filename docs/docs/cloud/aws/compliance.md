# AWS Compliance

## CIS Compliance Report

!!! warning "EXPERIMENTAL"
This feature might change without preserving backwards compatibility.

The Trivy AWS CLI allows you to scan your AWS account resources and generate the `AWS CIS Foundations Benchmark` report

[AWS CIS Foundations Benchmark v1.2](https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf) validates the following control checks:

```shell
+--------------------------------------------+--------------------------------+
|                    NAME                    |          DESCRIPTION           |
+--------------------------------------------+--------------------------------+
| limit-root-account-usage                   | The "root" account has         |
|                                            | unrestricted access to all     |
|                                            | resources in the AWS account.  |
|                                            | It is highly recommended that  |
|                                            | the use of this account be     |
|                                            | avoided.                       |
| no-password-reuse                          | IAM Password policy should     |
|                                            | prevent password reuse.        |
| set-max-password-age                       | IAM Password policy should     |
|                                            | have expiry less than or equal |
|                                            | to 90 days.                    |
| no-root-access-keys                        | The root user has complete     |
|                                            | access to all services and     |
|                                            | resources in an AWS account.   |
|                                            | AWS Access Keys provide        |
|                                            | programmatic access to a given |
|                                            | account.                       |
| enforce-root-mfa                           | The "root" account has         |
|                                            | unrestricted access to all     |
|                                            | resources in the AWS account.  |
|                                            | It is highly recommended that  |
|                                            | this account have MFA enabled. |
| no-user-attached-policies                  | IAM policies should not be     |
|                                            | granted directly to users.     |
| enforce-user-mfa                           | IAM Users should have MFA      |
|                                            | enforcement activated.         |
| disable-unused-credentials                 | Credentials which are          |
|                                            | no longer used should be       |
|                                            | disabled.                      |
| rotate-access-keys                         | Access keys should be rotated  |
|                                            | at least every 90 days         |
| require-uppercase-in-passwords             | IAM Password policy should     |
|                                            | have requirement for at least  |
|                                            | one uppercase character.       |
| require-lowercase-in-passwords             | IAM Password policy should     |
|                                            | have requirement for at least  |
|                                            | one lowercase character.       |
| require-symbols-in-passwords               | IAM Password policy should     |
|                                            | have requirement for at least  |
|                                            | one symbol in the password.    |
| require-numbers-in-passwords               | IAM Password policy should     |
|                                            | have requirement for at least  |
|                                            | one number in the password.    |
| set-minimum-password-length                | IAM Password policy should     |
|                                            | have minimum password length   |
|                                            | of 14 or more characters.      |
| no-public-log-access                       | The S3 Bucket backing          |
|                                            | Cloudtrail should be private   |
| ensure-cloudwatch-integration              | CloudTrail logs should be      |
|                                            | stored in S3 and also sent to  |
|                                            | CloudWatch Logs                |
| enable-all-regions                         | Cloudtrail should be enabled   |
|                                            | in all regions regardless of   |
|                                            | where your AWS resources are   |
|                                            | generally homed                |
| require-bucket-access-logging              | You should enable bucket       |
|                                            | access logging on the          |
|                                            | CloudTrail S3 bucket.          |
| require-unauthorised-api-call-alarm        | Ensure a log metric filter and |
|                                            | alarm exist for unauthorized   |
|                                            | API calls                      |
| require-sg-change-alarms                   | Ensure a log metric filter and |
|                                            | alarm exist for security group |
|                                            | changes                        |
| require-nacl-changes-alarm                 | Ensure a log metric filter     |
|                                            | and alarm exist for changes to |
|                                            | Network Access Control Lists   |
|                                            | (NACL)                         |
| require-network-gateway-changes-alarm      | Ensure a log metric filter     |
|                                            | and alarm exist for changes to |
|                                            | network gateways               |
| require-network-gateway-changes-alarm      | Ensure a log metric filter and |
|                                            | alarm exist for route table    |
|                                            | changes                        |
| require-vpc-changes-alarm                  | Ensure a log metric filter and |
|                                            | alarm exist for VPC changes    |
| require-non-mfa-login-alarm                | Ensure a log metric filter and |
|                                            | alarm exist for AWS Management |
|                                            | Console sign-in without MFA    |
| require-root-user-usage-alarm              | Ensure a log metric filter and |
|                                            | alarm exist for usage of root  |
|                                            | user                           |
| require-iam-policy-change-alarm            | Ensure a log metric filter     |
|                                            | and alarm exist for IAM policy |
|                                            | changes                        |
| require-cloud-trail-change-alarm           | Ensure a log metric filter     |
|                                            | and alarm exist for CloudTrail |
|                                            | configuration changes          |
| require-console-login-failures-alarm       | Ensure a log metric filter and |
|                                            | alarm exist for AWS Management |
|                                            | Console authentication         |
|                                            | failures                       |
| require-cmk-disabled-alarm                 | Ensure a log metric filter and |
|                                            | alarm exist for disabling or   |
|                                            | scheduled deletion of customer |
|                                            | managed keys                   |
| require-s3-bucket-policy-change-alarm      | Ensure a log metric filter     |
|                                            | and alarm exist for S3 bucket  |
|                                            | policy changes                 |
| require-config-configuration-changes-alarm | Ensure a log metric filter     |
|                                            | and alarm exist for AWS Config |
|                                            | configuration changes          |
| no-public-ingress-sgr                      | An ingress security group rule |
|                                            | allows traffic from /0.        |
+--------------------------------------------+--------------------------------+
```

## CLI Commands

Scan for misconfigurations in an AWS account based on AWS CIS 1.2 benchmark:

```shell
$ trivy aws --compliance=awscis1.2

arn:aws:iam::123456789:user/DummyRoleManager (cloud)

Tests: 1 (SUCCESSES: 0, FAILURES: 1, EXCEPTIONS: 0)

LOW: One or more policies are attached directly to a user
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
CIS recommends that you apply IAM policies directly to groups and roles but not users. Assigning privileges at the group or role level reduces the complexity of access management as the number of users grow. Reducing access management complexity might in turn reduce opportunity for a principal to inadvertently receive or retain excessive privileges.

See https://avd.aquasec.com/misconfig/avd-aws-0143
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


```



You can also summarize the report to get a full compliance report with all the included checks.
```shell
$ trivy aws --compliance=awscis1.2 --report=summary
```

```shell
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


Furthermore, you can also get the report in a JSON format.
```shell
$ trivy aws --compliance=awscis1.2 --report=summary --format=json
```

```json
{
	"ID": "0001",
	"Title": "awscis1.2",
	"SummaryControls": [{
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
  id: "0001"
  title: awscis1.2
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

```
$ trivy aws --compliance=@/spec/my_compliance.yaml
```

