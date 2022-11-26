# AWS EC2

Trivy can scan the following targets in AWS EC2.

- Amazon Machine Image (AMI)
- Elastic Block Store (EBS) Snapshot

## Amazon Machine Image (AMI)
You can specify your AMI ID with the `ami:` prefix.

```shell
$ trivy vm ami:${your_ami_id}
```

!!! note
    AMIs in the marketplace are not supported because the EBS direct APIs don't support that.
    See [the AWS documentation][ebsapi-elements] for the detail.

### Example
Note that the scanning could be faster if you enable only vulnerability scanning.

```shell
$ trivy vm --security-checks vuln ami:ami-0123456789abcdefg
```

### Required Actions
Some actions on EBS are also necessary since Trivy scans an EBS snapshot tied to the specified AMI under the hood.

- ec2:DescribeImages
- ebs:ListSnapshotBlocks
- ebs:GetSnapshotBlock

## Elastic Block Store (EBS) Snapshot
You can specify your EBS snapshot ID with the `ebs:` prefix.

```shell
$ trivy vm ebs:${your_ebs_snapshot_id}
```

!!! note
    Public snapshots are not supported because the EBS direct APIs don't support that.
    See [the AWS documentation][ebsapi-elements] for the detail.

### Example
Note that the scanning could be faster if you enable only vulnerability scanning.

```shell
$ trivy vm --security-checks vuln ebs:snap-0123456789abcdefg
```

The above command takes a while as it calls EBS API and fetches the EBS blocks.
If you want to scan the same snapshot several times, you can download the snapshot locally by using [coldsnap][coldsnap] maintained by AWS.
Then, Trivy can scan the local VM image file.

```shell
$ coldsnap download snap-0123456789abcdefg disk.img
$ trivy vm ./disk.img
```

### Required Actions

- ebs:ListSnapshotBlocks
- ebs:GetSnapshotBlock

[ebsapi-elements]: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-accessing-snapshot.html#ebsapi-elements
[coldsnap]: https://github.com/awslabs/coldsnap