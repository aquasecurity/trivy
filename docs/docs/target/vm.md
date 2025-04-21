# Virtual Machine Image

!!! warning "EXPERIMENTAL"
    This feature might change without preserving backwards compatibility.

Scan virtual machine (VM) images.

`vm` is a post-build target type, which means it scans installed packages. For more information, see [Target types](../coverage/language/index.md#target-types).

You can scan a VM image file, Amazon Machine Image (AMI), or Amazon Elastic Block Store (EBS) snapshot.

Usage:

```shell
trivy vm disk.vmdk
trivy vm ami:${your_ami_id}
trivy vm ebs:${your_ebs_snapshot_id}
```
## Scanners

Supported scanners:

- Vulnerabilities
- Misconfigurations
- Secrets
- Licenses

By default, only vulnerability and secret scanning are enabled. You can configure which scanners are used with the [`--scanners` flag](../configuration/others.md#enabledisable-scanners).

## Local file
Pass the path to a local VM image file.

```shell
trivy vm --scanners vuln disk.vmdk
```

<details>
<summary>Result</summary>

```
disk.vmdk (amazon 2 (Karoo))
===========================================================================================
Total: 802 (UNKNOWN: 0, LOW: 17, MEDIUM: 554, HIGH: 221, CRITICAL: 10)

┌────────────────────────────┬────────────────┬──────────┬───────────────────────────────┬───────────────────────────────┬──────────────────────────────────────────────────────────────┐
│          Library           │ Vulnerability  │ Severity │       Installed Version       │         Fixed Version         │                            Title                             │
├────────────────────────────┼────────────────┼──────────┼───────────────────────────────┼───────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ amazon-ssm-agent           │ CVE-2022-24675 │ HIGH     │ 3.0.529.0-1.amzn2             │ 3.1.1575.0-1.amzn2            │ golang: encoding/pem: fix stack overflow in Decode           │
│                            │                │          │                               │                               │ https://avd.aquasec.com/nvd/cve-2022-24675                   │
├────────────────────────────┼────────────────┤          ├───────────────────────────────┼───────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ bind-export-libs           │ CVE-2021-25215 │          │ 32:9.11.4-26.P2.amzn2.4       │ 32:9.11.4-26.P2.amzn2.5       │ bind: An assertion check can fail while answering queries    │
│                            │                │          │                               │                               │ for DNAME records...                                         │
│                            │                │          │                               │                               │ https://avd.aquasec.com/nvd/cve-2021-25215                   │
│                            ├────────────────┼──────────┤                               ├───────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                            │ CVE-2021-25214 │ MEDIUM   │                               │ 32:9.11.4-26.P2.amzn2.5.2     │ bind: Broken inbound incremental zone update (IXFR) can      │
│                            │                │          │                               │                               │ cause named to terminate...                                  │
│                            │                │          │                               │                               │ https://avd.aquasec.com/nvd/cve-2021-25214                   │
├────────────────────────────┼────────────────┼──────────┤                               ├───────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ bind-libs                  │ CVE-2021-25215 │ HIGH     │                               │ 32:9.11.4-26.P2.amzn2.5       │ bind: An assertion check can fail while answering queries    │
│                            │                │          │                               │                               │ for DNAME records...                                         │
│                            │                │          │                               │                               │ https://avd.aquasec.com/nvd/cve-2021-25215                   │
│                            ├────────────────┼──────────┤                               ├───────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                            │ CVE-2021-25214 │ MEDIUM   │                               │ 32:9.11.4-26.P2.amzn2.5.2     │ bind: Broken inbound incremental zone update (IXFR) can      │
│                            │                │          │                               │                               │ cause named to terminate...                                  │
│                            │                │          │                               │                               │ https://avd.aquasec.com/nvd/cve-2021-25214                   │
├────────────────────────────┼────────────────┼──────────┤                               ├───────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ bind-libs-lite             │ CVE-2021-25215 │ HIGH     │                               │ 32:9.11.4-26.P2.amzn2.5       │ bind: An assertion check can fail while answering queries    │
│                            │                │          │                               │                               │ for DNAME records...                                         │
│                            │                │          │                               │                               │ https://avd.aquasec.com/nvd/cve-2021-25215                   │
│                            ├────────────────┼──────────┤                               ├───────────────────────────────┼──────────────────────────────────────────────────────────────┤
│                            │ CVE-2021-25214 │ MEDIUM   │                               │ 32:9.11.4-26.P2.amzn2.5.2     │ bind: Broken inbound incremental zone update (IXFR) can      │
│                            │                │          │                               │                               │ cause named to terminate...                                  │
│                            │                │          │                               │                               │ https://avd.aquasec.com/nvd/cve-2021-25214                   │
├────────────────────────────┼────────────────┼──────────┤                               ├───────────────────────────────┼──────────────────────────────────────────────────────────────┤
...
```

</details>

## Amazon Machine Image (AMI)
You can specify an AMI ID with the `ami:` prefix.

AMIs in the marketplace are not supported because the EBS direct APIs don't support that. See [the AWS documentation][ebsapi-elements] for the detail.

```shell
trivy vm --scanners vuln ami:ami-0123456789abcdefg
```

You can set AWS region via `--aws-region` flag.

```shell
trivy vm --aws-region ap-northeast-1 ami:ami-0123456789abcdefg
```

### Required Roles
Some actions on EBS are also necessary since Trivy scans an EBS snapshot tied to the specified AMI under the hood.

- `ec2:DescribeImages`
- `ebs:ListSnapshotBlocks`
- `ebs:GetSnapshotBlock`

## Amazon Elastic Block Store (EBS) Snapshot
You can specify your EBS snapshot ID with the `ebs:` prefix.

Public snapshots are not supported because the EBS direct APIs don't support that. See [the AWS documentation][ebsapi-elements] for the detail.

```shell
trivy vm --scanners vuln ebs:snap-0123456789abcdefg
```

You can set AWS region via `--aws-region` flag.

```shell
trivy vm --aws-region ap-northeast-1 ebs:ebs-0123456789abcdefg
```

The above command takes a while as it calls EBS API and fetches the EBS blocks.
If you want to scan the same snapshot several times, you can download the snapshot locally by using [coldsnap][coldsnap] maintained by AWS. Then, Trivy can scan the local VM image file.

```bash
$ coldsnap download snap-0123456789abcdefg disk.img
$ trivy vm ./disk.img
```

### Required Roles

- `ebs:ListSnapshotBlocks`
- `ebs:GetSnapshotBlock`

## Scan Cache
When scanning AMI or EBS snapshots, it stores analysis results in the cache, using the snapshot ID.
Scanning the same snapshot several times skips analysis if the cache is already available.

When scanning local files, it doesn't use the cache by default.

More details are available in the [cache documentation](../configuration/cache.md#scan-cache-backend).

## Supported Architectures

Virtual machine images:

| Image format | Support |
|--------------|:-------:|
| VMDK         |    ✔    |
| OVA          |         |
| VHD          |         |
| VHDX         |         |
| QCOW2        |         |


VMDK disk types:

| VMDK disk type              | Support |
|-----------------------------|:-------:|
| streamOptimized             |    ✔    |
| monolithicSparse            |         |
| vmfs                        |         |
| vmfsSparse                  |         |
| twoGbMaxExtentSparse        |         |
| monolithicFlat              |         |
| twoGbMaxExtentFlat          |         |
| vmfsRaw                     |         |
| fullDevice                  |         |
| partitionedDevice           |         |
| vmfsRawDeviceMap            |         |
| vmfsPassthroughRawDeviceMap |         |

Reference: [VMware Virtual Disk Format 1.1.pdf][vmdk]

Disk partitions:

| Disk format                  | Support |
|------------------------------|:-------:|
| Master boot record (MBR)     |    ✔    |
| Extended master boot record  |         |
| GUID partition table (GPT)   |    ✔    |
| Logical volume manager (LVM) |         |

Filesystems:

| Filesystem format | Support |
|-------------------|:-------:|
| XFS               |    ✔    |
| EXT4              |    ✔    |
| EXT2/3            |    ✔    |
| ZFS               |         |

## SBOM Generation

You can generate SBOM for the virtual machine using the `--format` flag. For supported SBOM formats and additional information, see [here](../supply-chain/sbom.md).

For example:

```bash
# Generate a CycloneDX SBOM
trivy vm --format cyclonedx disk.vmdk
```

[vmdk]: https://github.com/libyal/libvmdk/blob/main/documentation/VMWare%20Virtual%20Disk%20Format%20(VMDK).asciidoc
[ebsapi-elements]: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-accessing-snapshot.html#ebsapi-elements
[coldsnap]: https://github.com/awslabs/coldsnap

