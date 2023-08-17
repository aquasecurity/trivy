# Virtual Machine Image

!!! warning "EXPERIMENTAL"
    This feature might change without preserving backwards compatibility.

To scan virtual machine (VM) images, you can use the `vm` subcommand.

## Targets
The following targets are currently supported:

- Local file
- AWS EC2
    - Amazon Machine Image (AMI)
    - Amazon Elastic Block Store (EBS) Snapshot
 
### Local file
Pass the path to your local VM image file.

```bash
$ trivy vm --scanners vuln disk.vmdk
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

### Amazon Machine Image (AMI)
You can specify your AMI ID with the `ami:` prefix.

```shell
$ trivy vm ami:${your_ami_id}
```

!!! note
    AMIs in the marketplace are not supported because the EBS direct APIs don't support that.
    See [the AWS documentation][ebsapi-elements] for the detail.

#### Example

```shell
$ trivy vm --scanners vuln ami:ami-0123456789abcdefg
```

If you want to scan a AMI of non-default setting region, you can set any region via `--aws-region` option.

```shell
$ trivy vm --aws-region ap-northeast-1 ami:ami-0123456789abcdefg
```


#### Required Actions
Some actions on EBS are also necessary since Trivy scans an EBS snapshot tied to the specified AMI under the hood.

- ec2:DescribeImages
- ebs:ListSnapshotBlocks
- ebs:GetSnapshotBlock

### Amazon Elastic Block Store (EBS) Snapshot
You can specify your EBS snapshot ID with the `ebs:` prefix.

```shell
$ trivy vm ebs:${your_ebs_snapshot_id}
```

!!! note
    Public snapshots are not supported because the EBS direct APIs don't support that.
    See [the AWS documentation][ebsapi-elements] for the detail.

#### Example

```shell
$ trivy vm --scanners vuln ebs:snap-0123456789abcdefg
```


If you want to scan an EBS Snapshot of non-default setting region, you can set any region via `--aws-region` option.

```shell
$ trivy vm --aws-region ap-northeast-1 ebs:ebs-0123456789abcdefg
```

The above command takes a while as it calls EBS API and fetches the EBS blocks.
If you want to scan the same snapshot several times, you can download the snapshot locally by using [coldsnap][coldsnap] maintained by AWS.
Then, Trivy can scan the local VM image file.

```shell
$ coldsnap download snap-0123456789abcdefg disk.img
$ trivy vm ./disk.img
```

#### Required Actions

- ebs:ListSnapshotBlocks
- ebs:GetSnapshotBlock

## Scanners
Trivy supports VM image scanning for

- Vulnerabilities
- Misconfigurations
- Secrets
- Licenses

### Vulnerabilities
It is enabled by default.
You can simply specify your VM image location.
It detects known vulnerabilities in your VM image.
See [here](../scanner/vulnerability.md) for the detail.

```
$ trivy vm [YOUR_VM_IMAGE]
```

### Misconfigurations
It is supported, but it is not useful in most cases.
As mentioned [here](../scanner/misconfiguration/index.md), Trivy mainly supports Infrastructure as Code (IaC) files for misconfigurations.
If your VM image includes IaC files such as Kubernetes YAML files or Terraform files, you should enable this feature with `--scanners config`.

```
$ trivy vm --scanners config [YOUR_VM_IMAGE]
```

### Secrets
It is enabled by default.
See [here](../scanner/secret.md) for the detail.

```shell
$ trivy vm [YOUR_VM_IMAGE]
```

!!! tip
    The scanning could be faster if you enable only vulnerability scanning (`--scanners vuln`) because Trivy tries to download only necessary blocks for vulnerability detection.

### Licenses
It is disabled by default.
See [here](../scanner/license.md) for the detail.

```shell
$ trivy vm --scanners license [YOUR_VM_IMAGE]
```

## SBOM generation
Trivy can generate SBOM for VM images.
See [here](../supply-chain/sbom.md) for the detail.

## Supported Architectures

### Virtual machine images

| Image format | Support |
|--------------|:-------:|
| VMDK         |    ✔    |
| OVA          |         |
| VHD          |         |
| VHDX         |         |
| QCOW2        |         |


#### VMDK disk types

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


### Disk partitions

| Disk format                  | Support |
|------------------------------|:-------:|
| Master boot record (MBR)     |    ✔    |
| Extended master boot record  |         |
| GUID partition table (GPT)   |    ✔    |
| Logical volume manager (LVM) |         |

### Filesystems

| Filesystem format | Support |
|-------------------|:-------:|
| XFS               |    ✔    |
| EXT4              |    ✔    |
| EXT2/3            |         |
| ZFS               |         |


[vmdk]: https://www.vmware.com/app/vmdk/?src=vmdk
[ebsapi-elements]: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-accessing-snapshot.html#ebsapi-elements
[coldsnap]: https://github.com/awslabs/coldsnap

