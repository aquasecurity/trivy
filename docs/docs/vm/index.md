# Virtual Machine Image

!!! warning "EXPERIMENTAL"
    This feature might change without preserving backwards compatibility.

## Scanning
Trivy supports VM image scanning for vulnerabilities, secrets, etc.
The following targets are currently supported:

- Local file
- [AWS EC2][aws]

To scan VM images, you can use the `vm` subcommand.

### Local file
Pass the path to your local VM image file.

```bash
$ trivy vm --security-checks vuln disk.vmdk
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

### AWS EC2

See [here][aws] for the detail.

## Supported architectures

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

[aws]: ./aws.md
[vmdk]: https://www.vmware.com/app/vmdk/?src=vmdk