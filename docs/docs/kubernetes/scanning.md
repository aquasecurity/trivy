# Kubernetes

Scan your Kubernetes cluster for both Vulnerabilities and Misconfigurations.

Scan a full cluster:

```
$ trivy k8s
```

Scan a namespace:

```
$ trivy k8s -n default
```

Scan a namespace for only `CRITICAL` Vulnerabilities and Misconfigurations:

```
$ trivy k8s -n default -o results.json --severity CRITICAL
```

It uses local kubectl configuration to access the API server to list artifacts.
Currently, the only supported output is json to be used for automation, other reports will be implemented soon.

<details>
<summary>Result</summary>

```
{
  "ClusterName": "minikube",
  "Vulnerabilities": [
    {
      "Namespace": "default",
      "Kind": "Deployment",
      "Name": "app",
      "Results": [
        {
          "Target": "ubuntu:latest (ubuntu 22.04)",
          "Class": "os-pkgs",
          "Type": "ubuntu",
          "Vulnerabilities": [
            {
              "VulnerabilityID": "CVE-2016-2781",
              "PkgName": "coreutils",
              "InstalledVersion": "8.32-4.1ubuntu1",
              "Layer": {
                "Digest": "sha256:125a6e411906fe6b0aaa50fc9d600bf6ff9bb11a8651727ce1ed482dc271c24c",
                "DiffID": "sha256:e59fc94956120a6c7629f085027578e6357b48061d45714107e79f04a81a6f0c"
              },
              "SeveritySource": "ubuntu",
              "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2016-2781",
              "DataSource": {
                "ID": "ubuntu",
                "Name": "Ubuntu CVE Tracker",
                "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
              },
              "Title": "coreutils: Non-privileged session can escape to the parent session in chroot",
              "Description": "chroot in GNU coreutils, when used with --userspec, allows local users to escape to the parent session via a crafted TIOCSTI ioctl call, which pushes characters to the terminal's input buffer.",
              "Severity": "LOW",
              "CweIDs": [
                "CWE-20"
              ],
              "VendorSeverity": {
                "cbl-mariner": 2,
                "nvd": 2,
                "redhat": 2,
                "ubuntu": 1
              },
              "CVSS": {
                "nvd": {
                  "V2Vector": "AV:L/AC:L/Au:N/C:N/I:P/A:N",
                  "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N",
                  "V2Score": 2.1,
                  "V3Score": 6.5
                },
                "redhat": {
                  "V2Vector": "AV:L/AC:H/Au:N/C:C/I:C/A:C",
                  "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
                  "V2Score": 6.2,
                  "V3Score": 8.6
                }
              },
              "References": [
                "http://seclists.org/oss-sec/2016/q1/452",
                "http://www.openwall.com/lists/oss-security/2016/02/28/2",
                "http://www.openwall.com/lists/oss-security/2016/02/28/3",
                "https://access.redhat.com/security/cve/CVE-2016-2781",
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-2781",
                "https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E",
                "https://lore.kernel.org/patchwork/patch/793178/",
                "https://nvd.nist.gov/vuln/detail/CVE-2016-2781"
              ],
              "PublishedDate": "2017-02-07T15:59:00Z",
              "LastModifiedDate": "2021-02-25T17:15:00Z"
            },
            {
              "VulnerabilityID": "CVE-2022-1304",
              "PkgName": "e2fsprogs",
              "InstalledVersion": "1.46.5-2ubuntu1",
              "Layer": {
                "Digest": "sha256:125a6e411906fe6b0aaa50fc9d600bf6ff9bb11a8651727ce1ed482dc271c24c",
                "DiffID": "sha256:e59fc94956120a6c7629f085027578e6357b48061d45714107e79f04a81a6f0c"
              },
              "SeveritySource": "ubuntu",
              "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2022-1304",
              "DataSource": {
                "ID": "ubuntu",
                "Name": "Ubuntu CVE Tracker",
                "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
              },
              "Title": "e2fsprogs: out-of-bounds read/write via crafted filesystem",
              "Description": "An out-of-bounds read/write vulnerability was found in e2fsprogs 1.46.5. This issue leads to a segmentation fault and possibly arbitrary code execution via a specially crafted filesystem.",
              "Severity": "MEDIUM",
              "CweIDs": [
                "CWE-125",
                "CWE-787"
              ],
              "VendorSeverity": {
                "cbl-mariner": 3,
                "nvd": 3,
                "redhat": 2,
                "ubuntu": 2
              },
              "CVSS": {
                "nvd": {
                  "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
                  "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                  "V2Score": 6.8,
                  "V3Score": 7.8
                },
                "redhat": {
                  "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H",
                  "V3Score": 7
                }
              },
              "References": [
                "https://access.redhat.com/security/cve/CVE-2022-1304",
                "https://bugzilla.redhat.com/show_bug.cgi?id=2069726",
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1304",
                "https://marc.info/?l=linux-ext4\u0026m=165056234501732\u0026w=2",
                "https://nvd.nist.gov/vuln/detail/CVE-2022-1304"
              ],
              "PublishedDate": "2022-04-14T21:15:00Z",
              "LastModifiedDate": "2022-04-21T15:36:00Z"
            },
            {
              "VulnerabilityID": "CVE-2022-1304",
              "PkgName": "libcom-err2",
              "InstalledVersion": "1.46.5-2ubuntu1",
              "Layer": {
                "Digest": "sha256:125a6e411906fe6b0aaa50fc9d600bf6ff9bb11a8651727ce1ed482dc271c24c",
                "DiffID": "sha256:e59fc94956120a6c7629f085027578e6357b48061d45714107e79f04a81a6f0c"
              },
              "SeveritySource": "ubuntu",
              "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2022-1304",
              "DataSource": {
                "ID": "ubuntu",
                "Name": "Ubuntu CVE Tracker",
                "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
              },
              "Title": "e2fsprogs: out-of-bounds read/write via crafted filesystem",
              "Description": "An out-of-bounds read/write vulnerability was found in e2fsprogs 1.46.5. This issue leads to a segmentation fault and possibly arbitrary code execution via a specially crafted filesystem.",
              "Severity": "MEDIUM",
              "CweIDs": [
                "CWE-125",
                "CWE-787"
              ],
              "VendorSeverity": {
                "cbl-mariner": 3,
                "nvd": 3,
                "redhat": 2,
                "ubuntu": 2
              },
              "CVSS": {
                "nvd": {
                  "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
                  "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                  "V2Score": 6.8,
                  "V3Score": 7.8
                },
                "redhat": {
                  "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H",
                  "V3Score": 7
                }
              },
              "References": [
                "https://access.redhat.com/security/cve/CVE-2022-1304",
                "https://bugzilla.redhat.com/show_bug.cgi?id=2069726",
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1304",
                "https://marc.info/?l=linux-ext4\u0026m=165056234501732\u0026w=2",
                "https://nvd.nist.gov/vuln/detail/CVE-2022-1304"
              ],
              "PublishedDate": "2022-04-14T21:15:00Z",
              "LastModifiedDate": "2022-04-21T15:36:00Z"
            },
            {
              "VulnerabilityID": "CVE-2022-1304",
              "PkgName": "libext2fs2",
              "InstalledVersion": "1.46.5-2ubuntu1",
              "Layer": {
                "Digest": "sha256:125a6e411906fe6b0aaa50fc9d600bf6ff9bb11a8651727ce1ed482dc271c24c",
                "DiffID": "sha256:e59fc94956120a6c7629f085027578e6357b48061d45714107e79f04a81a6f0c"
              },
              "SeveritySource": "ubuntu",
              "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2022-1304",
              "DataSource": {
                "ID": "ubuntu",
                "Name": "Ubuntu CVE Tracker",
                "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
              },
              "Title": "e2fsprogs: out-of-bounds read/write via crafted filesystem",
              "Description": "An out-of-bounds read/write vulnerability was found in e2fsprogs 1.46.5. This issue leads to a segmentation fault and possibly arbitrary code execution via a specially crafted filesystem.",
              "Severity": "MEDIUM",
              "CweIDs": [
                "CWE-125",
                "CWE-787"
              ],
              "VendorSeverity": {
                "cbl-mariner": 3,
                "nvd": 3,
                "redhat": 2,
                "ubuntu": 2
              },
              "CVSS": {
                "nvd": {
                  "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
                  "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                  "V2Score": 6.8,
                  "V3Score": 7.8
                },
                "redhat": {
                  "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H",
                  "V3Score": 7
                }
              },
              "References": [
                "https://access.redhat.com/security/cve/CVE-2022-1304",
                "https://bugzilla.redhat.com/show_bug.cgi?id=2069726",
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1304",
                "https://marc.info/?l=linux-ext4\u0026m=165056234501732\u0026w=2",
                "https://nvd.nist.gov/vuln/detail/CVE-2022-1304"
              ],
              "PublishedDate": "2022-04-14T21:15:00Z",
              "LastModifiedDate": "2022-04-21T15:36:00Z"
            },
            {
              "VulnerabilityID": "CVE-2021-43618",
              "PkgName": "libgmp10",
              "InstalledVersion": "2:6.2.1+dfsg-3ubuntu1",
              "Layer": {
                "Digest": "sha256:125a6e411906fe6b0aaa50fc9d600bf6ff9bb11a8651727ce1ed482dc271c24c",
                "DiffID": "sha256:e59fc94956120a6c7629f085027578e6357b48061d45714107e79f04a81a6f0c"
              },
              "SeveritySource": "ubuntu",
              "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-43618",
              "DataSource": {
                "ID": "ubuntu",
                "Name": "Ubuntu CVE Tracker",
                "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
              },
              "Title": "gmp: Integer overflow and resultant buffer overflow via crafted input",
              "Description": "GNU Multiple Precision Arithmetic Library (GMP) through 6.2.1 has an mpz/inp_raw.c integer overflow and resultant buffer overflow via crafted input, leading to a segmentation fault on 32-bit platforms.",
              "Severity": "LOW",
              "CweIDs": [
                "CWE-190"
              ],
              "VendorSeverity": {
                "arch-linux": 1,
                "cbl-mariner": 3,
                "nvd": 3,
                "redhat": 1,
                "ubuntu": 1
              },
              "CVSS": {
                "nvd": {
                  "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
                  "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                  "V2Score": 5,
                  "V3Score": 7.5
                },
                "redhat": {
                  "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                  "V3Score": 6.2
                }
              },
              "References": [
                "https://access.redhat.com/security/cve/CVE-2021-43618",
                "https://bugs.debian.org/994405",
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-43618",
                "https://gmplib.org/list-archives/gmp-bugs/2021-September/005077.html",
                "https://gmplib.org/repo/gmp-6.2/rev/561a9c25298e",
                "https://lists.debian.org/debian-lts-announce/2021/12/msg00001.html",
                "https://nvd.nist.gov/vuln/detail/CVE-2021-43618"
              ],
              "PublishedDate": "2021-11-15T04:15:00Z",
              "LastModifiedDate": "2021-12-16T18:39:00Z"
            },
            {
              "VulnerabilityID": "CVE-2018-5709",
              "PkgName": "libgssapi-krb5-2",
              "InstalledVersion": "1.19.2-2",
              "Layer": {
                "Digest": "sha256:125a6e411906fe6b0aaa50fc9d600bf6ff9bb11a8651727ce1ed482dc271c24c",
                "DiffID": "sha256:e59fc94956120a6c7629f085027578e6357b48061d45714107e79f04a81a6f0c"
              },
              "SeveritySource": "ubuntu",
              "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2018-5709",
              "DataSource": {
                "ID": "ubuntu",
                "Name": "Ubuntu CVE Tracker",
                "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
              },
              "Title": "krb5: integer overflow in dbentry-\u003en_key_data in kadmin/dbutil/dump.c",
              "Description": "An issue was discovered in MIT Kerberos 5 (aka krb5) through 1.16. There is a variable \"dbentry-\u003en_key_data\" in kadmin/dbutil/dump.c that can store 16-bit data but unknowingly the developer has assigned a \"u4\" variable to it, which is for 32-bit data. An attacker can use this vulnerability to affect other artifacts of the database as we know that a Kerberos database dump file contains trusted data.",
              "Severity": "LOW",
              "CweIDs": [
                "CWE-190"
              ],
              "VendorSeverity": {
                "arch-linux": 2,
                "nvd": 3,
                "redhat": 2,
                "ubuntu": 1
              },
              "CVSS": {
                "nvd": {
                  "V2Vector": "AV:N/AC:L/Au:N/C:N/I:P/A:N",
                  "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                  "V2Score": 5,
                  "V3Score": 7.5
                },
                "redhat": {
                  "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",
                  "V3Score": 6.3
                }
              },
              "References": [
                "https://access.redhat.com/security/cve/CVE-2018-5709",
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-5709",
                "https://github.com/poojamnit/Kerberos-V5-1.16-Vulnerabilities/tree/master/Integer%20Overflow",
                "https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E"
              ],
              "PublishedDate": "2018-01-16T09:29:00Z",
              "LastModifiedDate": "2021-02-25T17:15:00Z"
            },
            {
              "VulnerabilityID": "CVE-2018-5709",
              "PkgName": "libk5crypto3",
              "InstalledVersion": "1.19.2-2",
              "Layer": {
                "Digest": "sha256:125a6e411906fe6b0aaa50fc9d600bf6ff9bb11a8651727ce1ed482dc271c24c",
                "DiffID": "sha256:e59fc94956120a6c7629f085027578e6357b48061d45714107e79f04a81a6f0c"
              },
              "SeveritySource": "ubuntu",
              "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2018-5709",
              "DataSource": {
                "ID": "ubuntu",
                "Name": "Ubuntu CVE Tracker",
                "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
              },
              "Title": "krb5: integer overflow in dbentry-\u003en_key_data in kadmin/dbutil/dump.c",
              "Description": "An issue was discovered in MIT Kerberos 5 (aka krb5) through 1.16. There is a variable \"dbentry-\u003en_key_data\" in kadmin/dbutil/dump.c that can store 16-bit data but unknowingly the developer has assigned a \"u4\" variable to it, which is for 32-bit data. An attacker can use this vulnerability to affect other artifacts of the database as we know that a Kerberos database dump file contains trusted data.",
              "Severity": "LOW",
              "CweIDs": [
                "CWE-190"
              ],
              "VendorSeverity": {
                "arch-linux": 2,
                "nvd": 3,
                "redhat": 2,
                "ubuntu": 1
              },
              "CVSS": {
                "nvd": {
                  "V2Vector": "AV:N/AC:L/Au:N/C:N/I:P/A:N",
                  "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                  "V2Score": 5,
                  "V3Score": 7.5
                },
                "redhat": {
                  "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",
                  "V3Score": 6.3
                }
              },
              "References": [
                "https://access.redhat.com/security/cve/CVE-2018-5709",
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-5709",
                "https://github.com/poojamnit/Kerberos-V5-1.16-Vulnerabilities/tree/master/Integer%20Overflow",
                "https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E"
              ],
              "PublishedDate": "2018-01-16T09:29:00Z",
              "LastModifiedDate": "2021-02-25T17:15:00Z"
            },
            {
              "VulnerabilityID": "CVE-2018-5709",
              "PkgName": "libkrb5-3",
              "InstalledVersion": "1.19.2-2",
              "Layer": {
                "Digest": "sha256:125a6e411906fe6b0aaa50fc9d600bf6ff9bb11a8651727ce1ed482dc271c24c",
                "DiffID": "sha256:e59fc94956120a6c7629f085027578e6357b48061d45714107e79f04a81a6f0c"
              },
              "SeveritySource": "ubuntu",
              "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2018-5709",
              "DataSource": {
                "ID": "ubuntu",
                "Name": "Ubuntu CVE Tracker",
                "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
              },
              "Title": "krb5: integer overflow in dbentry-\u003en_key_data in kadmin/dbutil/dump.c",
              "Description": "An issue was discovered in MIT Kerberos 5 (aka krb5) through 1.16. There is a variable \"dbentry-\u003en_key_data\" in kadmin/dbutil/dump.c that can store 16-bit data but unknowingly the developer has assigned a \"u4\" variable to it, which is for 32-bit data. An attacker can use this vulnerability to affect other artifacts of the database as we know that a Kerberos database dump file contains trusted data.",
              "Severity": "LOW",
              "CweIDs": [
                "CWE-190"
              ],
              "VendorSeverity": {
                "arch-linux": 2,
                "nvd": 3,
                "redhat": 2,
                "ubuntu": 1
              },
              "CVSS": {
                "nvd": {
                  "V2Vector": "AV:N/AC:L/Au:N/C:N/I:P/A:N",
                  "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                  "V2Score": 5,
                  "V3Score": 7.5
                },
                "redhat": {
                  "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",
                  "V3Score": 6.3
                }
              },
              "References": [
                "https://access.redhat.com/security/cve/CVE-2018-5709",
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-5709",
                "https://github.com/poojamnit/Kerberos-V5-1.16-Vulnerabilities/tree/master/Integer%20Overflow",
                "https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E"
              ],
              "PublishedDate": "2018-01-16T09:29:00Z",
              "LastModifiedDate": "2021-02-25T17:15:00Z"
            },
            {
              "VulnerabilityID": "CVE-2018-5709",
              "PkgName": "libkrb5support0",
              "InstalledVersion": "1.19.2-2",
              "Layer": {
                "Digest": "sha256:125a6e411906fe6b0aaa50fc9d600bf6ff9bb11a8651727ce1ed482dc271c24c",
                "DiffID": "sha256:e59fc94956120a6c7629f085027578e6357b48061d45714107e79f04a81a6f0c"
              },
              "SeveritySource": "ubuntu",
              "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2018-5709",
              "DataSource": {
                "ID": "ubuntu",
                "Name": "Ubuntu CVE Tracker",
                "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
              },
              "Title": "krb5: integer overflow in dbentry-\u003en_key_data in kadmin/dbutil/dump.c",
              "Description": "An issue was discovered in MIT Kerberos 5 (aka krb5) through 1.16. There is a variable \"dbentry-\u003en_key_data\" in kadmin/dbutil/dump.c that can store 16-bit data but unknowingly the developer has assigned a \"u4\" variable to it, which is for 32-bit data. An attacker can use this vulnerability to affect other artifacts of the database as we know that a Kerberos database dump file contains trusted data.",
              "Severity": "LOW",
              "CweIDs": [
                "CWE-190"
              ],
              "VendorSeverity": {
                "arch-linux": 2,
                "nvd": 3,
                "redhat": 2,
                "ubuntu": 1
              },
              "CVSS": {
                "nvd": {
                  "V2Vector": "AV:N/AC:L/Au:N/C:N/I:P/A:N",
                  "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                  "V2Score": 5,
                  "V3Score": 7.5
                },
                "redhat": {
                  "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",
                  "V3Score": 6.3
                }
              },
              "References": [
                "https://access.redhat.com/security/cve/CVE-2018-5709",
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-5709",
                "https://github.com/poojamnit/Kerberos-V5-1.16-Vulnerabilities/tree/master/Integer%20Overflow",
                "https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E"
              ],
              "PublishedDate": "2018-01-16T09:29:00Z",
              "LastModifiedDate": "2021-02-25T17:15:00Z"
            },
            {
              "VulnerabilityID": "CVE-2017-11164",
              "PkgName": "libpcre3",
              "InstalledVersion": "2:8.39-13build5",
              "Layer": {
                "Digest": "sha256:125a6e411906fe6b0aaa50fc9d600bf6ff9bb11a8651727ce1ed482dc271c24c",
                "DiffID": "sha256:e59fc94956120a6c7629f085027578e6357b48061d45714107e79f04a81a6f0c"
              },
              "SeveritySource": "ubuntu",
              "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2017-11164",
              "DataSource": {
                "ID": "ubuntu",
                "Name": "Ubuntu CVE Tracker",
                "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
              },
              "Title": "pcre: OP_KETRMAX feature in the match function in pcre_exec.c",
              "Description": "In PCRE 8.41, the OP_KETRMAX feature in the match function in pcre_exec.c allows stack exhaustion (uncontrolled recursion) when processing a crafted regular expression.",
              "Severity": "LOW",
              "CweIDs": [
                "CWE-674"
              ],
              "VendorSeverity": {
                "arch-linux": 1,
                "nvd": 3,
                "photon": 3,
                "redhat": 1,
                "ubuntu": 1
              },
              "CVSS": {
                "nvd": {
                  "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:C",
                  "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                  "V2Score": 7.8,
                  "V3Score": 7.5
                },
                "redhat": {
                  "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L",
                  "V3Score": 3.3
                }
              },
              "References": [
                "http://openwall.com/lists/oss-security/2017/07/11/3",
                "http://www.securityfocus.com/bid/99575",
                "https://access.redhat.com/security/cve/CVE-2017-11164",
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-11164",
                "https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E"
              ],
              "PublishedDate": "2017-07-11T03:29:00Z",
              "LastModifiedDate": "2021-02-25T17:15:00Z"
            },
            {
              "VulnerabilityID": "CVE-2019-20838",
              "PkgName": "libpcre3",
              "InstalledVersion": "2:8.39-13build5",
              "Layer": {
                "Digest": "sha256:125a6e411906fe6b0aaa50fc9d600bf6ff9bb11a8651727ce1ed482dc271c24c",
                "DiffID": "sha256:e59fc94956120a6c7629f085027578e6357b48061d45714107e79f04a81a6f0c"
              },
              "SeveritySource": "ubuntu",
              "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-20838",
              "DataSource": {
                "ID": "ubuntu",
                "Name": "Ubuntu CVE Tracker",
                "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
              },
              "Title": "pcre: Buffer over-read in JIT when UTF is disabled and \\X or \\R has fixed quantifier greater than 1",
              "Description": "libpcre in PCRE before 8.43 allows a subject buffer over-read in JIT when UTF is disabled, and \\X or \\R has more than one fixed quantifier, a related issue to CVE-2019-20454.",
              "Severity": "LOW",
              "CweIDs": [
                "CWE-125"
              ],
              "VendorSeverity": {
                "alma": 1,
                "cbl-mariner": 3,
                "nvd": 3,
                "oracle-oval": 1,
                "photon": 3,
                "redhat": 1,
                "ubuntu": 1
              },
              "CVSS": {
                "nvd": {
                  "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
                  "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                  "V2Score": 4.3,
                  "V3Score": 7.5
                },
                "redhat": {
                  "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                  "V3Score": 7.5
                }
              },
              "References": [
                "http://seclists.org/fulldisclosure/2020/Dec/32",
                "http://seclists.org/fulldisclosure/2021/Feb/14",
                "https://access.redhat.com/security/cve/CVE-2019-20838",
                "https://bugs.gentoo.org/717920",
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-20838",
                "https://linux.oracle.com/cve/CVE-2019-20838.html",
                "https://linux.oracle.com/errata/ELSA-2021-4373.html",
                "https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E",
                "https://nvd.nist.gov/vuln/detail/CVE-2019-20838",
                "https://support.apple.com/kb/HT211931",
                "https://support.apple.com/kb/HT212147",
                "https://www.pcre.org/original/changelog.txt"
              ],
              "PublishedDate": "2020-06-15T17:15:00Z",
              "LastModifiedDate": "2021-09-22T14:22:00Z"
            },
            {
              "VulnerabilityID": "CVE-2022-1304",
              "PkgName": "libss2",
              "InstalledVersion": "1.46.5-2ubuntu1",
              "Layer": {
                "Digest": "sha256:125a6e411906fe6b0aaa50fc9d600bf6ff9bb11a8651727ce1ed482dc271c24c",
                "DiffID": "sha256:e59fc94956120a6c7629f085027578e6357b48061d45714107e79f04a81a6f0c"
              },
              "SeveritySource": "ubuntu",
              "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2022-1304",
              "DataSource": {
                "ID": "ubuntu",
                "Name": "Ubuntu CVE Tracker",
                "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
              },
              "Title": "e2fsprogs: out-of-bounds read/write via crafted filesystem",
              "Description": "An out-of-bounds read/write vulnerability was found in e2fsprogs 1.46.5. This issue leads to a segmentation fault and possibly arbitrary code execution via a specially crafted filesystem.",
              "Severity": "MEDIUM",
              "CweIDs": [
                "CWE-125",
                "CWE-787"
              ],
              "VendorSeverity": {
                "cbl-mariner": 3,
                "nvd": 3,
                "redhat": 2,
                "ubuntu": 2
              },
              "CVSS": {
                "nvd": {
                  "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
                  "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                  "V2Score": 6.8,
                  "V3Score": 7.8
                },
                "redhat": {
                  "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H",
                  "V3Score": 7
                }
              },
              "References": [
                "https://access.redhat.com/security/cve/CVE-2022-1304",
                "https://bugzilla.redhat.com/show_bug.cgi?id=2069726",
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1304",
                "https://marc.info/?l=linux-ext4\u0026m=165056234501732\u0026w=2",
                "https://nvd.nist.gov/vuln/detail/CVE-2022-1304"
              ],
              "PublishedDate": "2022-04-14T21:15:00Z",
              "LastModifiedDate": "2022-04-21T15:36:00Z"
            },
            {
              "VulnerabilityID": "CVE-2022-1292",
              "PkgName": "libssl3",
              "InstalledVersion": "3.0.2-0ubuntu1",
              "FixedVersion": "3.0.2-0ubuntu1.1",
              "Layer": {
                "Digest": "sha256:125a6e411906fe6b0aaa50fc9d600bf6ff9bb11a8651727ce1ed482dc271c24c",
                "DiffID": "sha256:e59fc94956120a6c7629f085027578e6357b48061d45714107e79f04a81a6f0c"
              },
              "SeveritySource": "ubuntu",
              "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2022-1292",
              "DataSource": {
                "ID": "ubuntu",
                "Name": "Ubuntu CVE Tracker",
                "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
              },
              "Title": "openssl: c_rehash script allows command injection",
              "Description": "The c_rehash script does not properly sanitise shell metacharacters to prevent command injection. This script is distributed by some operating systems in a manner where it is automatically executed. On such operating systems, an attacker could execute arbitrary commands with the privileges of the script. Use of the c_rehash script is considered obsolete and should be replaced by the OpenSSL rehash command line tool. Fixed in OpenSSL 3.0.3 (Affected 3.0.0,3.0.1,3.0.2). Fixed in OpenSSL 1.1.1o (Affected 1.1.1-1.1.1n). Fixed in OpenSSL 1.0.2ze (Affected 1.0.2-1.0.2zd).",
              "Severity": "MEDIUM",
              "VendorSeverity": {
                "arch-linux": 2,
                "redhat": 2,
                "ubuntu": 2
              },
              "CVSS": {
                "redhat": {
                  "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",
                  "V3Score": 6.3
                }
              },
              "References": [
                "https://access.redhat.com/security/cve/CVE-2022-1292",
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1292",
                "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=1ad73b4d27bd8c1b369a3cd453681d3a4f1bb9b2",
                "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=548d3f280a6e737673f5b61fce24bb100108dfeb",
                "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=e5fd1728ef4c7a5bf7c7a7163ca60370460a6e23",
                "https://mta.openssl.org/pipermail/openssl-announce/2022-May/000224.html",
                "https://ubuntu.com/security/notices/USN-5402-1",
                "https://www.openssl.org/news/secadv/20220503.txt"
              ],
              "PublishedDate": "2022-05-03T16:15:00Z",
              "LastModifiedDate": "2022-05-03T19:52:00Z"
            },
            {
              "VulnerabilityID": "CVE-2022-1343",
              "PkgName": "libssl3",
              "InstalledVersion": "3.0.2-0ubuntu1",
              "FixedVersion": "3.0.2-0ubuntu1.1",
              "Layer": {
                "Digest": "sha256:125a6e411906fe6b0aaa50fc9d600bf6ff9bb11a8651727ce1ed482dc271c24c",
                "DiffID": "sha256:e59fc94956120a6c7629f085027578e6357b48061d45714107e79f04a81a6f0c"
              },
              "SeveritySource": "ubuntu",
              "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2022-1343",
              "DataSource": {
                "ID": "ubuntu",
                "Name": "Ubuntu CVE Tracker",
                "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
              },
              "Description": "The function `OCSP_basic_verify` verifies the signer certificate on an OCSP response. In the case where the (non-default) flag OCSP_NOCHECKS is used then the response will be positive (meaning a successful verification) even in the case where the response signing certificate fails to verify. It is anticipated that most users of `OCSP_basic_verify` will not use the OCSP_NOCHECKS flag. In this case the `OCSP_basic_verify` function will return a negative value (indicating a fatal error) in the case of a certificate verification failure. The normal expected return value in this case would be 0. This issue also impacts the command line OpenSSL \"ocsp\" application. When verifying an ocsp response with the \"-no_cert_checks\" option the command line application will report that the verification is successful even though it has in fact failed. In this case the incorrect successful response will also be accompanied by error messages showing the failure and contradicting the apparently successful result. Fixed in OpenSSL 3.0.3 (Affected 3.0.0,3.0.1,3.0.2).",
              "Severity": "MEDIUM",
              "VendorSeverity": {
                "ubuntu": 2
              },
              "References": [
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1343",
                "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=2eda98790c5c2741d76d23cc1e74b0dc4f4b391a",
                "https://mta.openssl.org/pipermail/openssl-announce/2022-May/000224.html",
                "https://ubuntu.com/security/notices/USN-5402-1",
                "https://www.openssl.org/news/secadv/20220503.txt"
              ],
              "PublishedDate": "2022-05-03T16:15:00Z",
              "LastModifiedDate": "2022-05-03T19:52:00Z"
            },
            {
              "VulnerabilityID": "CVE-2022-1434",
              "PkgName": "libssl3",
              "InstalledVersion": "3.0.2-0ubuntu1",
              "FixedVersion": "3.0.2-0ubuntu1.1",
              "Layer": {
                "Digest": "sha256:125a6e411906fe6b0aaa50fc9d600bf6ff9bb11a8651727ce1ed482dc271c24c",
                "DiffID": "sha256:e59fc94956120a6c7629f085027578e6357b48061d45714107e79f04a81a6f0c"
              },
              "SeveritySource": "ubuntu",
              "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2022-1434",
              "DataSource": {
                "ID": "ubuntu",
                "Name": "Ubuntu CVE Tracker",
                "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
              },
              "Description": "The OpenSSL 3.0 implementation of the RC4-MD5 ciphersuite incorrectly uses the AAD data as the MAC key. This makes the MAC key trivially predictable. An attacker could exploit this issue by performing a man-in-the-middle attack to modify data being sent from one endpoint to an OpenSSL 3.0 recipient such that the modified data would still pass the MAC integrity check. Note that data sent from an OpenSSL 3.0 endpoint to a non-OpenSSL 3.0 endpoint will always be rejected by the recipient and the connection will fail at that point. Many application protocols require data to be sent from the client to the server first. Therefore, in such a case, only an OpenSSL 3.0 server would be impacted when talking to a non-OpenSSL 3.0 client. If both endpoints are OpenSSL 3.0 then the attacker could modify data being sent in both directions. In this case both clients and servers could be affected, regardless of the application protocol. Note that in the absence of an attacker this bug means that an OpenSSL 3.0 endpoint communicating with a non-OpenSSL 3.0 endpoint will fail to complete the handshake when using this ciphersuite. The confidentiality of data is not impacted by this issue, i.e. an attacker cannot decrypt data that has been encrypted using this ciphersuite - they can only modify it. In order for this attack to work both endpoints must legitimately negotiate the RC4-MD5 ciphersuite. This ciphersuite is not compiled by default in OpenSSL 3.0, and is not available within the default provider or the default ciphersuite list. This ciphersuite will never be used if TLSv1.3 has been negotiated. In order for an OpenSSL 3.0 endpoint to use this ciphersuite the following must have occurred: 1) OpenSSL must have been compiled with the (non-default) compile time option enable-weak-ssl-ciphers 2) OpenSSL must have had the legacy provider explicitly loaded (either through application code or via configuration) 3) The ciphersuite must have been explicitly added to the ciphersuite list 4) The libssl security level must have been set to 0 (default is 1) 5) A version of SSL/TLS below TLSv1.3 must have been negotiated 6) Both endpoints must negotiate the RC4-MD5 ciphersuite in preference to any others that both endpoints have in common Fixed in OpenSSL 3.0.3 (Affected 3.0.0,3.0.1,3.0.2).",
              "Severity": "LOW",
              "VendorSeverity": {
                "ubuntu": 1
              },
              "References": [
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1434",
                "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=7d56a74a96828985db7354a55227a511615f732b",
                "https://mta.openssl.org/pipermail/openssl-announce/2022-May/000224.html",
                "https://ubuntu.com/security/notices/USN-5402-1",
                "https://www.openssl.org/news/secadv/20220503.txt"
              ],
              "PublishedDate": "2022-05-03T16:15:00Z",
              "LastModifiedDate": "2022-05-03T19:52:00Z"
            },
            {
              "VulnerabilityID": "CVE-2022-1473",
              "PkgName": "libssl3",
              "InstalledVersion": "3.0.2-0ubuntu1",
              "FixedVersion": "3.0.2-0ubuntu1.1",
              "Layer": {
                "Digest": "sha256:125a6e411906fe6b0aaa50fc9d600bf6ff9bb11a8651727ce1ed482dc271c24c",
                "DiffID": "sha256:e59fc94956120a6c7629f085027578e6357b48061d45714107e79f04a81a6f0c"
              },
              "SeveritySource": "ubuntu",
              "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2022-1473",
              "DataSource": {
                "ID": "ubuntu",
                "Name": "Ubuntu CVE Tracker",
                "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
              },
              "Description": "The OPENSSL_LH_flush() function, which empties a hash table, contains a bug that breaks reuse of the memory occuppied by the removed hash table entries. This function is used when decoding certificates or keys. If a long lived process periodically decodes certificates or keys its memory usage will expand without bounds and the process might be terminated by the operating system causing a denial of service. Also traversing the empty hash table entries will take increasingly more time. Typically such long lived processes might be TLS clients or TLS servers configured to accept client certificate authentication. The function was added in the OpenSSL 3.0 version thus older releases are not affected by the issue. Fixed in OpenSSL 3.0.3 (Affected 3.0.0,3.0.1,3.0.2).",
              "Severity": "LOW",
              "VendorSeverity": {
                "ubuntu": 1
              },
              "References": [
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1473",
                "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=64c85430f95200b6b51fe9475bd5203f7c19daf1",
                "https://mta.openssl.org/pipermail/openssl-announce/2022-May/000224.html",
                "https://ubuntu.com/security/notices/USN-5402-1",
                "https://www.openssl.org/news/secadv/20220503.txt"
              ],
              "PublishedDate": "2022-05-03T16:15:00Z",
              "LastModifiedDate": "2022-05-03T19:52:00Z"
            },
            {
              "VulnerabilityID": "CVE-2013-4235",
              "PkgName": "login",
              "InstalledVersion": "1:4.8.1-2ubuntu2",
              "Layer": {
                "Digest": "sha256:125a6e411906fe6b0aaa50fc9d600bf6ff9bb11a8651727ce1ed482dc271c24c",
                "DiffID": "sha256:e59fc94956120a6c7629f085027578e6357b48061d45714107e79f04a81a6f0c"
              },
              "SeveritySource": "ubuntu",
              "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2013-4235",
              "DataSource": {
                "ID": "ubuntu",
                "Name": "Ubuntu CVE Tracker",
                "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
              },
              "Title": "shadow-utils: TOCTOU race conditions by copying and removing directory trees",
              "Description": "shadow: TOCTOU (time-of-check time-of-use) race condition when copying and removing directory trees",
              "Severity": "LOW",
              "CweIDs": [
                "CWE-367"
              ],
              "VendorSeverity": {
                "nvd": 2,
                "redhat": 1,
                "ubuntu": 1
              },
              "CVSS": {
                "nvd": {
                  "V2Vector": "AV:L/AC:M/Au:N/C:N/I:P/A:P",
                  "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N",
                  "V2Score": 3.3,
                  "V3Score": 4.7
                },
                "redhat": {
                  "V2Vector": "AV:L/AC:H/Au:N/C:P/I:P/A:P",
                  "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:N/I:H/A:N",
                  "V2Score": 3.7,
                  "V3Score": 4.4
                }
              },
              "References": [
                "https://access.redhat.com/security/cve/CVE-2013-4235",
                "https://access.redhat.com/security/cve/cve-2013-4235",
                "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2013-4235",
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-4235",
                "https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E",
                "https://security-tracker.debian.org/tracker/CVE-2013-4235"
              ],
              "PublishedDate": "2019-12-03T15:15:00Z",
              "LastModifiedDate": "2021-02-25T17:15:00Z"
            },
            {
              "VulnerabilityID": "CVE-2022-1304",
              "PkgName": "logsave",
              "InstalledVersion": "1.46.5-2ubuntu1",
              "Layer": {
                "Digest": "sha256:125a6e411906fe6b0aaa50fc9d600bf6ff9bb11a8651727ce1ed482dc271c24c",
                "DiffID": "sha256:e59fc94956120a6c7629f085027578e6357b48061d45714107e79f04a81a6f0c"
              },
              "SeveritySource": "ubuntu",
              "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2022-1304",
              "DataSource": {
                "ID": "ubuntu",
                "Name": "Ubuntu CVE Tracker",
                "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
              },
              "Title": "e2fsprogs: out-of-bounds read/write via crafted filesystem",
              "Description": "An out-of-bounds read/write vulnerability was found in e2fsprogs 1.46.5. This issue leads to a segmentation fault and possibly arbitrary code execution via a specially crafted filesystem.",
              "Severity": "MEDIUM",
              "CweIDs": [
                "CWE-125",
                "CWE-787"
              ],
              "VendorSeverity": {
                "cbl-mariner": 3,
                "nvd": 3,
                "redhat": 2,
                "ubuntu": 2
              },
              "CVSS": {
                "nvd": {
                  "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
                  "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                  "V2Score": 6.8,
                  "V3Score": 7.8
                },
                "redhat": {
                  "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H",
                  "V3Score": 7
                }
              },
              "References": [
                "https://access.redhat.com/security/cve/CVE-2022-1304",
                "https://bugzilla.redhat.com/show_bug.cgi?id=2069726",
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1304",
                "https://marc.info/?l=linux-ext4\u0026m=165056234501732\u0026w=2",
                "https://nvd.nist.gov/vuln/detail/CVE-2022-1304"
              ],
              "PublishedDate": "2022-04-14T21:15:00Z",
              "LastModifiedDate": "2022-04-21T15:36:00Z"
            },
            {
              "VulnerabilityID": "CVE-2013-4235",
              "PkgName": "passwd",
              "InstalledVersion": "1:4.8.1-2ubuntu2",
              "Layer": {
                "Digest": "sha256:125a6e411906fe6b0aaa50fc9d600bf6ff9bb11a8651727ce1ed482dc271c24c",
                "DiffID": "sha256:e59fc94956120a6c7629f085027578e6357b48061d45714107e79f04a81a6f0c"
              },
              "SeveritySource": "ubuntu",
              "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2013-4235",
              "DataSource": {
                "ID": "ubuntu",
                "Name": "Ubuntu CVE Tracker",
                "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
              },
              "Title": "shadow-utils: TOCTOU race conditions by copying and removing directory trees",
              "Description": "shadow: TOCTOU (time-of-check time-of-use) race condition when copying and removing directory trees",
              "Severity": "LOW",
              "CweIDs": [
                "CWE-367"
              ],
              "VendorSeverity": {
                "nvd": 2,
                "redhat": 1,
                "ubuntu": 1
              },
              "CVSS": {
                "nvd": {
                  "V2Vector": "AV:L/AC:M/Au:N/C:N/I:P/A:P",
                  "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N",
                  "V2Score": 3.3,
                  "V3Score": 4.7
                },
                "redhat": {
                  "V2Vector": "AV:L/AC:H/Au:N/C:P/I:P/A:P",
                  "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:N/I:H/A:N",
                  "V2Score": 3.7,
                  "V3Score": 4.4
                }
              },
              "References": [
                "https://access.redhat.com/security/cve/CVE-2013-4235",
                "https://access.redhat.com/security/cve/cve-2013-4235",
                "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2013-4235",
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-4235",
                "https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E",
                "https://security-tracker.debian.org/tracker/CVE-2013-4235"
              ],
              "PublishedDate": "2019-12-03T15:15:00Z",
              "LastModifiedDate": "2021-02-25T17:15:00Z"
            },
            {
              "VulnerabilityID": "CVE-2020-16156",
              "PkgName": "perl-base",
              "InstalledVersion": "5.34.0-3ubuntu1",
              "Layer": {
                "Digest": "sha256:125a6e411906fe6b0aaa50fc9d600bf6ff9bb11a8651727ce1ed482dc271c24c",
                "DiffID": "sha256:e59fc94956120a6c7629f085027578e6357b48061d45714107e79f04a81a6f0c"
              },
              "SeveritySource": "ubuntu",
              "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-16156",
              "DataSource": {
                "ID": "ubuntu",
                "Name": "Ubuntu CVE Tracker",
                "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
              },
              "Title": "perl-CPAN: Bypass of verification of signatures in CHECKSUMS files",
              "Description": "CPAN 2.28 allows Signature Verification Bypass.",
              "Severity": "MEDIUM",
              "CweIDs": [
                "CWE-347"
              ],
              "VendorSeverity": {
                "arch-linux": 2,
                "nvd": 3,
                "redhat": 2,
                "ubuntu": 2
              },
              "CVSS": {
                "nvd": {
                  "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
                  "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                  "V2Score": 6.8,
                  "V3Score": 7.8
                },
                "redhat": {
                  "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                  "V3Score": 7.8
                }
              },
              "References": [
                "http://blogs.perl.org/users/neilb/2021/11/addressing-cpan-vulnerabilities-related-to-checksums.html",
                "https://access.redhat.com/security/cve/CVE-2020-16156",
                "https://blog.hackeriet.no/cpan-signature-verification-vulnerabilities/",
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-16156",
                "https://github.com/andk/cpanpm/commit/b27c51adf0fda25dee84cb72cb2b1bf7d832148c",
                "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/SD6RYOJII7HRJ6WVORFNVTYNOFY5JDXN/",
                "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/SZ32AJIV4RHJMLWLU5QULGKMMIHYOMDC/",
                "https://metacpan.org/pod/distribution/CPAN/scripts/cpan"
              ],
              "PublishedDate": "2021-12-13T18:15:00Z",
              "LastModifiedDate": "2022-04-01T13:26:00Z"
            },
            {
              "VulnerabilityID": "CVE-2019-9923",
              "PkgName": "tar",
              "InstalledVersion": "1.34+dfsg-1build3",
              "Layer": {
                "Digest": "sha256:125a6e411906fe6b0aaa50fc9d600bf6ff9bb11a8651727ce1ed482dc271c24c",
                "DiffID": "sha256:e59fc94956120a6c7629f085027578e6357b48061d45714107e79f04a81a6f0c"
              },
              "SeveritySource": "ubuntu",
              "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-9923",
              "DataSource": {
                "ID": "ubuntu",
                "Name": "Ubuntu CVE Tracker",
                "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
              },
              "Title": "tar: null-pointer dereference in pax_decode_header in sparse.c",
              "Description": "pax_decode_header in sparse.c in GNU Tar before 1.32 had a NULL pointer dereference when parsing certain archives that have malformed extended headers.",
              "Severity": "LOW",
              "CweIDs": [
                "CWE-476"
              ],
              "VendorSeverity": {
                "nvd": 3,
                "photon": 3,
                "redhat": 1,
                "ubuntu": 1
              },
              "CVSS": {
                "nvd": {
                  "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
                  "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                  "V2Score": 5,
                  "V3Score": 7.5
                },
                "redhat": {
                  "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L",
                  "V3Score": 3.3
                }
              },
              "References": [
                "http://git.savannah.gnu.org/cgit/tar.git/commit/?id=cb07844454d8cc9fb21f53ace75975f91185a120",
                "http://lists.opensuse.org/opensuse-security-announce/2019-04/msg00077.html",
                "http://savannah.gnu.org/bugs/?55369",
                "https://access.redhat.com/security/cve/CVE-2019-9923",
                "https://bugs.launchpad.net/ubuntu/+source/tar/+bug/1810241",
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9923",
                "https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E",
                "https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E",
                "https://ubuntu.com/security/notices/USN-4692-1"
              ],
              "PublishedDate": "2019-03-22T08:29:00Z",
              "LastModifiedDate": "2021-06-29T15:15:00Z"
            }
          ]
        }
      ]
    }
  ],
  "Misconfigurations": [
    {
      "Namespace": "default",
      "Kind": "Deployment",
      "Name": "app",
      "Results": [
        {
          "Target": "Deployment/app",
          "Class": "config",
          "Type": "kubernetes",
          "MisconfSummary": {
            "Successes": 20,
            "Failures": 19,
            "Exceptions": 0
          },
          "Misconfigurations": [
            {
              "Type": "Kubernetes Security Check",
              "ID": "KSV001",
              "Title": "Process can elevate its own privileges",
              "Description": "A program inside the container can elevate its own privileges and run as root, which might give the program control over the container and node.",
              "Message": "Container 'app' of Deployment 'app' should set 'securityContext.allowPrivilegeEscalation' to false",
              "Namespace": "builtin.kubernetes.KSV001",
              "Query": "data.builtin.kubernetes.KSV001.deny",
              "Resolution": "Set 'set containers[].securityContext.allowPrivilegeEscalation' to 'false'.",
              "Severity": "MEDIUM",
              "PrimaryURL": "https://avd.aquasec.com/misconfig/ksv001",
              "References": [
                "https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted",
                "https://avd.aquasec.com/misconfig/ksv001"
              ],
              "Status": "FAIL",
              "Layer": {},
              "IacMetadata": {
                "Provider": "Kubernetes",
                "Service": "general",
                "StartLine": 121,
                "EndLine": 133
              }
            },
            {
              "Type": "Kubernetes Security Check",
              "ID": "KSV003",
              "Title": "Default capabilities not dropped",
              "Description": "The container should drop all default capabilities and add only those that are needed for its execution.",
              "Message": "Container 'app' of Deployment 'app' should add 'ALL' to 'securityContext.capabilities.drop'",
              "Namespace": "builtin.kubernetes.KSV003",
              "Query": "data.builtin.kubernetes.KSV003.deny",
              "Resolution": "Add 'ALL' to containers[].securityContext.capabilities.drop.",
              "Severity": "LOW",
              "PrimaryURL": "https://avd.aquasec.com/misconfig/ksv003",
              "References": [
                "https://kubesec.io/basics/containers-securitycontext-capabilities-drop-index-all/",
                "https://avd.aquasec.com/misconfig/ksv003"
              ],
              "Status": "FAIL",
              "Layer": {},
              "IacMetadata": {
                "Provider": "Kubernetes",
                "Service": "general",
                "StartLine": 121,
                "EndLine": 133
              }
            },
            {
              "Type": "Kubernetes Security Check",
              "ID": "KSV004",
              "Title": "Unused capabilities should be dropped (drop any)",
              "Description": "Security best practices require containers to run with minimal required capabilities.",
              "Message": "Container 'app' of 'deployment' 'app' in 'default' namespace should set securityContext.capabilities.drop",
              "Namespace": "builtin.kubernetes.KSV004",
              "Query": "data.builtin.kubernetes.KSV004.deny",
              "Resolution": "Specify at least one unneeded capability in 'containers[].securityContext.capabilities.drop'",
              "Severity": "LOW",
              "PrimaryURL": "https://avd.aquasec.com/misconfig/ksv004",
              "References": [
                "https://kubesec.io/basics/containers-securitycontext-capabilities-drop-index-all/",
                "https://avd.aquasec.com/misconfig/ksv004"
              ],
              "Status": "FAIL",
              "Layer": {},
              "IacMetadata": {
                "Provider": "Kubernetes",
                "Service": "general",
                "StartLine": 121,
                "EndLine": 133
              }
            },
            {
              "Type": "Kubernetes Security Check",
              "ID": "KSV011",
              "Title": "CPU not limited",
              "Description": "Enforcing CPU limits prevents DoS via resource exhaustion.",
              "Message": "Container 'app' of Deployment 'app' should set 'resources.limits.cpu'",
              "Namespace": "builtin.kubernetes.KSV011",
              "Query": "data.builtin.kubernetes.KSV011.deny",
              "Resolution": "Set a limit value under 'containers[].resources.limits.cpu'.",
              "Severity": "LOW",
              "PrimaryURL": "https://avd.aquasec.com/misconfig/ksv011",
              "References": [
                "https://cloud.google.com/blog/products/containers-kubernetes/kubernetes-best-practices-resource-requests-and-limits",
                "https://avd.aquasec.com/misconfig/ksv011"
              ],
              "Status": "FAIL",
              "Layer": {},
              "IacMetadata": {
                "Provider": "Kubernetes",
                "Service": "general",
                "StartLine": 121,
                "EndLine": 133
              }
            },
            {
              "Type": "Kubernetes Security Check",
              "ID": "KSV012",
              "Title": "Runs as root user",
              "Description": "'runAsNonRoot' forces the running image to run as a non-root user to ensure least privileges.",
              "Message": "Container 'app' of Deployment 'app' should set 'securityContext.runAsNonRoot' to true",
              "Namespace": "builtin.kubernetes.KSV012",
              "Query": "data.builtin.kubernetes.KSV012.deny",
              "Resolution": "Set 'containers[].securityContext.runAsNonRoot' to true.",
              "Severity": "MEDIUM",
              "PrimaryURL": "https://avd.aquasec.com/misconfig/ksv012",
              "References": [
                "https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted",
                "https://avd.aquasec.com/misconfig/ksv012"
              ],
              "Status": "FAIL",
              "Layer": {},
              "IacMetadata": {
                "Provider": "Kubernetes",
                "Service": "general",
                "StartLine": 121,
                "EndLine": 133
              }
            },
            {
              "Type": "Kubernetes Security Check",
              "ID": "KSV013",
              "Title": "Image tag ':latest' used",
              "Description": "It is best to avoid using the ':latest' image tag when deploying containers in production. Doing so makes it hard to track which version of the image is running, and hard to roll back the version.",
              "Message": "Container 'app' of Deployment 'app' should specify an image tag",
              "Namespace": "builtin.kubernetes.KSV013",
              "Query": "data.builtin.kubernetes.KSV013.deny",
              "Resolution": "Use a specific container image tag that is not 'latest'.",
              "Severity": "MEDIUM",
              "PrimaryURL": "https://avd.aquasec.com/misconfig/ksv013",
              "References": [
                "https://kubernetes.io/docs/concepts/configuration/overview/#container-images",
                "https://avd.aquasec.com/misconfig/ksv013"
              ],
              "Status": "FAIL",
              "Layer": {},
              "IacMetadata": {
                "Provider": "Kubernetes",
                "Service": "general",
                "StartLine": 121,
                "EndLine": 133
              }
            },
            {
              "Type": "Kubernetes Security Check",
              "ID": "KSV014",
              "Title": "Root file system is not read-only",
              "Description": "An immutable root file system prevents applications from writing to their local disk. This can limit intrusions, as attackers will not be able to tamper with the file system or write foreign executables to disk.",
              "Message": "Container 'app' of Deployment 'app' should set 'securityContext.readOnlyRootFilesystem' to true",
              "Namespace": "builtin.kubernetes.KSV014",
              "Query": "data.builtin.kubernetes.KSV014.deny",
              "Resolution": "Change 'containers[].securityContext.readOnlyRootFilesystem' to 'true'.",
              "Severity": "LOW",
              "PrimaryURL": "https://avd.aquasec.com/misconfig/ksv014",
              "References": [
                "https://kubesec.io/basics/containers-securitycontext-readonlyrootfilesystem-true/",
                "https://avd.aquasec.com/misconfig/ksv014"
              ],
              "Status": "FAIL",
              "Layer": {},
              "IacMetadata": {
                "Provider": "Kubernetes",
                "Service": "general",
                "StartLine": 121,
                "EndLine": 133
              }
            },
            {
              "Type": "Kubernetes Security Check",
              "ID": "KSV015",
              "Title": "CPU requests not specified",
              "Description": "When containers have resource requests specified, the scheduler can make better decisions about which nodes to place pods on, and how to deal with resource contention.",
              "Message": "Container 'app' of Deployment 'app' should set 'resources.requests.cpu'",
              "Namespace": "builtin.kubernetes.KSV015",
              "Query": "data.builtin.kubernetes.KSV015.deny",
              "Resolution": "Set 'containers[].resources.requests.cpu'.",
              "Severity": "LOW",
              "PrimaryURL": "https://avd.aquasec.com/misconfig/ksv015",
              "References": [
                "https://cloud.google.com/blog/products/containers-kubernetes/kubernetes-best-practices-resource-requests-and-limits",
                "https://avd.aquasec.com/misconfig/ksv015"
              ],
              "Status": "FAIL",
              "Layer": {},
              "IacMetadata": {
                "Provider": "Kubernetes",
                "Service": "general",
                "StartLine": 121,
                "EndLine": 133
              }
            },
            {
              "Type": "Kubernetes Security Check",
              "ID": "KSV016",
              "Title": "Memory requests not specified",
              "Description": "When containers have memory requests specified, the scheduler can make better decisions about which nodes to place pods on, and how to deal with resource contention.",
              "Message": "Container 'app' of Deployment 'app' should set 'resources.requests.memory'",
              "Namespace": "builtin.kubernetes.KSV016",
              "Query": "data.builtin.kubernetes.KSV016.deny",
              "Resolution": "Set 'containers[].resources.requests.memory'.",
              "Severity": "LOW",
              "PrimaryURL": "https://avd.aquasec.com/misconfig/ksv016",
              "References": [
                "https://kubesec.io/basics/containers-resources-limits-memory/",
                "https://avd.aquasec.com/misconfig/ksv016"
              ],
              "Status": "FAIL",
              "Layer": {},
              "IacMetadata": {
                "Provider": "Kubernetes",
                "Service": "general",
                "StartLine": 121,
                "EndLine": 133
              }
            },
            {
              "Type": "Kubernetes Security Check",
              "ID": "KSV018",
              "Title": "Memory not limited",
              "Description": "Enforcing memory limits prevents DoS via resource exhaustion.",
              "Message": "Container 'app' of Deployment 'app' should set 'resources.limits.memory'",
              "Namespace": "builtin.kubernetes.KSV018",
              "Query": "data.builtin.kubernetes.KSV018.deny",
              "Resolution": "Set a limit value under 'containers[].resources.limits.memory'.",
              "Severity": "LOW",
              "PrimaryURL": "https://avd.aquasec.com/misconfig/ksv018",
              "References": [
                "https://kubesec.io/basics/containers-resources-limits-memory/",
                "https://avd.aquasec.com/misconfig/ksv018"
              ],
              "Status": "FAIL",
              "Layer": {},
              "IacMetadata": {
                "Provider": "Kubernetes",
                "Service": "general",
                "StartLine": 121,
                "EndLine": 133
              }
            },
            {
              "Type": "Kubernetes Security Check",
              "ID": "KSV020",
              "Title": "Runs with low user ID",
              "Description": "Force the container to run with user ID \u003e 10000 to avoid conflicts with the host’s user table.",
              "Message": "Container 'app' of Deployment 'app' should set 'securityContext.runAsUser' \u003e 10000",
              "Namespace": "builtin.kubernetes.KSV020",
              "Query": "data.builtin.kubernetes.KSV020.deny",
              "Resolution": "Set 'containers[].securityContext.runAsUser' to an integer \u003e 10000.",
              "Severity": "LOW",
              "PrimaryURL": "https://avd.aquasec.com/misconfig/ksv020",
              "References": [
                "https://kubesec.io/basics/containers-securitycontext-runasuser/",
                "https://avd.aquasec.com/misconfig/ksv020"
              ],
              "Status": "FAIL",
              "Layer": {},
              "IacMetadata": {
                "Provider": "Kubernetes",
                "Service": "general",
                "StartLine": 121,
                "EndLine": 133
              }
            },
            {
              "Type": "Kubernetes Security Check",
              "ID": "KSV021",
              "Title": "Runs with low group ID",
              "Description": "Force the container to run with group ID \u003e 10000 to avoid conflicts with the host’s user table.",
              "Message": "Container 'app' of Deployment 'app' should set 'securityContext.runAsGroup' \u003e 10000",
              "Namespace": "builtin.kubernetes.KSV021",
              "Query": "data.builtin.kubernetes.KSV021.deny",
              "Resolution": "Set 'containers[].securityContext.runAsGroup' to an integer \u003e 10000.",
              "Severity": "LOW",
              "PrimaryURL": "https://avd.aquasec.com/misconfig/ksv021",
              "References": [
                "https://kubesec.io/basics/containers-securitycontext-runasuser/",
                "https://avd.aquasec.com/misconfig/ksv021"
              ],
              "Status": "FAIL",
              "Layer": {},
              "IacMetadata": {
                "Provider": "Kubernetes",
                "Service": "general",
                "StartLine": 121,
                "EndLine": 133
              }
            },
            {
              "Type": "Kubernetes Security Check",
              "ID": "KSV032",
              "Title": "All container images must start with the *.azurecr.io domain",
              "Description": "Containers should only use images from trusted registries.",
              "Message": "container app of deployment app in default namespace should restrict container image to your specific registry domain. For Azure any domain ending in 'azurecr.io'",
              "Namespace": "builtin.kubernetes.KSV032",
              "Query": "data.builtin.kubernetes.KSV032.deny",
              "Resolution": "Use images from trusted Azure registries.",
              "Severity": "MEDIUM",
              "PrimaryURL": "https://avd.aquasec.com/misconfig/ksv032",
              "References": [
                "https://avd.aquasec.com/misconfig/ksv032"
              ],
              "Status": "FAIL",
              "Layer": {},
              "IacMetadata": {
                "Provider": "Kubernetes",
                "Service": "general",
                "StartLine": 121,
                "EndLine": 133
              }
            },
            {
              "Type": "Kubernetes Security Check",
              "ID": "KSV033",
              "Title": "All container images must start with a GCR domain",
              "Description": "Containers should only use images from trusted GCR registries.",
              "Message": "container app of deployment app in default namespace should restrict container image to your specific registry domain. See the full GCR list here: https://cloud.google.com/container-registry/docs/overview#registries",
              "Namespace": "builtin.kubernetes.KSV033",
              "Query": "data.builtin.kubernetes.KSV033.deny",
              "Resolution": "Use images from trusted GCR registries.",
              "Severity": "MEDIUM",
              "PrimaryURL": "https://avd.aquasec.com/misconfig/ksv033",
              "References": [
                "https://avd.aquasec.com/misconfig/ksv033"
              ],
              "Status": "FAIL",
              "Layer": {},
              "IacMetadata": {
                "Provider": "Kubernetes",
                "Service": "general",
                "StartLine": 121,
                "EndLine": 133
              }
            },
            {
              "Type": "Kubernetes Security Check",
              "ID": "KSV034",
              "Title": "Container images from public registries used",
              "Description": "Container images must not start with an empty prefix or a defined public registry domain.",
              "Message": "Container 'app' of Deployment 'app' should restrict container image to use private registries",
              "Namespace": "builtin.kubernetes.KSV034",
              "Query": "data.builtin.kubernetes.KSV034.deny",
              "Resolution": "Use images from private registries.",
              "Severity": "MEDIUM",
              "PrimaryURL": "https://avd.aquasec.com/misconfig/ksv034",
              "References": [
                "https://avd.aquasec.com/misconfig/ksv034"
              ],
              "Status": "FAIL",
              "Layer": {},
              "IacMetadata": {
                "Provider": "Kubernetes",
                "Service": "general",
                "StartLine": 121,
                "EndLine": 133
              }
            },
            {
              "Type": "Kubernetes Security Check",
              "ID": "KSV035",
              "Title": "All container images must start with an ECR domain",
              "Description": "Container images from non-ECR registries should be forbidden.",
              "Message": "Container 'app' of Deployment 'app' should restrict images to own ECR repository. See the full ECR list here: https://docs.aws.amazon.com/general/latest/gr/ecr.html",
              "Namespace": "builtin.kubernetes.KSV035",
              "Query": "data.builtin.kubernetes.KSV035.deny",
              "Resolution": "Container image should be used from Amazon container Registry",
              "Severity": "MEDIUM",
              "PrimaryURL": "https://avd.aquasec.com/misconfig/ksv035",
              "References": [
                "https://avd.aquasec.com/misconfig/ksv035"
              ],
              "Status": "FAIL",
              "Layer": {},
              "IacMetadata": {
                "Provider": "Kubernetes",
                "Service": "general",
                "StartLine": 121,
                "EndLine": 133
              }
            },
            {
              "Type": "Kubernetes Security Check",
              "ID": "KSV038",
              "Title": "Selector usage in network policies",
              "Description": "ensure that network policies selectors are applied to pods or namespaces to restricted ingress and egress traffic within the pod network",
              "Message": "Network policy should uses podSelector and/or the namespaceSelector to restrict ingress and egress traffic within the Pod network",
              "Namespace": "builtin.kubernetes.KSV038",
              "Query": "data.builtin.kubernetes.KSV038.deny",
              "Resolution": "create network policies and ensure that pods are selected using the podSelector and/or the namespaceSelector options",
              "Severity": "MEDIUM",
              "PrimaryURL": "https://avd.aquasec.com/misconfig/ksv038",
              "References": [
                "https://kubernetes.io/docs/tasks/administer-cluster/declare-network-policy/",
                "https://avd.aquasec.com/misconfig/ksv038"
              ],
              "Status": "FAIL",
              "Layer": {},
              "IacMetadata": {
                "Provider": "Kubernetes",
                "Service": "general",
                "StartLine": 103,
                "EndLine": 138
              }
            },
            {
              "Type": "Kubernetes Security Check",
              "ID": "KSV039",
              "Title": "limit range usage",
              "Description": "ensure limit range policy has configure in order to limit resource usage for namespaces or nodes",
              "Message": "limit range policy with a default request and limit, min and max request, for each container should be configure",
              "Namespace": "builtin.kubernetes.KSV039",
              "Query": "data.builtin.kubernetes.KSV039.deny",
              "Resolution": "create limit range policy with a default request and limit, min and max request, for each container.",
              "Severity": "LOW",
              "PrimaryURL": "https://avd.aquasec.com/misconfig/ksv039",
              "References": [
                "https://kubernetes.io/docs/concepts/policy/limit-range/",
                "https://avd.aquasec.com/misconfig/ksv039"
              ],
              "Status": "FAIL",
              "Layer": {},
              "IacMetadata": {
                "Provider": "Kubernetes",
                "Service": "general",
                "StartLine": 103,
                "EndLine": 138
              }
            },
            {
              "Type": "Kubernetes Security Check",
              "ID": "KSV040",
              "Title": "resource quota usage",
              "Description": "ensure resource quota policy has configure in order to limit aggregate resource usage within namespace",
              "Message": "resource quota policy with hard memory and cpu quota per namespace should be configure",
              "Namespace": "builtin.kubernetes.KSV040",
              "Query": "data.builtin.kubernetes.KSV040.deny",
              "Resolution": "create resource quota policy with mem and cpu quota per each namespace",
              "Severity": "LOW",
              "PrimaryURL": "https://avd.aquasec.com/misconfig/ksv040",
              "References": [
                "https://kubernetes.io/docs/tasks/administer-cluster/manage-resources/quota-memory-cpu-namespace/",
                "https://avd.aquasec.com/misconfig/ksv040"
              ],
              "Status": "FAIL",
              "Layer": {},
              "IacMetadata": {
                "Provider": "Kubernetes",
                "Service": "general",
                "StartLine": 103,
                "EndLine": 138
              }
            }
          ]
        }
      ]
    },
    {
      "Namespace": "default",
      "Kind": "Service",
      "Name": "kubernetes",
      "Results": [
        {
          "Target": "Service/kubernetes",
          "Class": "config",
          "Type": "kubernetes",
          "MisconfSummary": {
            "Successes": 36,
            "Failures": 3,
            "Exceptions": 0
          },
          "Misconfigurations": [
            {
              "Type": "Kubernetes Security Check",
              "ID": "KSV038",
              "Title": "Selector usage in network policies",
              "Description": "ensure that network policies selectors are applied to pods or namespaces to restricted ingress and egress traffic within the pod network",
              "Message": "Network policy should uses podSelector and/or the namespaceSelector to restrict ingress and egress traffic within the Pod network",
              "Namespace": "builtin.kubernetes.KSV038",
              "Query": "data.builtin.kubernetes.KSV038.deny",
              "Resolution": "create network policies and ensure that pods are selected using the podSelector and/or the namespaceSelector options",
              "Severity": "MEDIUM",
              "PrimaryURL": "https://avd.aquasec.com/misconfig/ksv038",
              "References": [
                "https://kubernetes.io/docs/tasks/administer-cluster/declare-network-policy/",
                "https://avd.aquasec.com/misconfig/ksv038"
              ],
              "Status": "FAIL",
              "Layer": {},
              "IacMetadata": {
                "Provider": "Kubernetes",
                "Service": "general",
                "StartLine": 39,
                "EndLine": 52
              }
            },
            {
              "Type": "Kubernetes Security Check",
              "ID": "KSV039",
              "Title": "limit range usage",
              "Description": "ensure limit range policy has configure in order to limit resource usage for namespaces or nodes",
              "Message": "limit range policy with a default request and limit, min and max request, for each container should be configure",
              "Namespace": "builtin.kubernetes.KSV039",
              "Query": "data.builtin.kubernetes.KSV039.deny",
              "Resolution": "create limit range policy with a default request and limit, min and max request, for each container.",
              "Severity": "LOW",
              "PrimaryURL": "https://avd.aquasec.com/misconfig/ksv039",
              "References": [
                "https://kubernetes.io/docs/concepts/policy/limit-range/",
                "https://avd.aquasec.com/misconfig/ksv039"
              ],
              "Status": "FAIL",
              "Layer": {},
              "IacMetadata": {
                "Provider": "Kubernetes",
                "Service": "general",
                "StartLine": 39,
                "EndLine": 52
              }
            },
            {
              "Type": "Kubernetes Security Check",
              "ID": "KSV040",
              "Title": "resource quota usage",
              "Description": "ensure resource quota policy has configure in order to limit aggregate resource usage within namespace",
              "Message": "resource quota policy with hard memory and cpu quota per namespace should be configure",
              "Namespace": "builtin.kubernetes.KSV040",
              "Query": "data.builtin.kubernetes.KSV040.deny",
              "Resolution": "create resource quota policy with mem and cpu quota per each namespace",
              "Severity": "LOW",
              "PrimaryURL": "https://avd.aquasec.com/misconfig/ksv040",
              "References": [
                "https://kubernetes.io/docs/tasks/administer-cluster/manage-resources/quota-memory-cpu-namespace/",
                "https://avd.aquasec.com/misconfig/ksv040"
              ],
              "Status": "FAIL",
              "Layer": {},
              "IacMetadata": {
                "Provider": "Kubernetes",
                "Service": "general",
                "StartLine": 39,
                "EndLine": 52
              }
            }
          ]
        }
      ]
    },
    {
      "Namespace": "default",
      "Kind": "ConfigMap",
      "Name": "kube-root-ca.crt"
    }
  ]
}

```

</details>
