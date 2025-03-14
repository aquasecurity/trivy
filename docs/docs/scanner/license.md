# License Scanning

Trivy scans any container image for license files and offers an opinionated view on the risk associated with the license.

License are classified using the [Google License Classification][google-license-classification] -

 - Forbidden
 - Restricted 
 - Reciprocal
 - Notice
 - Permissive
 - Unencumbered
 - Unknown

!!! tip
    Licenses that Trivy fails to recognize are classified as UNKNOWN.
    As those licenses may be in violation, it is recommended to check those unknown licenses as well.    

By default, Trivy scans licenses for packages installed by `apk`, `apt-get`, `dnf`, `npm`, `pip`, `gem`, etc.
Check out [the coverage document][coverage] for details.

To enable extended license scanning, you can use `--license-full`.
In addition to package licenses, Trivy scans source code files, Markdown documents, text files and `LICENSE` documents to identify license usage within the image or filesystem.

By default, Trivy only classifies licenses that are matched with a confidence level of 0.9 or more by the classifier.
To configure the confidence level, you can use `--license-confidence-level`. This enables us to classify licenses that might be matched with a lower confidence level by the classifier. 

!!! note
    The full license scanning is expensive. It takes a while.

|   License scanning    | Image | Rootfs | Filesystem | Repository | SBOM |
|:---------------------:|:-----:|:------:|:----------:|:----------:|:----:|
|       Standard        |   ✅   |   ✅    | ✅[^1][^2]  | ✅[^1][^2]  |  ✅   |
| Full (--license-full) |   ✅   |   ✅    |     ✅      |     ✅      |  -   |

License checking classifies the identified licenses and map the classification to severity.

| Classification | Severity |
| -------------- | -------- |
| Forbidden      | CRITICAL |
| Restricted     | HIGH     |
| Reciprocal     | MEDIUM   |
| Notice         | LOW      |
| Permissive     | LOW      |
| Unencumbered   | LOW      |
| Unknown        | UNKNOWN  |

## Quick start
This section shows how to scan license in container image and filesystem.

### Standard scanning
Specify an image name with `--scanners license`.

``` shell
$ trivy image --scanners license --severity UNKNOWN,HIGH,CRITICAL alpine:3.15
2022-07-13T17:28:39.526+0300    INFO    License scanning is enabled

OS Packages (license)
=====================
Total: 6 (UNKNOWN: 0, HIGH: 6, CRITICAL: 0)

┌───────────────────┬─────────┬────────────────┬──────────┐
│      Package      │ License │ Classification │ Severity │
├───────────────────┼─────────┼────────────────┼──────────┤
│ alpine-baselayout │ GPL-2.0 │ Restricted     │ HIGH     │
├───────────────────┤         │                │          │
│ apk-tools         │         │                │          │
├───────────────────┤         │                │          │
│ busybox           │         │                │          │
├───────────────────┤         │                │          │
│ musl-utils        │         │                │          │
├───────────────────┤         │                │          │
│ scanelf           │         │                │          │
├───────────────────┤         │                │          │
│ ssl_client        │         │                │          │
└───────────────────┴─────────┴────────────────┴──────────┘
```

### Full scanning
Specify `--license-full`

``` shell
$ trivy image --scanners license --severity UNKNOWN,HIGH,CRITICAL --license-full grafana/grafana
2022-07-13T17:48:40.905+0300    INFO    Full license scanning is enabled

OS Packages (license)
=====================
Total: 20 (UNKNOWN: 9, HIGH: 11, CRITICAL: 0)

┌───────────────────┬───────────────────┬────────────────┬──────────┐
│      Package      │      License      │ Classification │ Severity │
├───────────────────┼───────────────────┼────────────────┼──────────┤
│ alpine-baselayout │ GPL-2.0           │ Restricted     │ HIGH     │
├───────────────────┤                   │                │          │
│ apk-tools         │                   │                │          │
├───────────────────┼───────────────────┤                │          │
│ bash              │ GPL-3.0           │                │          │
├───────────────────┼───────────────────┼────────────────┼──────────┤
│ keyutils-libs     │ GPL-2.0           │ Restricted     │ HIGH     │
│                   ├───────────────────┼────────────────┼──────────┤
│                   │ LGPL-2.0-or-later │ Non Standard   │ UNKNOWN  │
├───────────────────┼───────────────────┤                │          │
│ libaio            │ LGPL-2.1-or-later │                │          │
├───────────────────┼───────────────────┼────────────────┼──────────┤
│ libcom_err        │ GPL-2.0           │ Restricted     │ HIGH     │
│                   ├───────────────────┼────────────────┼──────────┤
│                   │ LGPL-2.0-or-later │ Non Standard   │ UNKNOWN  │
├───────────────────┼───────────────────┼────────────────┼──────────┤
│ tzdata            │ Public-Domain     │ Non Standard   │ UNKNOWN  │
└───────────────────┴───────────────────┴────────────────┴──────────┘

Loose File License(s) (license)
===============================
Total: 6 (UNKNOWN: 4, HIGH: 0, CRITICAL: 2)

┌────────────────┬──────────┬──────────────┬──────────────────────────────────────────────────────────────┐
│ Classification │ Severity │   License    │                        File Location                         │
├────────────────┼──────────┼──────────────┼──────────────────────────────────────────────────────────────┤
│ Forbidden      │ CRITICAL │ AGPL-3.0     │ /usr/share/grafana/LICENSE                                   │
│                │          │              │                                                              │
│                │          │              │                                                              │
├────────────────┼──────────┼──────────────┼──────────────────────────────────────────────────────────────┤
│ Non Standard   │ UNKNOWN  │ BSD-0-Clause │ /usr/share/grafana/public/build/5069.d6aae9dd11d49c741a80.j- │
│                │          │              │ s.LICENSE.txt                                                │
│                │          │              ├──────────────────────────────────────────────────────────────┤
│                │          │              │ /usr/share/grafana/public/build/6444.d6aae9dd11d49c741a80.j- │
│                │          │              │ s.LICENSE.txt                                                │
│                │          │              ├──────────────────────────────────────────────────────────────┤
│                │          │              │ /usr/share/grafana/public/build/7889.d6aae9dd11d49c741a80.j- │
│                │          │              │ s.LICENSE.txt                                                │
│                │          │              ├──────────────────────────────────────────────────────────────┤
│                │          │              │ /usr/share/grafana/public/build/canvasPanel.d6aae9dd11d49c7- │
│                │          │              │ 41a80.js.LICENSE.txt                                         │
└────────────────┴──────────┴──────────────┴──────────────────────────────────────────────────────────────┘
```

## Configuration

Trivy has number of configuration flags for use with license scanning;
                                 
### Ignored Licenses

Trivy license scanning can ignore licenses that are identified to explicitly remove them from the results using the `--ignored-licenses` flag;

```shell
$ trivy image --scanners license --ignored-licenses MPL-2.0,MIT --severity HIGH grafana/grafana:latest
2022-07-13T18:15:28.605Z        INFO    License scanning is enabled

OS Packages (license)
=====================
Total: 2 (HIGH: 2, CRITICAL: 0)

┌───────────────────┬─────────┬────────────────┬──────────┐
│      Package      │ License │ Classification │ Severity │
├───────────────────┼─────────┼────────────────┼──────────┤
│ alpine-baselayout │ GPL-2.0 │ Restricted     │ HIGH     │
├───────────────────┤         │                │          │
│ ssl_client        │         │                │          │
└───────────────────┴─────────┴────────────────┴──────────┘

```

### Configuring Classifier Confidence Level
You can use the `--license-confidence-level` flag to adjust the confidence level between 0.0 to 1.0 (default 0.9).
For example, when you run the scanner with the default confidence level on [SPDX license list data](https://github.com/spdx/license-list-data/tree/main/text), it is able to detect only 258 licenses.

```shell
$ trivy fs --scanners license --license-full <path/to/spdx/list/data>
2023-04-18T10:05:13.601-0700    INFO    Full license scanning is enabled

Loose File License(s) (license)
===============================
Total: 258 (UNKNOWN: 70, LOW: 90, MEDIUM: 18, HIGH: 58, CRITICAL: 22)
```

However, by configuring the confidence level to 0.8, the scanner is now able to detect 282 licenses.

```shell
$ trivy fs --scanners license --license-full --license-confidence-level 0.8 <path/to/spdx/list/data>
2023-04-18T10:21:39.637-0700    INFO    Full license scanning is enabled

Loose File License(s) (license)
===============================
Total: 282 (UNKNOWN: 81, LOW: 97, MEDIUM: 24, HIGH: 58, CRITICAL: 22)
```

### Custom Classification
You can generate the default config by the `--generate-default-config` flag and customize the license classification.
For example, if you want to forbid only AGPL-3.0, you can leave it under `forbidden` and move other licenses to another classification.

```shell
$ trivy image --generate-default-config
$ vim trivy.yaml
license:
  forbidden:
  - AGPL-3.0
  
  restricted:
  - AGPL-1.0
  - CC-BY-NC-1.0
  - CC-BY-NC-2.0
  - CC-BY-NC-2.5
  - CC-BY-NC-3.0
  - CC-BY-NC-4.0
  - CC-BY-NC-ND-1.0
  - CC-BY-NC-ND-2.0
  - CC-BY-NC-ND-2.5
  - CC-BY-NC-ND-3.0
  - CC-BY-NC-ND-4.0
  - CC-BY-NC-SA-1.0
  - CC-BY-NC-SA-2.0
  - CC-BY-NC-SA-2.5
  - CC-BY-NC-SA-3.0
  - CC-BY-NC-SA-4.0
  - Commons-Clause
  - Facebook-2-Clause
  - Facebook-3-Clause
  - Facebook-Examples
  - WTFPL
  - BCL
  - CC-BY-ND-1.0
  - CC-BY-ND-2.0
  - CC-BY-ND-2.5
  - CC-BY-ND-3.0
  - CC-BY-ND-4.0
  - CC-BY-SA-1.0
  - CC-BY-SA-2.0
  - CC-BY-SA-2.5
  - CC-BY-SA-3.0
  - CC-BY-SA-4.0
  - GPL-1.0
  - GPL-2.0
  - GPL-2.0-with-autoconf-exception
  - GPL-2.0-with-bison-exception
  - GPL-2.0-with-classpath-exception
  - GPL-2.0-with-font-exception
  - GPL-2.0-with-GCC-exception
  - GPL-3.0
  - GPL-3.0-with-autoconf-exception
  - GPL-3.0-with-GCC-exception
  - LGPL-2.0
  - LGPL-2.1
  - LGPL-3.0
  - NPL-1.0
  - NPL-1.1
  - OSL-1.0
  - OSL-1.1
  - OSL-2.0
  - OSL-2.1
  - OSL-3.0
  - QPL-1.0
  - Sleepycat
  
  reciprocal:
  - APSL-1.0
  - APSL-1.1
  - APSL-1.2
  - APSL-2.0
  - CDDL-1.0
  - CDDL-1.1
  - CPL-1.0
  - EPL-1.0
  - EPL-2.0
  - FreeImage
  - IPL-1.0
  - MPL-1.0
  - MPL-1.1
  - MPL-2.0
  - Ruby
  
  notice:
  - AFL-1.1
  - AFL-1.2
  - AFL-2.0
  - AFL-2.1
  - AFL-3.0
  - Apache-1.0
  - Apache-1.1
  - Apache-2.0
  - Artistic-1.0-cl8
  - Artistic-1.0-Perl
  - Artistic-1.0
  - Artistic-2.0
  - BSL-1.0
  - BSD-2-Clause-FreeBSD
  - BSD-2-Clause-NetBSD
  - BSD-2-Clause
  - BSD-3-Clause-Attribution
  - BSD-3-Clause-Clear
  - BSD-3-Clause-LBNL
  - BSD-3-Clause
  - BSD-4-Clause
  - BSD-4-Clause-UC
  - BSD-Protection
  - CC-BY-1.0
  - CC-BY-2.0
  - CC-BY-2.5
  - CC-BY-3.0
  - CC-BY-4.0
  - FTL
  - ISC
  - ImageMagick
  - Libpng
  - Lil-1.0
  - Linux-OpenIB
  - LPL-1.02
  - LPL-1.0
  - MS-PL
  - MIT
  - NCSA
  - OpenSSL
  - PHP-3.01
  - PHP-3.0
  - PIL
  - Python-2.0
  - Python-2.0-complete
  - PostgreSQL
  - SGI-B-1.0
  - SGI-B-1.1
  - SGI-B-2.0
  - Unicode-DFS-2015
  - Unicode-DFS-2016
  - Unicode-TOU
  - UPL-1.0
  - W3C-19980720
  - W3C-20150513
  - W3C
  - X11
  - Xnet
  - Zend-2.0
  - zlib-acknowledgement
  - Zlib
  - ZPL-1.1
  - ZPL-2.0
  - ZPL-2.1
  
  unencumbered:
  - CC0-1.0
  - Unlicense
  - 0BSD
  
  permissive: []
```

[^1]: See the list of supported language files [here](../coverage/language/index.md).
[^2]: Some lock files require additional files (e.g. files from the cache directory) to detect licenses. Check [coverage][coverage] for more information.

[coverage]: ../coverage/index.md
[google-license-classification]: https://opensource.google/documentation/reference/thirdparty/licenses
