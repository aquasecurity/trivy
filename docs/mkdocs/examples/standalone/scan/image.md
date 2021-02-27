Simply specify an image name (and a tag).

```
$ trivy image knqyf263/vuln-image:1.2.3
```

<details>
<summary>Result</summary>

```
2019-05-16T12:59:03.150+0900    INFO    Detecting Alpine vulnerabilities...
2019-05-16T12:59:04.941+0900    INFO    Detecting bundler vulnerabilities...
2019-05-16T12:59:05.967+0900    INFO    Detecting cargo vulnerabilities...
2019-05-16T12:59:07.834+0900    INFO    Detecting composer vulnerabilities...
2019-05-16T12:59:10.285+0900    INFO    Detecting npm vulnerabilities...
2019-05-16T12:59:11.487+0900    INFO    Detecting pipenv vulnerabilities...

knqyf263/vuln-image:1.2.3 (alpine 3.7.1)
========================================
Total: 26 (UNKNOWN: 0, LOW: 3, MEDIUM: 16, HIGH: 5, CRITICAL: 2)

+---------+------------------+----------+-------------------+---------------+----------------------------------+
| LIBRARY | VULNERABILITY ID | SEVERITY | INSTALLED VERSION | FIXED VERSION |              TITLE               |
+---------+------------------+----------+-------------------+---------------+----------------------------------+
| curl    | CVE-2018-14618   | CRITICAL | 7.61.0-r0         | 7.61.1-r0     | curl: NTLM password overflow     |
|         |                  |          |                   |               | via integer overflow             |
+         +------------------+----------+                   +---------------+----------------------------------+
|         | CVE-2018-16839   | HIGH     |                   | 7.61.1-r1     | curl: Integer overflow leading   |
|         |                  |          |                   |               | to heap-based buffer overflow in |
|         |                  |          |                   |               | Curl_sasl_create_plain_message() |
+         +------------------+          +                   +---------------+----------------------------------+
|         | CVE-2019-3822    |          |                   | 7.61.1-r2     | curl: NTLMv2 type-3 header       |
|         |                  |          |                   |               | stack buffer overflow            |
+         +------------------+          +                   +---------------+----------------------------------+
|         | CVE-2018-16840   |          |                   | 7.61.1-r1     | curl: Use-after-free when        |
|         |                  |          |                   |               | closing "easy" handle in         |
|         |                  |          |                   |               | Curl_close()                     |
+         +------------------+----------+                   +               +----------------------------------+
|         | CVE-2018-16842   | MEDIUM   |                   |               | curl: Heap-based buffer          |
|         |                  |          |                   |               | over-read in the curl tool       |
|         |                  |          |                   |               | warning formatting               |
+         +------------------+          +                   +---------------+----------------------------------+
|         | CVE-2018-16890   |          |                   | 7.61.1-r2     | curl: NTLM type-2 heap           |
|         |                  |          |                   |               | out-of-bounds buffer read        |
+         +------------------+          +                   +               +----------------------------------+
|         | CVE-2019-3823    |          |                   |               | curl: SMTP end-of-response       |
|         |                  |          |                   |               | out-of-bounds read               |
+---------+------------------+----------+-------------------+---------------+----------------------------------+
| git     | CVE-2018-17456   | HIGH     | 2.15.2-r0         | 2.15.3-r0     | git: arbitrary code execution    |
|         |                  |          |                   |               | via .gitmodules                  |
+         +------------------+          +                   +               +----------------------------------+
|         | CVE-2018-19486   |          |                   |               | git: Improper handling of        |
|         |                  |          |                   |               | PATH allows for commands to be   |
|         |                  |          |                   |               | executed from...                 |
+---------+------------------+----------+-------------------+---------------+----------------------------------+
| libssh2 | CVE-2019-3855    | CRITICAL | 1.8.0-r2          | 1.8.1-r0      | libssh2: Integer overflow in     |
|         |                  |          |                   |               | transport read resulting in      |
|         |                  |          |                   |               | out of bounds write...           |
+         +------------------+----------+                   +               +----------------------------------+
|         | CVE-2019-3859    | MEDIUM   |                   |               | libssh2: Unchecked use of        |
|         |                  |          |                   |               | _libssh2_packet_require and      |
|         |                  |          |                   |               | _libssh2_packet_requirev         |
|         |                  |          |                   |               | resulting in out-of-bounds       |
|         |                  |          |                   |               | read                             |
+         +------------------+          +                   +               +----------------------------------+
|         | CVE-2019-3858    |          |                   |               | libssh2: Zero-byte allocation    |
|         |                  |          |                   |               | with a specially crafted SFTP    |
|         |                  |          |                   |               | packed leading to an...          |
+         +------------------+          +                   +               +----------------------------------+
|         | CVE-2019-3863    |          |                   |               | libssh2: Integer overflow        |
|         |                  |          |                   |               | in user authenticate             |
|         |                  |          |                   |               | keyboard interactive allows      |
|         |                  |          |                   |               | out-of-bounds writes             |
+         +------------------+          +                   +               +----------------------------------+
|         | CVE-2019-3862    |          |                   |               | libssh2: Out-of-bounds memory    |
|         |                  |          |                   |               | comparison with specially        |
|         |                  |          |                   |               | crafted message channel          |
|         |                  |          |                   |               | request                          |
+         +------------------+          +                   +               +----------------------------------+
|         | CVE-2019-3860    |          |                   |               | libssh2: Out-of-bounds reads     |
|         |                  |          |                   |               | with specially crafted SFTP      |
|         |                  |          |                   |               | packets                          |
+         +------------------+          +                   +               +----------------------------------+
|         | CVE-2019-3857    |          |                   |               | libssh2: Integer overflow in     |
|         |                  |          |                   |               | SSH packet processing channel    |
|         |                  |          |                   |               | resulting in out of...           |
+         +------------------+          +                   +               +----------------------------------+
|         | CVE-2019-3861    |          |                   |               | libssh2: Out-of-bounds reads     |
|         |                  |          |                   |               | with specially crafted SSH       |
|         |                  |          |                   |               | packets                          |
+         +------------------+          +                   +               +----------------------------------+
|         | CVE-2019-3856    |          |                   |               | libssh2: Integer overflow in     |
|         |                  |          |                   |               | keyboard interactive handling    |
|         |                  |          |                   |               | resulting in out of bounds...    |
+---------+------------------+          +-------------------+---------------+----------------------------------+
| libxml2 | CVE-2018-14567   |          | 2.9.7-r0          | 2.9.8-r1      | libxml2: Infinite loop when      |
|         |                  |          |                   |               | --with-lzma is used allows for   |
|         |                  |          |                   |               | denial of service...             |
+         +------------------+          +                   +               +----------------------------------+
|         | CVE-2018-14404   |          |                   |               | libxml2: NULL pointer            |
|         |                  |          |                   |               | dereference in                   |
|         |                  |          |                   |               | xpath.c:xmlXPathCompOpEval()     |
|         |                  |          |                   |               | can allow attackers to cause     |
|         |                  |          |                   |               | a...                             |
+         +------------------+----------+                   +               +----------------------------------+
|         | CVE-2018-9251    | LOW      |                   |               | libxml2: infinite loop in        |
|         |                  |          |                   |               | xz_decomp function in xzlib.c    |
+---------+------------------+----------+-------------------+---------------+----------------------------------+
| openssh | CVE-2019-6109    | MEDIUM   | 7.5_p1-r9         | 7.5_p1-r10    | openssh: Missing character       |
|         |                  |          |                   |               | encoding in progress display     |
|         |                  |          |                   |               | allows for spoofing of scp...    |
+         +------------------+          +                   +               +----------------------------------+
|         | CVE-2019-6111    |          |                   |               | openssh: Improper validation     |
|         |                  |          |                   |               | of object names allows           |
|         |                  |          |                   |               | malicious server to overwrite    |
|         |                  |          |                   |               | files...                         |
+         +------------------+----------+                   +               +----------------------------------+
|         | CVE-2018-20685   | LOW      |                   |               | openssh: scp client improper     |
|         |                  |          |                   |               | directory name validation        |
+---------+------------------+----------+-------------------+---------------+----------------------------------+
| sqlite  | CVE-2018-20346   | MEDIUM   | 3.21.0-r1         | 3.25.3-r0     | sqlite: Multiple flaws in        |
|         |                  |          |                   |               | sqlite which can be triggered    |
|         |                  |          |                   |               | via corrupted internal...        |
+---------+------------------+----------+-------------------+---------------+----------------------------------+
| tar     | CVE-2018-20482   | LOW      | 1.29-r1           | 1.31-r0       | tar: Infinite read loop in       |
|         |                  |          |                   |               | sparse_dump_region function in   |
|         |                  |          |                   |               | sparse.c                         |
+---------+------------------+----------+-------------------+---------------+----------------------------------+

ruby-app/Gemfile.lock
=====================
Total: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 1, HIGH: 0, CRITICAL: 0)

+----------------------+------------------+----------+-------------------+---------------+--------------------------------+
|       LIBRARY        | VULNERABILITY ID | SEVERITY | INSTALLED VERSION | FIXED VERSION |             TITLE              |
+----------------------+------------------+----------+-------------------+---------------+--------------------------------+
| rails-html-sanitizer | CVE-2018-3741    | MEDIUM   | 1.0.3             | >= 1.0.4      | rubygem-rails-html-sanitizer:  |
|                      |                  |          |                   |               | non-whitelisted attributes     |
|                      |                  |          |                   |               | are present in sanitized       |
|                      |                  |          |                   |               | output when input with         |
|                      |                  |          |                   |               | specially-crafted...           |
+----------------------+------------------+----------+-------------------+---------------+--------------------------------+

rust-app/Cargo.lock
===================
Total: 3 (UNKNOWN: 3, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0)

+---------+-------------------+----------+-------------------+---------------+--------------------------------+
| LIBRARY | VULNERABILITY ID  | SEVERITY | INSTALLED VERSION | FIXED VERSION |             TITLE              |
+---------+-------------------+----------+-------------------+---------------+--------------------------------+
| ammonia | RUSTSEC-2019-0001 | UNKNOWN  | 1.9.0             | >= 2.1.0      | Uncontrolled recursion leads   |
|         |                   |          |                   |               | to abort in HTML serialization |
+---------+-------------------+          +-------------------+---------------+--------------------------------+
| openssl | RUSTSEC-2016-0001 |          | 0.8.3             | >= 0.9.0      | SSL/TLS MitM vulnerability due |
|         |                   |          |                   |               | to insecure defaults           |
+         +-------------------+          +                   +---------------+--------------------------------+
|         | RUSTSEC-2018-0010 |          |                   | >= 0.10.9     | Use after free in CMS Signing  |
+---------+-------------------+----------+-------------------+---------------+--------------------------------+

php-app/composer.lock
=====================
Total: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 1, HIGH: 0, CRITICAL: 0)

+-------------------+------------------+----------+-------------------+---------------------+--------------------------------+
|      LIBRARY      | VULNERABILITY ID | SEVERITY | INSTALLED VERSION |    FIXED VERSION    |             TITLE              |
+-------------------+------------------+----------+-------------------+---------------------+--------------------------------+
| guzzlehttp/guzzle | CVE-2016-5385    | MEDIUM   | 6.2.0             | 6.2.1, 4.2.4, 5.3.1 | PHP: sets environmental        |
|                   |                  |          |                   |                     | variable based on user         |
|                   |                  |          |                   |                     | supplied Proxy request header  |
+-------------------+------------------+----------+-------------------+---------------------+--------------------------------+

node-app/package-lock.json
==========================
Total: 4 (UNKNOWN: 0, LOW: 0, MEDIUM: 3, HIGH: 1, CRITICAL: 0)

+---------+------------------+----------+-------------------+---------------+--------------------------------+
| LIBRARY | VULNERABILITY ID | SEVERITY | INSTALLED VERSION | FIXED VERSION |             TITLE              |
+---------+------------------+----------+-------------------+---------------+--------------------------------+
| jquery  | CVE-2019-5428    | MEDIUM   | 3.3.9             | >=3.4.0       | Modification of                |
|         |                  |          |                   |               | Assumed-Immutable Data (MAID)  |
+         +------------------+          +                   +               +--------------------------------+
|         | CVE-2019-11358   |          |                   |               | js-jquery: prototype pollution |
|         |                  |          |                   |               | in object's prototype leading  |
|         |                  |          |                   |               | to denial of service or...     |
+---------+------------------+----------+-------------------+---------------+--------------------------------+
| lodash  | CVE-2018-16487   | HIGH     | 4.17.4            | >=4.17.11     | lodash: Prototype pollution in |
|         |                  |          |                   |               | utilities function             |
+         +------------------+----------+                   +---------------+                                +
|         | CVE-2018-3721    | MEDIUM   |                   | >=4.17.5      |                                |
|         |                  |          |                   |               |                                |
+---------+------------------+----------+-------------------+---------------+--------------------------------+

python-app/Pipfile.lock
=======================
Total: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 1, HIGH: 0, CRITICAL: 0)

+---------+------------------+----------+-------------------+---------------+------------------------------------+
| LIBRARY | VULNERABILITY ID | SEVERITY | INSTALLED VERSION | FIXED VERSION |               TITLE                |
+---------+------------------+----------+-------------------+---------------+------------------------------------+
| django  | CVE-2019-6975    | MEDIUM   | 2.0.9             | 2.0.11        | python-django:                     |
|         |                  |          |                   |               | memory exhaustion in               |
|         |                  |          |                   |               | django.utils.numberformat.format() |
+---------+------------------+----------+-------------------+---------------+------------------------------------+
```

</details>
