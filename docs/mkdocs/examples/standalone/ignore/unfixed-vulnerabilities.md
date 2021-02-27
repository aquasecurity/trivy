By default, `Trivy` also detects unpatched/unfixed vulnerabilities. This means you can't fix these vulnerabilities even if you update all packages.
If you would like to ignore them, use the `--ignore-unfixed` option.

```
$ trivy image --ignore-unfixed ruby:2.4.0
```

<details>
<summary>Result</summary>

```
2019-05-16T12:49:52.656+0900    INFO    Updating vulnerability database...
2019-05-16T12:50:14.786+0900    INFO    Detecting Debian vulnerabilities...

ruby:2.4.0 (debian 8.7)
=======================
Total: 4730 (UNKNOWN: 1, LOW: 145, MEDIUM: 3487, HIGH: 1014, CRITICAL: 83)

+------------------------------+------------------+----------+----------------------------+----------------------------------+-----------------------------------------------------+
|           LIBRARY            | VULNERABILITY ID | SEVERITY |     INSTALLED VERSION      |          FIXED VERSION           |                        TITLE                        |
+------------------------------+------------------+----------+----------------------------+----------------------------------+-----------------------------------------------------+
| apt                          | CVE-2019-3462    | CRITICAL | 1.0.9.8.3                  | 1.0.9.8.5                        | Incorrect sanitation of the                         |
|                              |                  |          |                            |                                  | 302 redirect field in HTTP                          |
|                              |                  |          |                            |                                  | transport method of...                              |
+                              +------------------+----------+                            +----------------------------------+-----------------------------------------------------+
|                              | CVE-2016-1252    | MEDIUM   |                            | 1.0.9.8.4                        | The apt package in Debian                           |
|                              |                  |          |                            |                                  | jessie before 1.0.9.8.4, in                         |
|                              |                  |          |                            |                                  | Debian unstable before...                           |
+------------------------------+------------------+----------+----------------------------+----------------------------------+-----------------------------------------------------+
| bash                         | CVE-2019-9924    | HIGH     | 4.3-11                     | 4.3-11+deb8u2                    | bash: BASH_CMD is writable in                       |
|                              |                  |          |                            |                                  | restricted bash shells                              |
+                              +------------------+          +                            +----------------------------------+-----------------------------------------------------+
|                              | CVE-2016-7543    |          |                            | 4.3-11+deb8u1                    | bash: Specially crafted                             |
|                              |                  |          |                            |                                  | SHELLOPTS+PS4 variables allows                      |
|                              |                  |          |                            |                                  | command substitution                                |
+                              +------------------+----------+                            +                                  +-----------------------------------------------------+
|                              | CVE-2016-0634    | MEDIUM   |                            |                                  | bash: Arbitrary code execution                      |
|                              |                  |          |                            |                                  | via malicious hostname                              |
+                              +------------------+----------+                            +----------------------------------+-----------------------------------------------------+
|                              | CVE-2016-9401    | LOW      |                            | 4.3-11+deb8u2                    | bash: popd controlled free                          |
+------------------------------+------------------+----------+----------------------------+----------------------------------+-----------------------------------------------------+
...
```

</details>
