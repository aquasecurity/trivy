[EXPERIMENTAL] This feature might change without preserving backwards compatibility.

Trivy supports Open Policy Agent (OPA) to filter vulnerabilities. You can specify a Rego file with `--ignore-policy` option.

The Rego package name must be `trivy` and it must include a rule called `ignore` which determines if each individual vulnerability should be excluded (ignore=true) or not (ignore=false). In the policy, each vulnerability will be available for inspection as the `input` variable. The structure of each vulnerability input is the same as for the Trivy JSON output.  
There is a built-in Rego library with helper functions that you can import into your policy using: `import data.lib.trivy`. For more info about the helper functions, look at the library [here][helper]

To get started, see the [example policy][policy].

```
$ trivy image --ignore-policy contrib/example_filter/basic.rego centos:7
```

<details>
<summary>Result</summary>

```
centos:7 (centos 7.8.2003)
==========================
Total: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 1, CRITICAL: 0)

+---------+------------------+----------+-------------------+---------------+--------------------------------+
| LIBRARY | VULNERABILITY ID | SEVERITY | INSTALLED VERSION | FIXED VERSION |             TITLE              |
+---------+------------------+----------+-------------------+---------------+--------------------------------+
| glib2   | CVE-2016-3191    | HIGH     | 2.56.1-5.el7      |               | pcre: workspace overflow       |
|         |                  |          |                   |               | for (*ACCEPT) with deeply      |
|         |                  |          |                   |               | nested parentheses (8.39/13,   |
|         |                  |          |                   |               | 10.22/12)                      |
+---------+------------------+----------+-------------------+---------------+--------------------------------+
```

</details>

[helper]: https://github.com/aquasecurity/trivy/tree/main/pkg/vulnerability/module.go
[policy]: https://github.com/aquasecurity/trivy/tree/main/contrib/example_policy
