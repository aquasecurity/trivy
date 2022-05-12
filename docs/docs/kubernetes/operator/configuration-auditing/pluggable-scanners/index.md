# Pluggable Scanners

!!! warning
    Pluggable configuration audit scanners are being deprecated. They did a great job when we first integrated them with
    Starboard, but recently we found that they are not very efficient and customizable. Therefore, we are switching
    over to efficient OPA Rego-based configuration scanner that ships with many [Built-in Policies].

Starboard relies on a configuration checker to run variety of tests on discovered workloads to make sure
they are configured using best practices.

You can choose any of the included configuration checkers or implement your own plugin. The plugin mechanism is based
on in-tree implementations of the [`configauditreport.Plugin`][plugin-interface] Go interface. For example, check the
implementation of the [Polaris plugin].

These are currently integrated configuration checkers:

* [Polaris by Fairwinds Ops](./polaris.md)
* [Conftest by Open Policy Agent](./conftest.md)

## What's Next?

* See the explanation and demo of configuration auditing with Polaris on the
  [Automating Configuration Auditing with Starboard Operator By Aqua][blog] blog.

[Built-in Policies]: ./../built-in-policies.md
[plugin-interface]: https://pkg.go.dev/github.com/aquasecurity/starboard@{{ git.tag }}/pkg/configauditreport#Plugin
[Polaris plugin]: https://github.com/aquasecurity/starboard/blob/{{ git.tag }}/pkg/plugin/polaris/plugin.go
[blog]: https://blog.aquasec.com/automating-configuration-auditing-starboard-operator
