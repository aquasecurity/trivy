# Polaris

[Polaris] is the default configuration checker used by Starboard. It runs a variety of checks to ensure that Kubernetes
Pods and controllers are configured using best practices.

The [default][config-default] Polaris [configuration] can be customized to do things like:

- Turn checks [on and off][checks]
- Change the [severity level][checks] of checks
- Add new [custom checks]
- Add [exemptions] for particular workloads or namespaces

## Settings

| CONFIGMAP KEY                      | DEFAULT                                                | DESCRIPTION                                                       |
|------------------------------------|--------------------------------------------------------|-------------------------------------------------------------------|
| `polaris.imageRef`                 | `quay.io/fairwinds/polaris:4.2`                        | Polaris image reference                                           |
| `polaris.config.yaml`              | [Check the default value here][default-polaris-config] | Polaris configuration file                                        |
| `polaris.resources.request.cpu`    | `50m`                                                  | The minimum amount of CPU required to run Polaris scanner pod.    |
| `polaris.resources.request.memory` | `50M`                                                  | The minimum amount of memory required to run Polaris scanner pod. |
| `polaris.resources.limit.cpu`      | `300m`                                                 | The maximum amount of CPU allowed to run Polaris scanner pod.     |
| `polaris.resources.limit.memory`   | `300M`                                                 | The maximum amount of memory allowed to run polaris scanner pod.  |

## What's Next?

- See the Polaris documentation for the list of [security], [efficiency], and [reliability] checks.

[Polaris]: https://github.com/FairwindsOps/polaris
[config-default]: https://github.com/aquasecurity/starboard/blob/{{ git.tag }}/deploy/static/05-starboard-operator.config.yaml#L24
[configuration]: https://polaris.docs.fairwinds.com/customization/configuration/
[checks]: https://polaris.docs.fairwinds.com/customization/checks/
[custom checks]: https://polaris.docs.fairwinds.com/customization/custom-checks/
[exemptions]: https://polaris.docs.fairwinds.com/customization/exemptions/
[security]: https://polaris.docs.fairwinds.com/checks/security/
[efficiency]: https://polaris.docs.fairwinds.com/checks/efficiency/
[reliability]: https://polaris.docs.fairwinds.com/checks/reliability/
