# Built-in Configuration Audit Policies

The following sections list built-in configuration audit policies installed with trivy-operator. They are stored in the
`trivy-operator-policies-config` ConfigMap created in the installation namespace (e.g. `trivy-system`). You can modify
them or add a new policy. For example, follow the [Writing Custom Configuration Audit Policies] tutorial to add a custom
policy that checks for recommended Kubernetes labels on any resource kind.

## General

| NAME                                       | DESCRIPTION                                                                                                                                                                                                         | KINDS    |
|--------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------|
| [CPU not limited]                          | Enforcing CPU limits prevents DoS via resource exhaustion.                                                                                                                                                          | Workload |
| [CPU requests not specified]               | When containers have resource requests specified, the scheduler can make better decisions about which nodes to place pods on, and how to deal with resource contention.                                             | Workload |
| [SYS_ADMIN capability added]               | SYS_ADMIN gives the processes running inside the container privileges that are equivalent to root.                                                                                                                  | Workload |
| [Default capabilities not dropped]         | The container should drop all default capabilities and add only those that are needed for its execution.                                                                                                            | Workload |
| [Root file system is not read-only]        | An immutable root file system prevents applications from writing to their local disk. This can limit intrusions, as attackers will not be able to tamper with the file system or write foreign executables to disk. | Workload |
| [Memory not limited]                       | Enforcing memory limits prevents DoS via resource exhaustion.                                                                                                                                                       | Workload |
| [Memory requests not specified]            | When containers have memory requests specified, the scheduler can make better decisions about which nodes to place pods on, and how to deal with resource contention.                                               | Workload |
| [hostPath volume mounted with docker.sock] | Mounting docker.sock from the host can give the container full root access to the host.                                                                                                                             | Workload |
| [Runs with low group ID]                   | Force the container to run with group ID > 10000 to avoid conflicts with the host’s user table.                                                                                                                     | Workload |
| [Runs with low user ID]                    | Force the container to run with user ID > 10000 to avoid conflicts with the host’s user table.                                                                                                                      | Workload |
| [Tiller Is Deployed]                       | Check if Helm Tiller component is deployed.                                                                                                                                                                         | Workload |
| [Image tag ':latest' used]                 | It is best to avoid using the ':latest' image tag when deploying containers in production. Doing so makes it hard to track which version of the image is running, and hard to roll back the version.                | Workload |

## Advanced

| NAME                                                           | DESCRIPTION                                                                                                                              | KINDS         |
|----------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|---------------|
| [Unused capabilities should be dropped (drop any)]             | Security best practices require containers to run with minimal required capabilities.                                                    | Workload      |
| [hostAliases is set]                                           | Managing /etc/hosts aliases can prevent the container engine from modifying the file after a pod’s containers have already been started. | Workload      |
| [User Pods should not be placed in kube-system namespace]      | ensure that User pods are not placed in kube-system namespace                                                                            | Workload      |
| [Protecting Pod service account tokens]                        | ensure that Pod specifications disable the secret token being mounted by setting automountServiceAccountToken: false                     | Workload      |
| [Selector usage in network policies]                           | ensure that network policies selectors are applied to pods or namespaces to restricted ingress and egress traffic within the pod network | NetworkPolicy |
| [limit range usage]                                            | ensure limit range policy has configure in order to limit resource usage for namespaces or nodes                                         | LimitRange    |
| [resource quota usage]                                         | ensure resource quota policy has configure in order to limit aggregate resource usage within namespace                                   | ResourceQuota |
| [All container images must start with the *.azurecr.io domain] | Containers should only use images from trusted registries.                                                                               | Workload      |
| [All container images must start with a GCR domain]            | Containers should only use images from trusted GCR registries.                                                                           | Workload      |

## Pod Security Standard

### Baseline

| NAME                               | DESCRIPTION                                                                                                                                                                                                                                                                              | KINDS    |
|------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------|
| [Access to host IPC namespace]     | Sharing the host’s IPC namespace allows container processes to communicate with processes on the host.                                                                                                                                                                                   | Workload |
| [Access to host network]           | Sharing the host’s network namespace permits processes in the pod to communicate with processes bound to the host’s loopback adapter.                                                                                                                                                    | Workload |
| [Access to host PID]               | Sharing the host’s PID namespace allows visibility on host processes, potentially leaking information such as environment variables and configuration.                                                                                                                                   | Workload |
| [Privileged container]             | Privileged containers share namespaces with the host system and do not offer any security. They should be used exclusively for system containers that require high privileges.                                                                                                           | Workload |
| [Non-default capabilities added]   | Adding NET_RAW or capabilities beyond the default set must be disallowed.                                                                                                                                                                                                                | Workload |
| [hostPath volumes mounted]         | HostPath volumes must be forbidden.                                                                                                                                                                                                                                                      | Workload |
| [Access to host ports]             | HostPorts should be disallowed, or at minimum restricted to a known list.                                                                                                                                                                                                                | Workload |
| [Default AppArmor profile not set] | A program inside the container can bypass AppArmor protection policies.                                                                                                                                                                                                                  | Workload |
| [SELinux custom options set]       | Setting a custom SELinux user or role option should be forbidden.                                                                                                                                                                                                                        | Workload |
| [Non-default /proc masks set]      | The default /proc masks are set up to reduce attack surface, and should be required.                                                                                                                                                                                                     | Workload |
| [Unsafe sysctl options set]        | Sysctls can disable security mechanisms or affect all containers on a host, and should be disallowed except for an allowed 'safe' subset. A sysctl is considered safe if it is namespaced in the container or the Pod, and it is isolated from other Pods or processes on the same Node. | Workload |

### Restricted

| NAME                                      | DESCRIPTION                                                                                                                                      | KINDS    |
|-------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|----------|
| [Non-ephemeral volume types used]         | In addition to restricting HostPath volumes, usage of non-ephemeral volume types should be limited to those defined through PersistentVolumes.   | Workload |
| [Process can elevate its own privileges]  | A program inside the container can elevate its own privileges and run as root, which might give the program control over the container and node. | Workload |
| [Runs as root user]                       | 'runAsNonRoot' forces the running image to run as a non-root user to ensure least privileges.                                                    | Workload |
| [A root primary or supplementary GID set] | Containers should be forbidden from running with a root primary or supplementary GID.                                                            | Workload |
| [Default Seccomp profile not set]         | The RuntimeDefault seccomp profile must be required, or allow specific additional profiles.                                                      | Workload |

[Writing Custom Configuration Audit Policies]: ./../tutorials/writing-custom-configuration-audit-policies.md

[CPU not limited]: https://avd.aquasec.com/misconfig/kubernetes/ksv011/
[CPU requests not specified]: https://avd.aquasec.com/misconfig/kubernetes/ksv015/
[SYS_ADMIN capability added]: https://avd.aquasec.com/misconfig/kubernetes/ksv005/
[Default capabilities not dropped]: https://avd.aquasec.com/misconfig/kubernetes/ksv003/
[Root file system is not read-only]: https://avd.aquasec.com/misconfig/kubernetes/ksv014/
[Memory not limited]: https://avd.aquasec.com/misconfig/kubernetes/ksv018/
[Memory requests not specified]: https://avd.aquasec.com/misconfig/kubernetes/ksv016/
[hostPath volume mounted with docker.sock]: https://avd.aquasec.com/misconfig/kubernetes/ksv006/
[Runs with low group ID]: https://avd.aquasec.com/misconfig/kubernetes/ksv021/
[Runs with low user ID]: https://avd.aquasec.com/misconfig/kubernetes/ksv020/
[Tiller Is Deployed]: https://avd.aquasec.com/misconfig/kubernetes/ksv102/
[Image tag ':latest' used]: https://avd.aquasec.com/misconfig/kubernetes/ksv013/

[Unused capabilities should be dropped (drop any)]: https://avd.aquasec.com/misconfig/kubernetes/ksv004/
[hostAliases is set]: https://avd.aquasec.com/misconfig/kubernetes/ksv007/
[User Pods should not be placed in kube-system namespace]: https://avd.aquasec.com/misconfig/kubernetes/ksv037/
[Protecting Pod service account tokens]: https://avd.aquasec.com/misconfig/kubernetes/ksv036/
[Selector usage in network policies]: https://avd.aquasec.com/misconfig/kubernetes/ksv038/
[limit range usage]: https://avd.aquasec.com/misconfig/kubernetes/ksv039/
[resource quota usage]: https://avd.aquasec.com/misconfig/kubernetes/ksv040/
[All container images must start with the *.azurecr.io domain]: https://avd.aquasec.com/misconfig/kubernetes/ksv032/
[All container images must start with a GCR domain]: https://avd.aquasec.com/misconfig/kubernetes/ksv033/

[Access to host IPC namespace]: https://avd.aquasec.com/misconfig/kubernetes/ksv008/
[Access to host network]: https://avd.aquasec.com/misconfig/kubernetes/ksv009/
[Access to host PID]: https://avd.aquasec.com/misconfig/kubernetes/ksv010/
[Privileged container]: https://avd.aquasec.com/misconfig/kubernetes/ksv017/
[Non-default capabilities added]: https://avd.aquasec.com/misconfig/kubernetes/ksv022/
[hostPath volumes mounted]: https://avd.aquasec.com/misconfig/kubernetes/ksv023/
[Access to host ports]: https://avd.aquasec.com/misconfig/kubernetes/ksv024/
[Default AppArmor profile not set]: https://avd.aquasec.com/misconfig/kubernetes/ksv002/
[SELinux custom options set]: https://avd.aquasec.com/misconfig/kubernetes/ksv025/
[Non-default /proc masks set]: https://avd.aquasec.com/misconfig/kubernetes/ksv027/
[Unsafe sysctl options set]: https://avd.aquasec.com/misconfig/kubernetes/ksv026/

[Non-ephemeral volume types used]: https://avd.aquasec.com/misconfig/kubernetes/ksv028/
[Process can elevate its own privileges]: https://avd.aquasec.com/misconfig/kubernetes/ksv001/
[Runs as root user]: https://avd.aquasec.com/misconfig/kubernetes/ksv012/
[A root primary or supplementary GID set]: https://avd.aquasec.com/misconfig/kubernetes/ksv029/
[Default Seccomp profile not set]: https://avd.aquasec.com/misconfig/kubernetes/ksv030/