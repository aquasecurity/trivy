package bottlerocket

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

var pkgs = []types.Package{
	{
		ID:      "amazon-ecs-cni-plugins@2024.09.0",
		Name:    "amazon-ecs-cni-plugins",
		Version: "2024.09.0",
		Arch:    "x86_64",
	},
	{
		ID:      "amazon-ecs-cni-plugins-bin@2024.09.0",
		Name:    "amazon-ecs-cni-plugins-bin",
		Version: "2024.09.0",
		Arch:    "x86_64",
	},
	{
		ID:      "amazon-ecs-cni-plugins-ecs-agent-extras@2024.09.0",
		Name:    "amazon-ecs-cni-plugins-ecs-agent-extras",
		Version: "2024.09.0",
		Arch:    "x86_64",
	},
	{
		ID:      "amazon-ssm-agent-plugin@3.3.1345.0",
		Name:    "amazon-ssm-agent-plugin",
		Version: "3.3.1345.0",
		Arch:    "x86_64",
	},
	{
		ID:      "amazon-ssm-agent-plugin-bin@3.3.1345.0",
		Name:    "amazon-ssm-agent-plugin-bin",
		Version: "3.3.1345.0",
		Arch:    "x86_64",
	},
	{
		ID:      "amazon-vpc-cni-plugins@1.3",
		Name:    "amazon-vpc-cni-plugins",
		Version: "1.3",
		Arch:    "x86_64",
	},
	{
		ID:      "amazon-vpc-cni-plugins-bin@1.3",
		Name:    "amazon-vpc-cni-plugins-bin",
		Version: "1.3",
		Arch:    "x86_64",
	},
	{
		ID:      "amazon-vpc-cni-plugins-ecs-agent-extras@1.3",
		Name:    "amazon-vpc-cni-plugins-ecs-agent-extras",
		Version: "1.3",
		Arch:    "x86_64",
	},
	{
		ID:      "apiclient@0.0",
		Name:    "apiclient",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "apiclient-bin@0.0",
		Name:    "apiclient-bin",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "apiserver@0.0",
		Name:    "apiserver",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "audit@4.0.2",
		Name:    "audit",
		Version: "4.0.2",
		Arch:    "x86_64",
	},
	{
		ID:      "bloodhound@0.0",
		Name:    "bloodhound",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "bootstrap-commands@0.0",
		Name:    "bootstrap-commands",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "bootstrap-containers@0.0",
		Name:    "bootstrap-containers",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "bork@0.0",
		Name:    "bork",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "certdog@0.0",
		Name:    "certdog",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "cfsignal@0.0",
		Name:    "cfsignal",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "cfsignal-bin@0.0",
		Name:    "cfsignal-bin",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "chrony@4.6.1",
		Name:    "chrony",
		Version: "4.6.1",
		Arch:    "x86_64",
	},
	{
		ID:      "conntrack-tools@1.4.8",
		Name:    "conntrack-tools",
		Version: "1.4.8",
		Arch:    "x86_64",
	},
	{
		ID:      "containerd@1.7.25",
		Name:    "containerd",
		Version: "1.7.25",
		Arch:    "x86_64",
	},
	{
		ID:      "containerd-bin@1.7.25",
		Name:    "containerd-bin",
		Version: "1.7.25",
		Arch:    "x86_64",
	},
	{
		ID:      "coreutils@9.5",
		Name:    "coreutils",
		Version: "9.5",
		Arch:    "x86_64",
	},
	{
		ID:      "corndog@0.0",
		Name:    "corndog",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "dbus-broker@36",
		Name:    "dbus-broker",
		Version: "36",
		Arch:    "x86_64",
	},
	{
		ID:      "docker-cli@25.0.5",
		Name:    "docker-cli",
		Version: "25.0.5",
		Arch:    "x86_64",
	},
	{
		ID:      "docker-cli-bin@25.0.5",
		Name:    "docker-cli-bin",
		Version: "25.0.5",
		Arch:    "x86_64",
	},
	{
		ID:      "docker-engine@25.0.6",
		Name:    "docker-engine",
		Version: "25.0.6",
		Arch:    "x86_64",
	},
	{
		ID:      "docker-engine-bin@25.0.6",
		Name:    "docker-engine-bin",
		Version: "25.0.6",
		Arch:    "x86_64",
	},
	{
		ID:      "docker-init@19.03.15",
		Name:    "docker-init",
		Version: "19.03.15",
		Arch:    "x86_64",
	},
	{
		ID:      "e2fsprogs@1.47.1",
		Name:    "e2fsprogs",
		Version: "1.47.1",
		Arch:    "x86_64",
	},
	{
		ID:      "e2fsprogs-libs@1.47.1",
		Name:    "e2fsprogs-libs",
		Version: "1.47.1",
		Arch:    "x86_64",
	},
	{
		ID:      "early-boot-config@0.1",
		Name:    "early-boot-config",
		Version: "0.1",
		Arch:    "x86_64",
	},
	{
		ID:      "early-boot-config-aws@0.1",
		Name:    "early-boot-config-aws",
		Version: "0.1",
		Arch:    "x86_64",
	},
	{
		ID:      "early-boot-config-local@0.1",
		Name:    "early-boot-config-local",
		Version: "0.1",
		Arch:    "x86_64",
	},
	{
		ID:      "ecs-agent@1.89.2",
		Name:    "ecs-agent",
		Version: "1.89.2",
		Arch:    "x86_64",
	},
	{
		ID:      "ecs-agent-bin@1.89.2",
		Name:    "ecs-agent-bin",
		Version: "1.89.2",
		Arch:    "x86_64",
	},
	{
		ID:      "ecs-agent-config@1.89.2",
		Name:    "ecs-agent-config",
		Version: "1.89.2",
		Arch:    "x86_64",
	},
	{
		ID:      "ethtool@6.11",
		Name:    "ethtool",
		Version: "6.11",
		Arch:    "x86_64",
	},
	{
		ID:      "filesystem@1.0",
		Name:    "filesystem",
		Version: "1.0",
		Arch:    "x86_64",
	},
	{
		ID:      "findutils@4.10.0",
		Name:    "findutils",
		Version: "4.10.0",
		Arch:    "x86_64",
	},
	{
		ID:      "ghostdog@0.0",
		Name:    "ghostdog",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "glibc@2.40",
		Name:    "glibc",
		Version: "2.40",
		Arch:    "x86_64",
	},
	{
		ID:      "grep@3.11",
		Name:    "grep",
		Version: "3.11",
		Arch:    "x86_64",
	},
	{
		ID:      "grub@2.06",
		Name:    "grub",
		Version: "2.06",
		Arch:    "x86_64",
	},
	{
		ID:      "host-containers@0.0",
		Name:    "host-containers",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "host-ctr@0.0",
		Name:    "host-ctr",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "host-ctr-bin@0.0",
		Name:    "host-ctr-bin",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "hostname-imds@0.1.1",
		Name:    "hostname-imds",
		Version: "0.1.1",
		Arch:    "x86_64",
	},
	{
		ID:      "hostname-reverse-dns@0.1.1",
		Name:    "hostname-reverse-dns",
		Version: "0.1.1",
		Arch:    "x86_64",
	},
	{
		ID:      "iproute@6.12.0",
		Name:    "iproute",
		Version: "6.12.0",
		Arch:    "x86_64",
	},
	{
		ID:      "iptables@1.8.11",
		Name:    "iptables",
		Version: "1.8.11",
		Arch:    "x86_64",
	},
	{
		ID:      "kernel-6.1@6.1.128",
		Name:    "kernel-6.1",
		Version: "6.1.128",
		Arch:    "x86_64",
	},
	{
		ID:      "kernel-6.1-bootconfig-aws@6.1.128",
		Name:    "kernel-6.1-bootconfig-aws",
		Version: "6.1.128",
		Arch:    "x86_64",
	},
	{
		ID:      "kernel-6.1-devel@6.1.128",
		Name:    "kernel-6.1-devel",
		Version: "6.1.128",
		Arch:    "x86_64",
	},
	{
		ID:      "kernel-6.1-devel-squashed@6.1.128",
		Name:    "kernel-6.1-devel-squashed",
		Version: "6.1.128",
		Arch:    "x86_64",
	},
	{
		ID:      "kernel-6.1-modules@6.1.128",
		Name:    "kernel-6.1-modules",
		Version: "6.1.128",
		Arch:    "x86_64",
	},
	{
		ID:      "kernel-6.1-modules-neuron@6.1.128",
		Name:    "kernel-6.1-modules-neuron",
		Version: "6.1.128",
		Arch:    "x86_64",
	},
	{
		ID:      "kexec-tools@2.0.29",
		Name:    "kexec-tools",
		Version: "2.0.29",
		Arch:    "x86_64",
	},
	{
		ID:      "keyutils@1.6.1",
		Name:    "keyutils",
		Version: "1.6.1",
		Arch:    "x86_64",
	},
	{
		ID:      "kmod@33",
		Name:    "kmod",
		Version: "33",
		Arch:    "x86_64",
	},
	{
		ID:      "libacl@2.3.2",
		Name:    "libacl",
		Version: "2.3.2",
		Arch:    "x86_64",
	},
	{
		ID:      "libattr@2.5.2",
		Name:    "libattr",
		Version: "2.5.2",
		Arch:    "x86_64",
	},
	{
		ID:      "libaudit@4.0.2",
		Name:    "libaudit",
		Version: "4.0.2",
		Arch:    "x86_64",
	},
	{
		ID:      "libblkid@2.40.2",
		Name:    "libblkid",
		Version: "2.40.2",
		Arch:    "x86_64",
	},
	{
		ID:      "libcap@2.70",
		Name:    "libcap",
		Version: "2.70",
		Arch:    "x86_64",
	},
	{
		ID:      "libelf@0.192",
		Name:    "libelf",
		Version: "0.192",
		Arch:    "x86_64",
	},
	{
		ID:      "libexpat@2.6.4",
		Name:    "libexpat",
		Version: "2.6.4",
		Arch:    "x86_64",
	},
	{
		ID:      "libfdisk@2.40.2",
		Name:    "libfdisk",
		Version: "2.40.2",
		Arch:    "x86_64",
	},
	{
		ID:      "libgcc@0.0",
		Name:    "libgcc",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "libinih@58",
		Name:    "libinih",
		Version: "58",
		Arch:    "x86_64",
	},
	{
		ID:      "libjson-c@0.18",
		Name:    "libjson-c",
		Version: "0.18",
		Arch:    "x86_64",
	},
	{
		ID:      "libmnl@1.0.5",
		Name:    "libmnl",
		Version: "1.0.5",
		Arch:    "x86_64",
	},
	{
		ID:      "libmount@2.40.2",
		Name:    "libmount",
		Version: "2.40.2",
		Arch:    "x86_64",
	},
	{
		ID:      "libncurses@6.5",
		Name:    "libncurses",
		Version: "6.5",
		Arch:    "x86_64",
	},
	{
		ID:      "libnetfilter_conntrack@1.1.0",
		Name:    "libnetfilter_conntrack",
		Version: "1.1.0",
		Arch:    "x86_64",
	},
	{
		ID:      "libnetfilter_cthelper@1.0.1",
		Name:    "libnetfilter_cthelper",
		Version: "1.0.1",
		Arch:    "x86_64",
	},
	{
		ID:      "libnetfilter_cttimeout@1.0.1",
		Name:    "libnetfilter_cttimeout",
		Version: "1.0.1",
		Arch:    "x86_64",
	},
	{
		ID:      "libnetfilter_queue@1.0.5",
		Name:    "libnetfilter_queue",
		Version: "1.0.5",
		Arch:    "x86_64",
	},
	{
		ID:      "libnfnetlink@1.0.2",
		Name:    "libnfnetlink",
		Version: "1.0.2",
		Arch:    "x86_64",
	},
	{
		ID:      "libnftnl@1.2.8",
		Name:    "libnftnl",
		Version: "1.2.8",
		Arch:    "x86_64",
	},
	{
		ID:      "libnl@3.11.0",
		Name:    "libnl",
		Version: "3.11.0",
		Arch:    "x86_64",
	},
	{
		ID:      "libnvme@1.11",
		Name:    "libnvme",
		Version: "1.11",
		Arch:    "x86_64",
	},
	{
		ID:      "libpcre@10.44",
		Name:    "libpcre",
		Version: "10.44",
		Arch:    "x86_64",
	},
	{
		ID:      "libseccomp@2.5.5",
		Name:    "libseccomp",
		Version: "2.5.5",
		Arch:    "x86_64",
	},
	{
		ID:      "libselinux@3.7",
		Name:    "libselinux",
		Version: "3.7",
		Arch:    "x86_64",
	},
	{
		ID:      "libselinux-utils@3.7",
		Name:    "libselinux-utils",
		Version: "3.7",
		Arch:    "x86_64",
	},
	{
		ID:      "libsemanage@3.7",
		Name:    "libsemanage",
		Version: "3.7",
		Arch:    "x86_64",
	},
	{
		ID:      "libsepol@3.7",
		Name:    "libsepol",
		Version: "3.7",
		Arch:    "x86_64",
	},
	{
		ID:      "libsmartcols@2.40.2",
		Name:    "libsmartcols",
		Version: "2.40.2",
		Arch:    "x86_64",
	},
	{
		ID:      "libstd-rust@0.0",
		Name:    "libstd-rust",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "liburcu@0.14.1",
		Name:    "liburcu",
		Version: "0.14.1",
		Arch:    "x86_64",
	},
	{
		ID:      "libuuid@2.40.2",
		Name:    "libuuid",
		Version: "2.40.2",
		Arch:    "x86_64",
	},
	{
		ID:      "libxcrypt@4.4.36",
		Name:    "libxcrypt",
		Version: "4.4.36",
		Arch:    "x86_64",
	},
	{
		ID:      "libz@1.3.1",
		Name:    "libz",
		Version: "1.3.1",
		Arch:    "x86_64",
	},
	{
		ID:      "libzstd@1.5.6",
		Name:    "libzstd",
		Version: "1.5.6",
		Arch:    "x86_64",
	},
	{
		ID:      "logdog@0.0",
		Name:    "logdog",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "logdog-bin@0.0",
		Name:    "logdog-bin",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "makedumpfile@1.7.5",
		Name:    "makedumpfile",
		Version: "1.7.5",
		Arch:    "x86_64",
	},
	{
		ID:      "mdadm@4.3",
		Name:    "mdadm",
		Version: "4.3",
		Arch:    "x86_64",
	},
	{
		ID:      "bottlerocket-metadata@1.0",
		Name:    "bottlerocket-metadata",
		Version: "1.0",
		Arch:    "x86_64",
	},
	{
		ID:      "metricdog@0.0",
		Name:    "metricdog",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "metricdog-bin@0.0",
		Name:    "metricdog-bin",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "microcode-amd-license@0.0",
		Name:    "microcode-amd-license",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "microcode-intel-license@0.0",
		Name:    "microcode-intel-license",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "microcode-licenses@0.0",
		Name:    "microcode-licenses",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "migration@0.0",
		Name:    "migration",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "migration-bin@0.0",
		Name:    "migration-bin",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "netdog@0.1.1",
		Name:    "netdog",
		Version: "0.1.1",
		Arch:    "x86_64",
	},
	{
		ID:      "netdog-systemd-networkd@0.1.1",
		Name:    "netdog-systemd-networkd",
		Version: "0.1.1",
		Arch:    "x86_64",
	},
	{
		ID:      "nvme-cli@2.11",
		Name:    "nvme-cli",
		Version: "2.11",
		Arch:    "x86_64",
	},
	{
		ID:      "oci-add-hooks@1.0.0",
		Name:    "oci-add-hooks",
		Version: "1.0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "os@0.0",
		Name:    "os",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "pciutils@3.13.0",
		Name:    "pciutils",
		Version: "3.13.0",
		Arch:    "x86_64",
	},
	{
		ID:      "pigz@2.8",
		Name:    "pigz",
		Version: "2.8",
		Arch:    "x86_64",
	},
	{
		ID:      "policycoreutils@3.7",
		Name:    "policycoreutils",
		Version: "3.7",
		Arch:    "x86_64",
	},
	{
		ID:      "prairiedog@0.0",
		Name:    "prairiedog",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "procps@4.0.4",
		Name:    "procps",
		Version: "4.0.4",
		Arch:    "x86_64",
	},
	{
		ID:      "rdma-core@54.0",
		Name:    "rdma-core",
		Version: "54.0",
		Arch:    "x86_64",
	},
	{
		ID:      "release@0.0",
		Name:    "release",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "runc@1.1.15",
		Name:    "runc",
		Version: "1.1.15",
		Arch:    "x86_64",
	},
	{
		ID:      "runc-bin@1.1.15",
		Name:    "runc-bin",
		Version: "1.1.15",
		Arch:    "x86_64",
	},
	{
		ID:      "schnauzer@0.0",
		Name:    "schnauzer",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "selinux-policy@0.0",
		Name:    "selinux-policy",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "settings-committer@0.0",
		Name:    "settings-committer",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "bottlerocket-settings-defaults@0.0",
		Name:    "bottlerocket-settings-defaults",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "bottlerocket-settings-defaults-aws-ecs-2@0.0",
		Name:    "bottlerocket-settings-defaults-aws-ecs-2",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "bottlerocket-settings-plugins@0.0",
		Name:    "bottlerocket-settings-plugins",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "bottlerocket-settings-plugins-aws-ecs-2@0.0",
		Name:    "bottlerocket-settings-plugins-aws-ecs-2",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "shibaken@0.0",
		Name:    "shibaken",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "shibaken-bin@0.0",
		Name:    "shibaken-bin",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "shim@15.8",
		Name:    "shim",
		Version: "15.8",
		Arch:    "x86_64",
	},
	{
		ID:      "shimpei@0.0",
		Name:    "shimpei",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "signpost@0.0",
		Name:    "signpost",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "storewolf@0.0",
		Name:    "storewolf",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "sundog@0.0",
		Name:    "sundog",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "systemd@252.22",
		Name:    "systemd",
		Version: "252.22",
		Arch:    "x86_64",
	},
	{
		ID:      "systemd-networkd@252.22",
		Name:    "systemd-networkd",
		Version: "252.22",
		Arch:    "x86_64",
	},
	{
		ID:      "systemd-resolved@252.22",
		Name:    "systemd-resolved",
		Version: "252.22",
		Arch:    "x86_64",
	},
	{
		ID:      "thar-be-settings@0.0",
		Name:    "thar-be-settings",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "thar-be-updates@0.0",
		Name:    "thar-be-updates",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "updog@0.0",
		Name:    "updog",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "updog-bin@0.0",
		Name:    "updog-bin",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "util-linux@2.40.2",
		Name:    "util-linux",
		Version: "2.40.2",
		Arch:    "x86_64",
	},
	{
		ID:      "xfscli@0.0",
		Name:    "xfscli",
		Version: "0.0",
		Arch:    "x86_64",
	},
	{
		ID:      "xfsprogs@6.9.0",
		Name:    "xfsprogs",
		Version: "6.9.0",
		Arch:    "x86_64",
	},
}

func TestParseApplicationInventory(t *testing.T) {
	var tests = []struct {
		name     string
		path     string
		wantPkgs []types.Package
	}{
		{
			name:     "happy path",
			path:     "./testdata/application-inventory.json",
			wantPkgs: pkgs,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := bottlerocketPkgAnalyzer{}
			f, err := os.Open(tt.path)
			require.NoError(t, err)
			defer f.Close()
			gotPkgs, err := a.parseApplicationInventory(context.Background(), f)
			require.NoError(t, err)

			assert.Equal(t, tt.wantPkgs, gotPkgs)
		})
	}
}
