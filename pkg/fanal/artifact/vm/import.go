package vm

import (
	// Register Filesystem
	_ "github.com/aquasecurity/trivy/pkg/fanal/vm/filesystem/ext4"
	_ "github.com/aquasecurity/trivy/pkg/fanal/vm/filesystem/xfs"
	// Register VirtualMachineImage
	_ "github.com/aquasecurity/trivy/pkg/fanal/vm/vmdk"
)
