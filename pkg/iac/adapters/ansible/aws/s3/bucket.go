package s3

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/s3"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/parser"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type adapter struct {
	tasks     parser.Tasks
	bucketMap map[string]*s3.Bucket
}

func (a *adapter) adaptBuckets() []s3.Bucket {
	var buckets []s3.Bucket

	for _, module := range a.tasks.GetModules("s3_bucket", "amazon.aws.s3_bucket") {
		buckets = append(buckets, a.adaptBucket(module))
	}

	return buckets
}

func (a *adapter) adaptBucket(module parser.Module) s3.Bucket {
	return s3.Bucket{
		Metadata:          module.Metadata(),
		Name:              module.GetStringAttr("name"),
		Versioning:        getVersioning(module),
		Encryption:        getEncryption(module),
		PublicAccessBlock: getPublicAccessBlock(module),
		Logging:           a.getLogging(module),
		ACL:               module.GetStringAttr("acl"),
		Website:           a.getWebsite(module),
	}
}

func getVersioning(module parser.Module) s3.Versioning {
	return s3.Versioning{
		Metadata:  module.Metadata(),
		Enabled:   module.GetBoolAttr("versioning"),
		MFADelete: iacTypes.BoolUnresolvable(module.Metadata()),
	}
}

func getEncryption(module parser.Module) s3.Encryption {
	return s3.Encryption{
		Metadata:  module.Metadata(),
		Algorithm: module.GetStringAttr("encryption"),
		KMSKeyId:  module.GetStringAttr("encryption_key_id"),
		Enabled:   iacTypes.Bool(false, module.Metadata()), // TODO: handle
	}
}

func getPublicAccessBlock(module parser.Module) *s3.PublicAccessBlock {
	publicAccess := module.GetAttr("public_access")
	if publicAccess.IsNil() {
		return &s3.PublicAccessBlock{
			Metadata: module.Metadata(),
		}
	}
	return &s3.PublicAccessBlock{
		Metadata:              publicAccess.Metadata(),
		BlockPublicACLs:       publicAccess.GetBoolAttr("block_public_acls"),
		BlockPublicPolicy:     publicAccess.GetBoolAttr("block_public_policy"),
		IgnorePublicACLs:      publicAccess.GetBoolAttr("ignore_public_acls"),
		RestrictPublicBuckets: publicAccess.GetBoolAttr("restrict_public_buckets"),
	}
}

func (a *adapter) getLogging(module parser.Module) s3.Logging {
	// TODO: adapt
	return s3.Logging{
		Metadata: module.Metadata(),
	}
}

func (a *adapter) getWebsite(module parser.Module) *s3.Website {
	// TODO: adapt
	return &s3.Website{
		Metadata: module.Metadata(),
	}
}
