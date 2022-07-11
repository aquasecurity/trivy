package flag

var (
	cloudUpdateCacheFlag = Flag{
		Name:       "update-cache",
		ConfigName: "cloud.update-cache",
		Value:      false,
		Usage:      "Update the cache for the applicable cloud provider instead of using cached results.",
	}
)

type CloudFlagGroup struct {
	UpdateCache *Flag
}

type CloudOptions struct {
	UpdateCache bool
}

func NewCloudFlagGroup() *CloudFlagGroup {
	return &CloudFlagGroup{
		UpdateCache: &cloudUpdateCacheFlag,
	}
}

func (f *CloudFlagGroup) Name() string {
	return "Cloud"
}

func (f *CloudFlagGroup) Flags() []*Flag {
	return []*Flag{f.UpdateCache}
}

func (f *CloudFlagGroup) ToOptions() CloudOptions {
	return CloudOptions{
		UpdateCache: getBool(f.UpdateCache),
	}
}
