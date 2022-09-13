package flag

import "time"

var (
	cloudUpdateCacheFlag = Flag{
		Name:       "update-cache",
		ConfigName: "cloud.update-cache",
		Value:      false,
		Usage:      "Update the cache for the applicable cloud provider instead of using cached results.",
	}
	cloudMaxCacheAgeFlag = Flag{
		Name:       "max-cache-age",
		ConfigName: "cloud.max-cache-age",
		Value:      time.Hour * 24,
		Usage:      "The maximum age of the cloud cache. Cached data will be requeried from the cloud provider if it is older than this.",
	}
)

type CloudFlagGroup struct {
	UpdateCache *Flag
	MaxCacheAge *Flag
}

type CloudOptions struct {
	MaxCacheAge time.Duration
	UpdateCache bool
}

func NewCloudFlagGroup() *CloudFlagGroup {
	return &CloudFlagGroup{
		UpdateCache: &cloudUpdateCacheFlag,
		MaxCacheAge: &cloudMaxCacheAgeFlag,
	}
}

func (f *CloudFlagGroup) Name() string {
	return "Cloud"
}

func (f *CloudFlagGroup) Flags() []*Flag {
	return []*Flag{f.UpdateCache, f.MaxCacheAge}
}

func (f *CloudFlagGroup) ToOptions() CloudOptions {
	return CloudOptions{
		UpdateCache: getBool(f.UpdateCache),
		MaxCacheAge: getDuration(f.MaxCacheAge),
	}
}
