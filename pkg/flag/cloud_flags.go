package flag

import "time"

var (
	cloudUpdateCacheFlag = Flag[bool]{
		Name:       "update-cache",
		ConfigName: "cloud.update-cache",
		Usage:      "Update the cache for the applicable cloud provider instead of using cached results.",
	}
	cloudMaxCacheAgeFlag = Flag[time.Duration]{
		Name:       "max-cache-age",
		ConfigName: "cloud.max-cache-age",
		Default:    time.Hour * 24,
		Usage:      "The maximum age of the cloud cache. Cached data will be requeried from the cloud provider if it is older than this.",
	}
)

type CloudFlagGroup struct {
	UpdateCache *Flag[bool]
	MaxCacheAge *Flag[time.Duration]
}

type CloudOptions struct {
	MaxCacheAge time.Duration
	UpdateCache bool
}

func NewCloudFlagGroup() *CloudFlagGroup {
	return &CloudFlagGroup{
		UpdateCache: cloudUpdateCacheFlag.Clone(),
		MaxCacheAge: cloudMaxCacheAgeFlag.Clone(),
	}
}

func (f *CloudFlagGroup) Name() string {
	return "Cloud"
}

func (f *CloudFlagGroup) Flags() []Flagger {
	return []Flagger{
		f.UpdateCache,
		f.MaxCacheAge,
	}
}

func (f *CloudFlagGroup) ToOptions() (CloudOptions, error) {
	if err := parseFlags(f); err != nil {
		return CloudOptions{}, err
	}
	return CloudOptions{
		UpdateCache: f.UpdateCache.Value(),
		MaxCacheAge: f.MaxCacheAge.Value(),
	}, nil
}
