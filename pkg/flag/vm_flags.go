package flag

var (
	awsRegionFlag = Flag[string]{
		Name:       "region",
		ConfigName: "cloud.aws.region",
		Usage:      "AWS Region to scan",
	}
	awsEndpointFlag = Flag[string]{
		Name:       "endpoint",
		ConfigName: "cloud.aws.endpoint",
		Usage:      "AWS Endpoint override",
	}
)

type VMFlagGroup struct {
	Region       *Flag[string]
	Endpoint     *Flag[string]
}

type VMOptions struct {
	Region       string
	Endpoint     string
}

func NewVMFlagGroup() *VMFlagGroup {
	return &VMFlagGroup{
		Region:       awsRegionFlag.Clone(),
		Endpoint:     awsEndpointFlag.Clone(),
	}
}

func (f *VMFlagGroup) Name() string {
	return "AWS"
}

func (f *VMFlagGroup) Flags() []Flagger {
	return []Flagger{
		f.Region,
		f.Endpoint,
	}
}

func (f *VMFlagGroup) ToOptions(opts *Options) error {
	opts.VMOptions = VMOptions{
		Region:       f.Region.Value(),
		Endpoint:     f.Endpoint.Value(),
	}
	return nil
}
