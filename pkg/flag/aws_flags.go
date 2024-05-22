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
	awsServiceFlag = Flag[[]string]{
		Name:       "service",
		ConfigName: "cloud.aws.service",
		Usage:      "Only scan AWS Service(s) specified with this flag. Can specify multiple services using --service A --service B etc.",
	}
	awsSkipServicesFlag = Flag[[]string]{
		Name:       "skip-service",
		ConfigName: "cloud.aws.skip-service",
		Usage:      "Skip selected AWS Service(s) specified with this flag. Can specify multiple services using --skip-service A --skip-service B etc.",
	}
	awsAccountFlag = Flag[string]{
		Name:       "account",
		ConfigName: "cloud.aws.account",
		Usage:      "The AWS account to scan. It's useful to specify this when reviewing cached results for multiple accounts.",
	}
	awsARNFlag = Flag[string]{
		Name:       "arn",
		ConfigName: "cloud.aws.arn",
		Usage:      "The AWS ARN to show results for. Useful to filter results once a scan is cached.",
	}
)

type AWSFlagGroup struct {
	Region       *Flag[string]
	Endpoint     *Flag[string]
	Services     *Flag[[]string]
	SkipServices *Flag[[]string]
	Account      *Flag[string]
	ARN          *Flag[string]
}

type AWSOptions struct {
	Region       string
	Endpoint     string
	Services     []string
	SkipServices []string
	Account      string
	ARN          string
}

func NewAWSFlagGroup() *AWSFlagGroup {
	return &AWSFlagGroup{
		Region:       awsRegionFlag.Clone(),
		Endpoint:     awsEndpointFlag.Clone(),
		Services:     awsServiceFlag.Clone(),
		SkipServices: awsSkipServicesFlag.Clone(),
		Account:      awsAccountFlag.Clone(),
		ARN:          awsARNFlag.Clone(),
	}
}

func (f *AWSFlagGroup) Name() string {
	return "AWS"
}

func (f *AWSFlagGroup) Flags() []Flagger {
	return []Flagger{
		f.Region,
		f.Endpoint,
		f.Services,
		f.SkipServices,
		f.Account,
		f.ARN,
	}
}

func (f *AWSFlagGroup) ToOptions() (AWSOptions, error) {
	if err := parseFlags(f); err != nil {
		return AWSOptions{}, err
	}
	return AWSOptions{
		Region:       f.Region.Value(),
		Endpoint:     f.Endpoint.Value(),
		Services:     f.Services.Value(),
		SkipServices: f.SkipServices.Value(),
		Account:      f.Account.Value(),
		ARN:          f.ARN.Value(),
	}, nil
}
