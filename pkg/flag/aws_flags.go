package flag

var (
	awsRegionFlag = Flag{
		Name:       "region",
		ConfigName: "cloud.aws.region",
		Value:      "",
		Usage:      "AWS Region to scan",
	}
	awsEndpointFlag = Flag{
		Name:       "endpoint",
		ConfigName: "cloud.aws.endpoint",
		Value:      "",
		Usage:      "AWS Endpoint override",
	}
	awsServiceFlag = Flag{
		Name:       "service",
		ConfigName: "cloud.aws.service",
		Value:      []string{},
		Usage:      "Only scan AWS Service(s) specified with this flag. Can specify multiple services using --service A --service B etc.",
	}
	awsSkipServicesFlag = Flag{
		Name:       "skip-service",
		ConfigName: "cloud.aws.skip-service",
		Value:      []string{},
		Usage:      "Skip selected AWS Service(s) specified with this flag. Can specify multiple services using --skip-service A --skip-service B etc.",
	}
	awsAccountFlag = Flag{
		Name:       "account",
		ConfigName: "cloud.aws.account",
		Value:      "",
		Usage:      "The AWS account to scan. It's useful to specify this when reviewing cached results for multiple accounts.",
	}
	awsARNFlag = Flag{
		Name:       "arn",
		ConfigName: "cloud.aws.arn",
		Value:      "",
		Usage:      "The AWS ARN to show results for. Useful to filter results once a scan is cached.",
	}
)

type AWSFlagGroup struct {
	Region       *Flag
	Endpoint     *Flag
	Services     *Flag
	SkipServices *Flag
	Account      *Flag
	ARN          *Flag
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
		Region:       &awsRegionFlag,
		Endpoint:     &awsEndpointFlag,
		Services:     &awsServiceFlag,
		SkipServices: &awsSkipServicesFlag,
		Account:      &awsAccountFlag,
		ARN:          &awsARNFlag,
	}
}

func (f *AWSFlagGroup) Name() string {
	return "AWS"
}

func (f *AWSFlagGroup) Flags() []*Flag {
	return []*Flag{f.Region, f.Endpoint, f.Services, f.SkipServices, f.Account, f.ARN}
}

func (f *AWSFlagGroup) ToOptions() AWSOptions {
	return AWSOptions{
		Region:       getString(f.Region),
		Endpoint:     getString(f.Endpoint),
		Services:     getStringSlice(f.Services),
		SkipServices: getStringSlice(f.SkipServices),
		Account:      getString(f.Account),
		ARN:          getString(f.ARN),
	}
}
